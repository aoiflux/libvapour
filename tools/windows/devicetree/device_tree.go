package devicetree

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/driverscan"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.device.tree"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Show each driver object, the devices it created and the devices attached above each one",
		},
		RunAny,
	)
}

var (
	ErrNoDeviceType = errors.New("devicetree: symbol table lacks a _DRIVER_OBJECT or _DEVICE_OBJECT member")
	ErrNotDevice    = errors.New("devicetree: object is not a device object")
	ErrOtherDriver  = errors.New("devicetree: device names another driver object")
	ErrCycle        = errors.New("devicetree: device chain returns to a device already walked")
	ErrTooLong      = errors.New("devicetree: device chain is longer than MaxListEntries")
	ErrTypeUnread   = errors.New("devicetree: device object Type does not read")
)

type Kind string

const (
	KindDriver   Kind = "driver"
	KindDevice   Kind = "device"
	KindAttached Kind = "attached"
)

func DeviceTypeName(code uint32) string {
	if name, ok := DeviceCodes[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%x", code)
}

type Row struct {
	Level int
	Kind  Kind

	DriverOffset   uint64
	DriverName     string
	DriverFullName string

	DeviceIndex   int
	DeviceAddress uint64
	DeviceName    string

	AttachedDriverName       string
	AttachedDriverHeaderName string

	DeviceType     string
	DeviceTypeCode uint32
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

// wdm.h IO_TYPE_DEVICE.
const ioTypeDevice = 3

type layout struct {
	driverDevices, driverName                uint64
	deviceType, deviceDriver, next, attached uint64
	typeCode                                 uint64
	headerBody                               uint64
	namer                                    scan.ObjectNamer
	named                                    bool
	unicode                                  util.UnicodeStringLayout
}

func resolve(t symbols.SymbolTable) (layout, error) {
	var l layout
	for _, m := range []struct {
		typ, member string
		at          *uint64
	}{
		{"_DRIVER_OBJECT", "DeviceObject", &l.driverDevices},
		{"_DRIVER_OBJECT", "DriverName", &l.driverName},
		{"_DEVICE_OBJECT", "Type", &l.deviceType},
		{"_DEVICE_OBJECT", "DriverObject", &l.deviceDriver},
		{"_DEVICE_OBJECT", "NextDevice", &l.next},
		{"_DEVICE_OBJECT", "AttachedDevice", &l.attached},
		{"_DEVICE_OBJECT", "DeviceType", &l.typeCode},
		{"_OBJECT_HEADER", "Body", &l.headerBody},
	} {
		f, err := t.Field(m.typ, m.member)
		if err != nil {
			return l, fmt.Errorf("%s.%s: %w", m.typ, m.member, ErrNoDeviceType)
		}
		*m.at = f.Offset
	}
	l.namer, l.named = scan.NewObjectNamer(t)
	l.unicode = util.ResolveUnicodeStringLayout(t)
	return l, nil
}

type tree struct {
	ctx tools.Context
	l   layout
	out []Row
}

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	l, err := resolve(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !l.named {
		ctx.AddDiagnostic("%s: symbol table cannot locate object header names: device names are not read", Name)
	}
	drivers, err := driverscan.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	tr := &tree{ctx: ctx, l: l}
	seen := map[uint64]bool{}
	physicalOnly := 0
	for _, d := range drivers {
		// Devices are reached through the kernel's pointers; a copy of a
		// driver object the kernel does not map has no live device list.
		if d.VirtualOffset == 0 {
			physicalOnly++
			continue
		}
		if seen[d.VirtualOffset] {
			continue
		}
		seen[d.VirtualOffset] = true
		if err := tr.driver(d); err != nil {
			return nil, err
		}
	}
	if physicalOnly > 0 {
		ctx.AddDiagnostic("%s: %d driver objects the kernel does not map are left out", Name, physicalOnly)
	}
	return tr.out, nil
}

func (tr *tree) fail(object string, at uint64, err error) error {
	if tr.ctx.StrictMode() {
		return fmt.Errorf("%s: %s at 0x%x: %w", Name, object, at, err)
	}
	tr.ctx.AddDiagnostic("%s: %s at 0x%x: %v", Name, object, at, err)
	return nil
}

func (tr *tree) driver(d driverscan.Driver) error {
	header, full := d.ObjectName, d.Name
	tr.out = append(tr.out, Row{Level: 0, Kind: KindDriver, DriverOffset: d.VirtualOffset, DriverName: header,
		DriverFullName: full})
	t, m := tr.ctx.Symbols, tr.ctx.Memory
	dev, err := t.ReadPointer(m, d.VirtualOffset+tr.l.driverDevices)
	if err != nil {
		return tr.fail("driver object", d.VirtualOffset, err)
	}
	limit := tr.ctx.Bounds().MaxListEntries
	seen := map[uint64]bool{}
	for index := 0; dev != 0; index++ {
		switch {
		case seen[dev]:
			return tr.fail("device list of driver object", d.VirtualOffset, ErrCycle)
		case index >= limit:
			return tr.fail("device list of driver object", d.VirtualOffset, ErrTooLong)
		}
		seen[dev] = true
		code, err := tr.device(dev, d.VirtualOffset)
		if err != nil {
			return tr.fail("device object", dev, err)
		}
		tr.out = append(tr.out, Row{Level: 1, Kind: KindDevice, DriverOffset: d.VirtualOffset, DriverName: header,
			DriverFullName: full, DeviceIndex: index, DeviceAddress: dev, DeviceName: tr.objectName(dev),
			DeviceType: DeviceTypeName(code), DeviceTypeCode: code})
		if err := tr.stack(dev, d, index); err != nil {
			return err
		}
		next, err := t.ReadPointer(m, dev+tr.l.next)
		if err != nil {
			return tr.fail("device object", dev, err)
		}
		dev = next
	}
	return nil
}

// Every listed device has Type IO_TYPE_DEVICE and names its own driver
// object, on every capture (S64 V1, V2); a device that does not is not
// followed.
func (tr *tree) device(dev, owner uint64) (uint32, error) {
	t, m := tr.ctx.Symbols, tr.ctx.Memory
	b, err := m.ReadAt(dev+tr.l.deviceType, 2)
	if err != nil || len(b) != 2 {
		return 0, ErrTypeUnread
	}
	if uint16(b[0])|uint16(b[1])<<8 != ioTypeDevice {
		return 0, ErrNotDevice
	}
	if owner != 0 {
		drv, err := t.ReadPointer(m, dev+tr.l.deviceDriver)
		if err != nil {
			return 0, err
		}
		if drv != owner {
			return 0, ErrOtherDriver
		}
	}
	code, err := t.ReadUint32(m, dev+tr.l.typeCode)
	if err != nil {
		return 0, err
	}
	return code, nil
}

// AttachedDevice names the device attached above this one, typically a
// filter's, which sees the requests first (Learn, DEVICE_OBJECT).
func (tr *tree) stack(base uint64, d driverscan.Driver, index int) error {
	t, m := tr.ctx.Symbols, tr.ctx.Memory
	limit := tr.ctx.Bounds().MaxListEntries
	seen := map[uint64]bool{base: true}
	up, err := t.ReadPointer(m, base+tr.l.attached)
	if err != nil {
		return tr.fail("device object", base, err)
	}
	for level := 2; up != 0; level++ {
		switch {
		case seen[up]:
			return tr.fail("device stack above device", base, ErrCycle)
		case level-2 >= limit:
			return tr.fail("device stack above device", base, ErrTooLong)
		}
		seen[up] = true
		code, err := tr.device(up, 0)
		if err != nil {
			return tr.fail("attached device object", up, err)
		}
		owner, err := t.ReadPointer(m, up+tr.l.deviceDriver)
		if err != nil {
			return tr.fail("attached device object", up, err)
		}
		r := Row{Level: level, Kind: KindAttached, DriverOffset: d.VirtualOffset, DriverName: d.ObjectName,
			DriverFullName: d.Name, DeviceIndex: index, DeviceAddress: up, DeviceName: tr.objectName(up),
			DeviceType: DeviceTypeName(code), DeviceTypeCode: code}
		if owner != 0 {
			r.AttachedDriverHeaderName = tr.objectName(owner)
			if s, err := util.ReadUnicodeString(m, owner+tr.l.driverName, tr.l.unicode, util.MaxUnicodeStringBytes); err == nil {
				r.AttachedDriverName = s.Text()
			}
		}
		tr.out = append(tr.out, r)
		above, err := t.ReadPointer(m, up+tr.l.attached)
		if err != nil {
			return tr.fail("attached device object", up, err)
		}
		up = above
	}
	return nil
}

func (tr *tree) objectName(body uint64) string {
	if !tr.l.named || body < tr.l.headerBody {
		return ""
	}
	m := tr.ctx.Memory
	return tr.l.namer.Name(m, m, m, body-tr.l.headerBody)
}
