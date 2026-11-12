package callbacklist

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// The arrays are 64 _EX_FAST_REF slots: Learn's limit for image-load routines
// and the measured gap to the next public symbol on every capture (S27 F2, M1).
const notifySlots = 64

const (
	ioTypeDevice  = 3
	ioTypeDriver  = 4
	irpMjShutdown = 0x10
)

var bugCheckReasons = []string{
	"KbCallbackInvalid", "KbCallbackReserved1", "KbCallbackSecondaryDumpData", "KbCallbackDumpIo",
	"KbCallbackAddPages", "KbCallbackSecondaryMultiPartDumpData", "KbCallbackRemovePages",
	"KbCallbackTriageDumpData", "KbCallbackReserved2", "KbCallbackReserved3",
}

func (c *collector) notifyArray(kind Kind, symbol string) error {
	base, err := c.symbol(symbol)
	if err != nil {
		return err
	}
	mask, err := fastRefMask(c.ctx.Symbols)
	if err != nil {
		return fmt.Errorf("%s: %s: %w", Name, symbol, err)
	}
	raw, err := c.mem.ReadAt(base, notifySlots*8)
	if err != nil || len(raw) < notifySlots*8 {
		if err == nil {
			err = fmt.Errorf("read 0x%x bytes, got 0x%x", notifySlots*8, len(raw))
		}
		return c.unread(symbol, base, err)
	}
	for slot := 0; slot < notifySlots; slot++ {
		ref := binary.LittleEndian.Uint64(raw[slot*8:])
		block := ref & mask
		if block == 0 {
			continue
		}
		e := Entry{Kind: kind, Record: block, Detail: fmt.Sprintf("slot %d", slot)}
		routine, err := c.pointer(block + c.private.blockRoutine)
		if err != nil {
			if err := c.add(e, c.unread(fmt.Sprintf("%s slot %d callback block", symbol, slot), block, err)); err != nil {
				return err
			}
			continue
		}
		e.Routine = routine
		if err := c.add(e, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) registry() error {
	const label = "CallbackListHead"
	head, err := c.symbol(label)
	if err != nil {
		return err
	}
	entries, err := c.walk(head, label)
	if err != nil {
		return err
	}
	for _, at := range entries {
		e := Entry{Kind: KindRegistry, Record: at}
		routine, err := c.pointer(at + c.private.registryRoutine)
		if err != nil {
			if err := c.add(e, c.unread("registry callback", at, err)); err != nil {
				return err
			}
			continue
		}
		e.Routine = routine
		altitude, err := c.unicode(at + c.private.registryAltitude)
		var damage error
		if err != nil {
			damage = c.stringUnread("registry callback altitude", at+c.private.registryAltitude, err)
		} else {
			e.Detail = "altitude " + altitude
		}
		if err := c.add(e, damage); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) bugChecks(kind Kind, label, typeName string, fallback bugCheckLayout) error {
	head, err := c.symbol(label)
	if err != nil {
		return err
	}
	layout := bugCheckLayoutOf(c.ctx.Symbols, typeName, fallback)
	entries, err := c.walk(head, label)
	if err != nil {
		return err
	}
	for _, at := range entries {
		e := Entry{Kind: kind, Record: at}
		routine, err := c.pointer(at + layout.routine)
		if err != nil {
			if err := c.add(e, c.unread(typeName, at, err)); err != nil {
				return err
			}
			continue
		}
		e.Routine = routine
		var parts []string
		var damage error
		if layout.hasReason {
			b, err := c.mem.ReadAt(at+layout.reason, 4)
			if err != nil || len(b) < 4 {
				damage = c.unread(typeName+".Reason", at+layout.reason, readErr(err, 4, len(b)))
			} else {
				parts = append(parts, reasonName(binary.LittleEndian.Uint32(b)))
			}
		}
		if component, err := c.pointer(at + layout.component); err != nil {
			damage = c.unread(typeName+".Component", at+layout.component, err)
		} else if component != 0 {
			name, err := c.ansi(component)
			if err != nil {
				damage = c.stringUnread(typeName+" component string", component, err)
			} else {
				parts = append(parts, "component "+name)
			}
		}
		e.Detail = strings.Join(parts, " ")
		if err := c.add(e, damage); err != nil {
			return err
		}
	}
	return nil
}

func reasonName(v uint32) string {
	if int(v) < len(bugCheckReasons) {
		return bugCheckReasons[v]
	}
	return fmt.Sprintf("reason %d", v)
}

func readErr(err error, want, got int) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("read %d bytes, got %d", want, got)
}

func (c *collector) objectType16(at uint64) (uint16, error) {
	b, err := c.mem.ReadAt(at, 2)
	if err != nil || len(b) < 2 {
		return 0, readErr(err, 2, len(b))
	}
	return binary.LittleEndian.Uint16(b), nil
}

// The kernel sends IRP_MJ_SHUTDOWN through the device's driver, so the
// routine is that driver's dispatch entry (Learn, IoRegisterShutdownNotification).
func (c *collector) shutdowns(kind Kind, label string) error {
	head, err := c.symbol(label)
	if err != nil {
		return err
	}
	devDriver, err1 := c.ctx.Symbols.Field("_DEVICE_OBJECT", "DriverObject")
	major, err2 := c.ctx.Symbols.Field("_DRIVER_OBJECT", "MajorFunction")
	if err1 != nil || err2 != nil {
		return fmt.Errorf("%s: %s: _DEVICE_OBJECT.DriverObject or _DRIVER_OBJECT.MajorFunction missing", Name, label)
	}
	entries, err := c.walk(head, label)
	if err != nil {
		return err
	}
	for _, at := range entries {
		e := Entry{Kind: kind, Record: at}
		device, err := c.pointer(at + c.private.shutdownDevice)
		if err != nil {
			if err := c.add(e, c.unread("shutdown packet", at, err)); err != nil {
				return err
			}
			continue
		}
		driver, damage := c.deviceDriver(device, devDriver.Offset)
		e.Detail = fmt.Sprintf("device 0x%x", device)
		if damage == nil {
			if name, err := c.driverName(driver); err == nil && name != "" {
				e.Detail += " driver " + name
			}
			dispatch := driver + major.Offset + irpMjShutdown*8
			if e.Routine, err = c.pointer(dispatch); err != nil {
				damage = c.unread("IRP_MJ_SHUTDOWN dispatch", dispatch, err)
			}
		}
		if err := c.add(e, damage); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) deviceDriver(device, driverOffset uint64) (uint64, error) {
	t, err := c.objectType16(device)
	if err != nil {
		return 0, c.unread("device object", device, err)
	}
	if t != ioTypeDevice {
		return 0, fmt.Errorf("%s: device object at 0x%x: Type %d: %w", Name, device, t, ErrNotDevice)
	}
	driver, err := c.pointer(device + driverOffset)
	if err != nil {
		return 0, c.unread("_DEVICE_OBJECT.DriverObject", device+driverOffset, err)
	}
	return driver, c.checkDriver(driver)
}

func (c *collector) checkDriver(driver uint64) error {
	t, err := c.objectType16(driver)
	if err != nil {
		return c.unread("driver object", driver, err)
	}
	if t != ioTypeDriver {
		return fmt.Errorf("%s: driver object at 0x%x: Type %d: %w", Name, driver, t, ErrNotDriver)
	}
	return nil
}

func (c *collector) driverName(driver uint64) (string, error) {
	f, err := c.ctx.Symbols.Field("_DRIVER_OBJECT", "DriverName")
	if err != nil {
		return "", err
	}
	return c.unicode(driver + f.Offset)
}

func (c *collector) fileSystemChanges() error {
	const label = "IopFsNotifyChangeQueueHead"
	head, err := c.symbol(label)
	if err != nil {
		return err
	}
	entries, err := c.walk(head, label)
	if err != nil {
		return err
	}
	for _, at := range entries {
		e := Entry{Kind: KindFileSystemChange, Record: at}
		routine, err := c.pointer(at + c.private.fsRoutine)
		if err != nil {
			if err := c.add(e, c.unread("file system notification packet", at, err)); err != nil {
				return err
			}
			continue
		}
		e.Routine = routine
		var damage error
		if driver, err := c.pointer(at + c.private.fsDriver); err != nil {
			damage = c.unread("file system notification driver", at+c.private.fsDriver, err)
		} else if damage = c.checkDriver(driver); damage == nil {
			if name, err := c.driverName(driver); err == nil && name != "" {
				e.Detail = "driver " + name
			}
		}
		if err := c.add(e, damage); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) powerSettings() error {
	const label = "PopRegisteredPowerSettingCallbacks"
	head, err := c.symbol(label)
	if err != nil {
		return err
	}
	entries, err := c.walk(head, label)
	if err != nil {
		return err
	}
	for _, at := range entries {
		e := Entry{Kind: KindPowerSetting, Record: at}
		routine, err := c.pointer(at + c.private.powerRoutine)
		if err != nil {
			if err := c.add(e, c.unread("power setting callback", at, err)); err != nil {
				return err
			}
			continue
		}
		e.Routine = routine
		var damage error
		if g, err := c.mem.ReadAt(at+c.private.powerGUID, 16); err != nil || len(g) < 16 {
			damage = c.unread("power setting GUID", at+c.private.powerGUID, readErr(err, 16, len(g)))
		} else {
			e.Detail = "setting " + formatGUID(g)
		}
		if err := c.add(e, damage); err != nil {
			return err
		}
	}
	return nil
}

// Data1, Data2 and Data3 are little-endian; Data4 is a byte array.
func formatGUID(b []byte) string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// ObRegisterCallbacks serves these three object types only (Learn).
var handleObjectTypes = []string{"PsProcessType", "PsThreadType", "ExDesktopObjectType"}

func (c *collector) objectHandles() error {
	list, err := c.ctx.Symbols.Field("_OBJECT_TYPE", "CallbackList")
	if err != nil {
		return fmt.Errorf("%s: _OBJECT_TYPE.CallbackList: %w", Name, err)
	}
	nameField, nameErr := c.ctx.Symbols.Field("_OBJECT_TYPE", "Name")
	for _, symbol := range handleObjectTypes {
		at, err := c.symbol(symbol)
		if err != nil {
			c.ctx.AddDiagnostic("%v", err)
			continue
		}
		object, err := c.pointer(at)
		if err != nil {
			if err := c.failSource(c.unread(symbol, at, err)); err != nil {
				return err
			}
			continue
		}
		typeName := symbol
		if nameErr == nil {
			if n, err := c.unicode(object + nameField.Offset); err == nil && n != "" {
				typeName = n
			}
		}
		entries, err := c.walk(object+list.Offset, symbol+" CallbackList")
		if err != nil {
			if err := c.failSource(err); err != nil {
				return err
			}
			continue
		}
		for _, entry := range entries {
			if err := c.objectEntry(entry, object, typeName); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *collector) failSource(err error) error {
	if c.strict {
		return err
	}
	c.ctx.AddDiagnostic("%v", err)
	return nil
}

func (c *collector) objectEntry(at, object uint64, typeName string) error {
	p := c.private
	raw, err := c.mem.ReadAt(at, p.objectPost+8)
	if err != nil || uint64(len(raw)) < p.objectPost+8 {
		return c.add(Entry{Kind: KindObjectHandle, Record: at, Detail: typeName},
			c.unread("object callback entry", at, readErr(err, int(p.objectPost+8), len(raw))))
	}
	owner := binary.LittleEndian.Uint64(raw[p.objectType:])
	if owner != object {
		return c.add(Entry{Kind: KindObjectHandle, Record: at, Detail: typeName},
			fmt.Errorf("%s: object callback entry at 0x%x: names 0x%x, not %s at 0x%x: %w", Name, at, owner, typeName,
				object, ErrOtherType))
	}
	ops := operationNames(binary.LittleEndian.Uint32(raw[p.objectOperations:]))
	altitude := ""
	var damage error
	if reg := binary.LittleEndian.Uint64(raw[p.objectRegistration:]); reg != 0 {
		if altitude, err = c.unicode(reg + p.registrationAlt); err != nil {
			damage = c.stringUnread("object callback registration altitude", reg+p.registrationAlt, err)
		}
	}
	for _, phase := range []struct {
		name string
		off  uint64
	}{{"pre", p.objectPre}, {"post", p.objectPost}} {
		routine := binary.LittleEndian.Uint64(raw[phase.off:])
		if routine == 0 {
			continue
		}
		detail := fmt.Sprintf("%s %s %s", typeName, phase.name, ops)
		if damage == nil {
			detail += " altitude " + altitude
		}
		if err := c.add(Entry{Kind: KindObjectHandle, Routine: routine, Record: at, Detail: detail}, damage); err != nil {
			return err
		}
	}
	return nil
}

// OB_OPERATION_HANDLE_CREATE and OB_OPERATION_HANDLE_DUPLICATE (wdm.h).
func operationNames(ops uint32) string {
	var names []string
	if ops&1 != 0 {
		names = append(names, "create")
	}
	if ops&2 != 0 {
		names = append(names, "duplicate")
	}
	if rest := ops &^ 3; rest != 0 {
		names = append(names, fmt.Sprintf("0x%x", rest))
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}
