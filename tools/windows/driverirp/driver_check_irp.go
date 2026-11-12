package driverirp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/driverscan"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const Name = "windows.driver.check_irp"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Read each driver object's major function table and the module holding each dispatch routine",
		},
		RunAny,
	)
}

var ErrNoMajorFunction = errors.New("driverirp: symbol table has no _DRIVER_OBJECT.MajorFunction array")

// The IRP_MJ_ codes 0x00 to IRP_MJ_MAXIMUM_FUNCTION (0x1b) of WDK wdm.h, by
// code.
var MajorFunctionNames = []string{
	"IRP_MJ_CREATE", "IRP_MJ_CREATE_NAMED_PIPE", "IRP_MJ_CLOSE", "IRP_MJ_READ", "IRP_MJ_WRITE",
	"IRP_MJ_QUERY_INFORMATION", "IRP_MJ_SET_INFORMATION", "IRP_MJ_QUERY_EA", "IRP_MJ_SET_EA",
	"IRP_MJ_FLUSH_BUFFERS", "IRP_MJ_QUERY_VOLUME_INFORMATION", "IRP_MJ_SET_VOLUME_INFORMATION",
	"IRP_MJ_DIRECTORY_CONTROL", "IRP_MJ_FILE_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CONTROL",
	"IRP_MJ_INTERNAL_DEVICE_CONTROL", "IRP_MJ_SHUTDOWN", "IRP_MJ_LOCK_CONTROL", "IRP_MJ_CLEANUP",
	"IRP_MJ_CREATE_MAILSLOT", "IRP_MJ_QUERY_SECURITY", "IRP_MJ_SET_SECURITY", "IRP_MJ_POWER",
	"IRP_MJ_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CHANGE", "IRP_MJ_QUERY_QUOTA", "IRP_MJ_SET_QUOTA", "IRP_MJ_PNP",
}

type Entry struct {
	Offset               uint64
	Driver               string
	DriverNameUnreadable bool
	Major                int
	MajorName            string
	Handler              uint64
	Module               string
	ModuleUnreadable     bool
	Symbol               string
	Unowned              bool
	InImage              bool
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]Entry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	t := ctx.Symbols
	table, err := t.Field("_DRIVER_OBJECT", "MajorFunction")
	if err != nil || !table.Type.IsArray || table.Type.ArrayLength == 0 {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoMajorFunction)
	}
	slots := table.Type.ArrayLength
	if slots != uint64(len(MajorFunctionNames)) {
		ctx.AddDiagnostic("%s: _DRIVER_OBJECT.MajorFunction holds %d slots, wdm.h names %d", Name, slots, len(MajorFunctionNames))
	}
	mods, err := modulelist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: loaded modules: %w", Name, err)
		}
		ctx.AddDiagnostic("%s: loaded modules not read, so no routine has an owner: %v", Name, err)
	}
	owners := modulelist.NewAttributor(ctx, modulelist.Placed(ctx, Name, mods))
	drivers, err := driverscan.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	width := uint64(t.PointerSize())
	seen := map[uint64]bool{}
	var out []Entry
	var physicalOnly, unread, unowned int
	for _, d := range drivers {
		// The table holds kernel addresses and is read through the kernel's
		// mapping of the object; a copy the kernel does not map is not a
		// live driver's table.
		if d.VirtualOffset == 0 {
			physicalOnly++
			continue
		}
		if seen[d.VirtualOffset] {
			continue
		}
		seen[d.VirtualOffset] = true
		name, nameUnread := d.Name, d.NameUnreadable
		if name == "" && !d.ObjectNameUnreadable {
			name, nameUnread = d.ObjectName, false
		}
		for i := uint64(0); i < slots; i++ {
			at := d.VirtualOffset + table.Offset + i*width
			handler, err := t.ReadPointer(ctx.Memory, at)
			if err != nil {
				unread++
				ctx.AddDiagnostic("%s: driver object at 0x%x: MajorFunction[%d] at 0x%x: does not read: %v", Name,
					d.VirtualOffset, i, at, err)
				continue
			}
			e := Entry{Offset: d.VirtualOffset, Driver: name, DriverNameUnreadable: nameUnread, Major: int(i),
				MajorName: majorName(i), Handler: handler,
				InImage: d.Start != 0 && handler >= d.Start && handler-d.Start < d.Size}
			if at := owners.At(handler); len(at) > 0 {
				e.Module, e.Symbol, e.ModuleUnreadable = at[0].Module, at[0].Symbol, at[0].ModuleUnreadable
			} else {
				e.Unowned = true
				unowned++
			}
			out = append(out, e)
		}
	}
	if physicalOnly > 0 {
		ctx.AddDiagnostic("%s: %d driver objects the kernel does not map are left out", Name, physicalOnly)
	}
	if unowned > 0 {
		ctx.AddDiagnostic("%s: %d of %d dispatch routines lie in no loaded module", Name, unowned, len(out))
	}
	if unread > 0 && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: %d major function slots do not read", Name, unread)
	}
	return out, nil
}

func majorName(i uint64) string {
	if i < uint64(len(MajorFunctionNames)) {
		return MajorFunctionNames[i]
	}
	return fmt.Sprintf("0x%02x", i)
}
