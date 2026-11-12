package syscalllist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const Name = "windows.syscall.list"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the native system service table, each routine and the module that holds it",
		},
		RunAny,
	)
}

var (
	ErrNoServiceTable = errors.New("syscalllist: symbol table has neither KeServiceDescriptorTable nor KiServiceTable with KiServiceLimit")
	ErrTableTooLarge  = errors.New("syscalllist: service limit is above MaxTableEntries")
)

type Entry struct {
	Index            int
	Address          uint64
	ArgumentBytes    uint32
	Module           string
	ModuleUnreadable bool
	Unowned          bool
	Symbol           string
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type table struct {
	base, limit uint64
	source      string
}

func Run(ctx tools.Context) ([]Entry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	tab, err := serviceTable(ctx)
	if err != nil {
		return nil, err
	}
	if max := uint64(ctx.Bounds().MaxTableEntries); tab.limit > max {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: %s limit %d: %w", Name, tab.source, tab.limit, ErrTableTooLarge)
		}
		ctx.AddDiagnostic("%s: %s limit %d is above MaxTableEntries; %d entries read", Name, tab.source, tab.limit, max)
		tab.limit = max
	}
	mods, err := modulelist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: loaded modules: %w", Name, err)
		}
		ctx.AddDiagnostic("%s: loaded modules not read, so no routine has an owner: %v", Name, err)
	}
	owners := modulelist.NewAttributorAnchoredAt(ctx, modulelist.Placed(ctx, Name, mods), tab.base)
	if !owners.SymbolModuleKnown() {
		ctx.AddDiagnostic("%s: no loaded module holds the service table at 0x%x: routines have no symbol names", Name, tab.base)
	}
	width := uint64(ctx.Symbols.PointerSize())
	const entryBytes = uint64(4)
	raw, err := ctx.Memory.ReadAt(tab.base, tab.limit*entryBytes)
	if err != nil || uint64(len(raw)) != tab.limit*entryBytes {
		raw = nil
	}
	out := make([]Entry, 0, tab.limit)
	var unread, unowned int
	for i := uint64(0); i < tab.limit; i++ {
		var v uint32
		if raw != nil {
			v = binary.LittleEndian.Uint32(raw[i*entryBytes:])
		} else {
			b, err := ctx.Memory.ReadAt(tab.base+i*entryBytes, entryBytes)
			if err != nil || uint64(len(b)) != entryBytes {
				unread++
				continue
			}
			v = binary.LittleEndian.Uint32(b)
		}
		e := Entry{Index: int(i)}
		if width == 8 {
			// Each 64-bit entry is a signed offset from the table in its upper
			// 28 bits and the routine's stack argument bytes divided by 4 in
			// its low 4 bits (S64 S2, S3).
			e.Address = uint64(int64(tab.base) + int64(int32(v))>>4)
			e.ArgumentBytes = 4 * (v & 0xF)
		} else {
			e.Address = uint64(v)
		}
		attributions := owners.At(e.Address)
		if len(attributions) == 0 {
			e.Unowned = true
			unowned++
		} else {
			e.Module, e.Symbol, e.ModuleUnreadable = attributions[0].Module, attributions[0].Symbol, attributions[0].ModuleUnreadable
		}
		out = append(out, e)
	}
	if unread > 0 {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: %s at 0x%x: %d of %d entries do not read", Name, tab.source, tab.base, unread, tab.limit)
		}
		ctx.AddDiagnostic("%s: %s at 0x%x: %d of %d entries do not read and are left out", Name, tab.source, tab.base, unread, tab.limit)
	}
	if unowned > 0 {
		ctx.AddDiagnostic("%s: %d of %d service routines lie in no loaded module", Name, unowned, len(out))
	}
	return out, nil
}

// The descriptor is what the kernel's system-call path reads, so it is
// preferred; its first element is ServiceTableBase, CounterTableBase,
// ServiceLimit and ArgumentTable, each pointer-wide (S64 S1). A descriptor
// naming another table than KiServiceTable is reported.
func serviceTable(ctx tools.Context) (table, error) {
	t := ctx.Symbols
	width := uint64(t.PointerSize())
	var direct *table
	if ki, err := t.LookupSymbol("KiServiceTable"); err == nil {
		if lim, err := t.LookupSymbol("KiServiceLimit"); err == nil {
			n, err := t.ReadUint32(ctx.Memory, lim.Address)
			if err == nil {
				direct = &table{base: ki.Address, limit: uint64(n), source: "KiServiceTable"}
			} else {
				ctx.AddDiagnostic("%s: KiServiceLimit at 0x%x: does not read: %v", Name, lim.Address, err)
			}
		}
	}
	if sdt, err := t.LookupSymbol("KeServiceDescriptorTable"); err == nil {
		base, err1 := t.ReadPointer(ctx.Memory, sdt.Address)
		limit, err2 := t.ReadUint32(ctx.Memory, sdt.Address+2*width)
		switch {
		case err1 != nil || err2 != nil || base == 0:
			ctx.AddDiagnostic("%s: KeServiceDescriptorTable at 0x%x: base or limit does not read", Name, sdt.Address)
		default:
			if direct != nil && (direct.base != base || direct.limit != uint64(limit)) {
				ctx.AddDiagnostic("%s: KeServiceDescriptorTable at 0x%x: names table 0x%x with limit %d, not KiServiceTable 0x%x with limit %d",
					Name, sdt.Address, base, limit, direct.base, direct.limit)
			}
			return table{base: base, limit: uint64(limit), source: "KeServiceDescriptorTable"}, nil
		}
	}
	if direct == nil {
		return table{}, fmt.Errorf("%s: %w", Name, ErrNoServiceTable)
	}
	return *direct, nil
}
