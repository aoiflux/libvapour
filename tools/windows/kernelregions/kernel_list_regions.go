package kernelregions

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const Name = "windows.kernel.list_regions"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the kernel's address space regions from MiVisibleState: the assigned regions and the type of each top-level slot",
		},
		RunAny,
	)
}

var (
	ErrNoVisibleState = errors.New("kernelregions: symbol table has no MiVisibleState or _MI_VISIBLE_STATE.SystemVaRegions")
	ErrStateUnread    = errors.New("kernelregions: MiVisibleState does not read")
)

const (
	TableAssigned = "SystemVaRegions"
	TableSlots    = "SystemVaType"
)

type Region struct {
	Table string
	Type  string
	Start uint64
	Size  uint64
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Region, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	t := ctx.Symbols
	sym, err := t.LookupSymbol("MiVisibleState")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoVisibleState)
	}
	assigned, err := t.Field("_MI_VISIBLE_STATE", "SystemVaRegions")
	if err != nil || !assigned.Type.IsArray || assigned.Type.ArrayLength == 0 {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoVisibleState)
	}
	state, err := t.ReadPointer(ctx.Memory, sym.Address)
	if err != nil || state == 0 {
		return nil, fmt.Errorf("%s: MiVisibleState at 0x%x: %w", Name, sym.Address, ErrStateUnread)
	}
	out, err := assignedRegions(ctx, state, assigned)
	if err != nil {
		return nil, err
	}
	out = append(out, slotRuns(ctx, state)...)
	slices.SortStableFunc(out, func(a, b Region) int {
		if c := cmp.Compare(a.Start, b.Start); c != 0 {
			return c
		}
		return cmp.Compare(a.Table, b.Table)
	})
	return out, nil
}

func enumNames(t symbols.SymbolTable, name string) map[int64]string {
	det, ok := t.(symbols.DeterministicLookup)
	if !ok {
		return nil
	}
	ty, err := det.LookupType(name)
	if err != nil || ty.Kind != symbols.TypeKindEnum {
		return nil
	}
	out := make(map[int64]string, len(ty.Enum))
	for _, e := range ty.Enum {
		out[e.Value] = e.Name
	}
	return out
}

func typeName(names map[int64]string, v int64) string {
	if n, ok := names[v]; ok {
		return n
	}
	return fmt.Sprintf("%d", v)
}

// SystemVaRegions is indexed by _MI_ASSIGNED_REGION_TYPES: its length is
// that enum's maximum on every measured build, and the PFN database, pool,
// directory object and kernel image lie in the element of their name (S64 R2).
func assignedRegions(ctx tools.Context, state uint64, f symbols.Field) ([]Region, error) {
	t := ctx.Symbols
	elem := f.Type.Element
	if elem == nil {
		elem = &f.Type
	}
	size, err1 := sizeOf(t, elem.Name)
	base, err2 := t.Field(elem.Name, "BaseAddress")
	count, err3 := t.Field(elem.Name, "NumberOfBytes")
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, fmt.Errorf("%s: %s lacks BaseAddress or NumberOfBytes: %w", Name, elem.Name, ErrNoVisibleState)
	}
	names := enumNames(t, "_MI_ASSIGNED_REGION_TYPES")
	if names == nil {
		ctx.AddDiagnostic("%s: symbol table has no _MI_ASSIGNED_REGION_TYPES: assigned regions are named by index", Name)
	}
	var out []Region
	for i := uint64(0); i < f.Type.ArrayLength; i++ {
		at := state + f.Offset + i*size
		start, err := t.ReadPointer(ctx.Memory, at+base.Offset)
		if err != nil {
			ctx.AddDiagnostic("%s: SystemVaRegions[%d] at 0x%x: does not read: %v", Name, i, at, err)
			continue
		}
		length, err := t.ReadUint64(ctx.Memory, at+count.Offset)
		if err != nil {
			ctx.AddDiagnostic("%s: SystemVaRegions[%d] at 0x%x: does not read: %v", Name, i, at, err)
			continue
		}
		// An unassigned region holds a zero base or a zero size (S64 R3).
		if start == 0 || length == 0 {
			continue
		}
		if start+length < start {
			ctx.AddDiagnostic("%s: SystemVaRegions[%d] at 0x%x: base 0x%x and size 0x%x pass the top of the address space",
				Name, i, at, start, length)
		}
		out = append(out, Region{Table: TableAssigned, Type: typeName(names, int64(i)), Start: start, Size: length})
	}
	return out, nil
}

func sizeOf(t symbols.SymbolTable, name string) (uint64, error) {
	st, err := t.Struct(name)
	if err != nil {
		return 0, err
	}
	if st.Size == 0 {
		return 0, fmt.Errorf("%s has no size", name)
	}
	return st.Size, nil
}

// SystemVaType gives one _MI_SYSTEM_VA_TYPE byte for each equal slice of the
// upper half; 256 slices of 512 GB on 4-level paging (S64 R4). Runs of one
// type are one row; MiVaUnused (0) is no row.
func slotRuns(ctx tools.Context, state uint64) []Region {
	t := ctx.Symbols
	f, err := t.Field("_MI_VISIBLE_STATE", "SystemVaType")
	if err != nil || !f.Type.IsArray || f.Type.ArrayLength == 0 {
		return nil
	}
	count := f.Type.ArrayLength
	half := modulelist.KernelHalfStart(ctx)
	span := ^half + 1
	if half == 0 || span%count != 0 {
		ctx.AddDiagnostic("%s: SystemVaType has %d slots, which do not divide the upper half from 0x%x", Name, count, half)
		return nil
	}
	slot := span / count
	raw, err := ctx.Memory.ReadAt(state+f.Offset, count)
	if err != nil || uint64(len(raw)) != count {
		ctx.AddDiagnostic("%s: SystemVaType at 0x%x: does not read: %v", Name, state+f.Offset, err)
		return nil
	}
	names := enumNames(t, "_MI_SYSTEM_VA_TYPE")
	if names == nil {
		ctx.AddDiagnostic("%s: symbol table has no _MI_SYSTEM_VA_TYPE: slot types are given as numbers", Name)
	}
	var out []Region
	for i := uint64(0); i < count; {
		j := i + 1
		for j < count && raw[j] == raw[i] {
			j++
		}
		if raw[i] != 0 {
			out = append(out, Region{Table: TableSlots, Type: typeName(names, int64(raw[i])), Start: half + i*slot,
				Size: (j - i) * slot})
		}
		i = j
	}
	return out
}
