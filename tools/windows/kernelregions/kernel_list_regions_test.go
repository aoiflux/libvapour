package kernelregions

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/symbols"
)

const (
	offRegions = uint64(0x120)
	offTypes   = uint64(0x10)
)

func regionKernel(withSlots bool) (*testsupport.S64Kernel, uint64) {
	k := testsupport.NewS64Kernel()
	t := k.Table
	t.AddStruct(symbols.StructType{Name: "_MI_SYSTEM_VA_ASSIGNMENT", Size: 0x10, Fields: []symbols.Field{
		{Name: "BaseAddress", Offset: 0, Type: symbols.TypeRef{Name: "void", IsPointer: true}},
		{Name: "NumberOfBytes", Offset: 8, Type: symbols.TypeRef{Name: "unsigned long long"}}}})
	fields := []symbols.Field{{Name: "SystemVaRegions", Offset: offRegions, Type: symbols.TypeRef{
		Name: "_MI_SYSTEM_VA_ASSIGNMENT", IsArray: true, ArrayLength: 3, Element: &symbols.TypeRef{Name: "_MI_SYSTEM_VA_ASSIGNMENT"}}}}
	if withSlots {
		fields = append(fields, symbols.Field{Name: "SystemVaType", Offset: offTypes, Type: symbols.TypeRef{
			Name: "unsigned char", IsArray: true, ArrayLength: 256, Element: &symbols.TypeRef{Name: "unsigned char"}}})
	}
	t.AddStruct(symbols.StructType{Name: "_MI_VISIBLE_STATE", Size: 0x200, Fields: fields})
	t.AddEnum(symbols.EnumType{Name: "_MI_ASSIGNED_REGION_TYPES", Size: 4, Values: []symbols.EnumValue{
		{Name: "AssignedRegionPfnDatabase", Value: 0}, {Name: "AssignedRegionNonPagedPool", Value: 1},
		{Name: "AssignedRegionKasan", Value: 2}}})
	t.AddEnum(symbols.EnumType{Name: "_MI_SYSTEM_VA_TYPE", Size: 4, Values: []symbols.EnumValue{
		{Name: "MiVaUnused", Value: 0}, {Name: "MiVaNonPagedPool", Value: 4}, {Name: "MiVaDriverImages", Value: 11}}})
	state := k.Alloc(0x200)
	k.U64(k.Global("MiVisibleState", 8), state)
	k.U64(state+offRegions, 0xffffe38000000000)
	k.U64(state+offRegions+8, 0xc8000000000)
	k.U64(state+offRegions+0x10, 0xffff9e0000000000)
	k.U64(state+offRegions+0x18, 0x100000000000)
	if withSlots {
		slots := make([]byte, 256)
		for i := 60; i < 92; i++ {
			slots[i] = 4
		}
		slots[240] = 11
		slots[241] = 11
		k.Write(state+offTypes, slots)
	}
	return k, state
}

func TestAssignedRegionsAndSlotRunsAreListedByStart(t *testing.T) {
	k, _ := regionKernel(true)
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []Region{
		{TableAssigned, "AssignedRegionNonPagedPool", 0xffff9e0000000000, 0x100000000000},
		{TableSlots, "MiVaNonPagedPool", 0xffff9e0000000000, 32 * 0x8000000000},
		{TableAssigned, "AssignedRegionPfnDatabase", 0xffffe38000000000, 0xc8000000000},
		{TableSlots, "MiVaDriverImages", 0xfffff80000000000, 2 * 0x8000000000},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestATableWithoutSlotTypesListsTheAssignedRegions(t *testing.T) {
	k, _ := regionKernel(false)
	rows, err := Run(k.Context())
	if err != nil || len(rows) != 2 {
		t.Errorf("rows %+v err %v", rows, err)
	}
}

func TestNoVisibleStateIsAnError(t *testing.T) {
	k := testsupport.NewS64Kernel()
	if _, err := Run(k.Context()); !errors.Is(err, ErrNoVisibleState) {
		t.Errorf("err = %v", err)
	}
}

func FuzzSlotRuns(f *testing.F) {
	f.Add(make([]byte, 256))
	k, state := regionKernel(true)
	ctx := k.Context()
	f.Fuzz(func(t *testing.T, slots []byte) {
		if len(slots) > 256 {
			slots = slots[:256]
		}
		k.Write(state+offTypes, append(slots, make([]byte, 256-len(slots))...))
		rows := slotRuns(ctx, state)
		var covered uint64
		for i, r := range rows {
			if r.Size == 0 || r.Size%0x8000000000 != 0 || (i > 0 && r.Start < rows[i-1].Start+rows[i-1].Size) {
				t.Errorf("run %+v", r)
			}
			covered += r.Size / 0x8000000000
		}
		if covered > 256 {
			t.Errorf("%d slots covered", covered)
		}
	})
}
