package registrycellroutine

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

// The offsets follow S63 P2: GetCellRoutine +0x8, ReleaseCellRoutine +0x10.
type words map[uint64]uint64

func (w words) ReadAt(at, n uint64) ([]byte, error) {
	v, ok := w[at]
	if !ok || n != 8 {
		return nil, memory.ErrOutOfBounds
	}
	return binary.LittleEndian.AppendUint64(nil, v), nil
}

func (w words) Size() uint64 { return 1 << 63 }

const (
	kernelBase = 0xfffff80000000000
	driverBase = 0xfffff80100000000
	getCell    = kernelBase + 0x1000
)

func table() *symbols.Table {
	t := symbols.NewTable("s63", 8)
	t.AddStruct(symbols.StructType{Name: "_CMHIVE", Size: 0x12d8, Fields: []symbols.Field{{Name: "Hive", Offset: 0}}})
	t.AddStruct(symbols.StructType{Name: "_HHIVE", Size: 0x608, Fields: []symbols.Field{
		{Name: "Signature", Offset: 0}, {Name: "GetCellRoutine", Offset: 8}, {Name: "ReleaseCellRoutine", Offset: 0x10}}})
	t.AddSymbol(symbols.Symbol{Name: "CmpHiveListHead", Address: kernelBase + 0x9000})
	t.AddSymbol(symbols.Symbol{Name: "HvpGetCellPaged", Address: getCell})
	return t
}

func modules() []modulelist.Module {
	return []modulelist.Module{
		{Name: "ntoskrnl.exe", Base: kernelBase, Size: 0x100000},
		{Name: "evil.sys", Base: driverBase, Size: 0x10000},
	}
}

func run(t *testing.T, mem words, hives []registryhive.Hive, strict bool) ([]Routine, []string, error) {
	t.Helper()
	tbl := table()
	var diags []string
	ctx := tools.Context{Memory: mem, Symbols: tbl, Options: map[string]any{"diagnostics": &diags, "strict": strict}}
	members, err := loadMembers(tbl)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := check(ctx, members, hives, newPlacer(ctx, modules()))
	return rows, diags, err
}

func TestEachRoutineIsPlacedInTheKernelAnotherModuleNoModuleOrNull(t *testing.T) {
	mem := words{
		0x1008: getCell, 0x1010: kernelBase + 0x2000,
		0x2008: driverBase + 0x40, 0x2010: 0,
		0x3008: 0x7ff000000000,
	}
	hives := []registryhive.Hive{
		{Address: 0x1000, FileFullPath: `\REGISTRY\MACHINE\SYSTEM`},
		{Address: 0x2000, Name: "x"},
		{Address: 0x3000},
	}
	rows, diags, err := run(t, mem, hives, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		member string
		place  Placement
		module string
		symbol string
	}{
		{"GetCellRoutine", InKernelImage, "ntoskrnl", "HvpGetCellPaged"},
		{"ReleaseCellRoutine", InKernelImage, "ntoskrnl", ""},
		{"GetCellRoutine", InOtherModule, "evil", ""},
		{"ReleaseCellRoutine", NullRoutine, "", ""},
		{"GetCellRoutine", InNoModule, "", ""},
		{"ReleaseCellRoutine", NotRead, "", ""},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i, w := range want {
		r := rows[i]
		if r.Member != w.member || r.Placement != w.place || r.Module != w.module || r.Symbol != w.symbol {
			t.Errorf("row %d %+v, want %+v", i, r, w)
		}
	}
	if rows[0].HivePath != `\REGISTRY\MACHINE\SYSTEM` || rows[2].HivePath != "x" {
		t.Errorf("hive paths %q %q", rows[0].HivePath, rows[2].HivePath)
	}
	joined := strings.Join(diags, "\n")
	if !strings.Contains(joined, "hive at 0x3000: ReleaseCellRoutine not read") ||
		!strings.Contains(joined, "3 of 6 routines are not inside the kernel image") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestStrictModeFailsOnAnUnreadRoutine(t *testing.T) {
	rows, _, err := run(t, words{0x1008: getCell}, []registryhive.Hive{{Address: 0x1000}}, true)
	if !errors.Is(err, ErrUnreadable) || len(rows) != 2 {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
}

func TestAKernelImageNotListedPlacesNothingInIt(t *testing.T) {
	tbl := table()
	var diags []string
	ctx := tools.Context{Memory: words{0x1008: getCell}, Symbols: tbl, Options: map[string]any{"diagnostics": &diags}}
	p := newPlacer(ctx, modules()[1:])
	r := Routine{Address: getCell}
	p.place(&r)
	if r.Placement != InNoModule || len(diags) != 1 {
		t.Fatalf("%+v %q", r, diags)
	}
}

func TestATableWithoutTheRoutinesIsALayoutError(t *testing.T) {
	tbl := symbols.NewTable("s63", 8)
	tbl.AddStruct(symbols.StructType{Name: "_CMHIVE", Fields: []symbols.Field{{Name: "Hive"}}})
	tbl.AddStruct(symbols.StructType{Name: "_HHIVE", Fields: []symbols.Field{{Name: "Signature"}}})
	if _, err := loadMembers(tbl); !errors.Is(err, ErrLayout) {
		t.Fatalf("err %v", err)
	}
}
