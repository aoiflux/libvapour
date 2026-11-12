package registryhivescan

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/windows/poolbig"
)

func allocation(at, size uint64, tag string, freed bool) poolbig.Allocation {
	return poolbig.Allocation{Address: at, Size: size, Tag: tag, Freed: freed}
}

func TestOnlyInUseCM10AllocationsHoldingTheSignatureAreHives(t *testing.T) {
	m := newMemory()
	m.hive(0x30000, `\SystemRoot\System32\Config\SOFTWARE`, `\REGISTRY\MACHINE\SOFTWARE`)
	m.hive(0x10000, "", `\REGISTRY\MACHINE\SYSTEM`)
	m.hive(0x50000, "x", "")
	m.u32(0x60000, 0x12345678)
	m.hive(0x70000, "small", "")
	var diags []string
	tbl := fxTable()
	l, err := loadLayout(tbl)
	if err != nil {
		t.Fatal(err)
	}
	pools := []poolbig.Allocation{
		allocation(0x30000, fxPoolSize, hiveTag, false),
		allocation(0x10000, fxPoolSize, hiveTag, false),
		allocation(0x50000, fxPoolSize, hiveTag, true),
		allocation(0x60000, fxPoolSize, hiveTag, false),
		allocation(0x70000, fxCMHIVESize-8, hiveTag, false),
		allocation(0x80000, fxPoolSize, "MmSt", false),
		allocation(0x90000, fxPoolSize, hiveTag, false),
	}
	rows := scan(fxContext(m, tbl, &diags, false), l, pools, map[uint64]bool{0x10000: true})
	if len(rows) != 3 {
		t.Fatalf("rows %+v, want the two signed hives and the unverified one", rows)
	}
	if rows[0].Address != 0x10000 || rows[1].Address != 0x30000 || rows[2].Address != 0x90000 {
		t.Errorf("rows not in address order: %+v", rows)
	}
	if !rows[0].Verified || rows[0].FilePath != `\REGISTRY\MACHINE\SYSTEM` || rows[0].OnHiveList != Listed {
		t.Errorf("a hive with no file path takes its mount point: %+v", rows[0])
	}
	if rows[1].FilePath != `\SystemRoot\System32\Config\SOFTWARE` || rows[1].RegistryPath != `\REGISTRY\MACHINE\SOFTWARE` ||
		rows[1].OnHiveList != NotListed || rows[1].PoolSize != fxPoolSize {
		t.Errorf("SOFTWARE row %+v", rows[1])
	}
	if rows[2].Verified || rows[2].FilePath != "" {
		t.Errorf("an allocation whose signature does not read is kept unverified: %+v", rows[2])
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "5 CM10 allocations in use, 1 freed, 1 smaller than _CMHIVE, 1 without the hive signature, 1 unverified") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestTheHiveListStateIsUnknownWithoutAWalk(t *testing.T) {
	m := newMemory()
	m.hive(0x10000, "a", "")
	tbl := fxTable()
	l, _ := loadLayout(tbl)
	var diags []string
	rows := scan(fxContext(m, tbl, &diags, false), l, []poolbig.Allocation{allocation(0x10000, fxPoolSize, hiveTag, false)}, nil)
	if len(rows) != 1 || rows[0].OnHiveList != ListUnknown {
		t.Fatalf("rows %+v", rows)
	}
}

func TestTheHiveListIsWalkedFromCmpHiveListHead(t *testing.T) {
	m := newMemory()
	const head, a, b = 0x5000, 0x10000, 0x20000
	ea, eb := uint64(a+fxHiveList), uint64(b+fxHiveList)
	m.u64(head, ea)
	m.u64(head+8, eb)
	m.u64(ea, eb)
	m.u64(ea+8, head)
	m.u64(eb, head)
	m.u64(eb+8, ea)
	tbl := fxTable()
	tbl.AddSymbol(symbols.Symbol{Name: "CmpHiveListHead", Address: head})
	l, _ := loadLayout(tbl)
	var diags []string
	set := hiveList(fxContext(m, tbl, &diags, false), l)
	if len(set) != 2 || !set[a] || !set[b] {
		t.Fatalf("listed %v, diagnostics %q", set, diags)
	}
	if hiveList(fxContext(m, fxTable(), &diags, false), l) != nil {
		t.Error("no CmpHiveListHead must leave the state unknown")
	}
}

func TestAMissingMemberIsALayoutError(t *testing.T) {
	tbl := symbols.NewTable("s63", 8)
	if _, err := loadLayout(tbl); !errors.Is(err, ErrLayout) {
		t.Fatalf("err %v", err)
	}
}

func TestPathStringsStopAtMaxNameBytes(t *testing.T) {
	m := newMemory()
	m.hive(0x10000, strings.Repeat("a", 300), "")
	tbl := fxTable()
	l, _ := loadLayout(tbl)
	file, _ := paths(m, l, 0x10000, 64)
	if len(file) > 32 {
		t.Errorf("a %d-character path read with a 64-byte cap", len(file))
	}
}
