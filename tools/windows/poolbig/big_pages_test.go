package poolbig

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools"
)

const (
	vaA = uint64(0xffffa00000200000)
	vaB = uint64(0xffffa00000100000)
	vaC = uint64(0xffffa00000300000)
)

func run(t *testing.T, b fxBuild, slots int, entries map[int]fxEntry, options map[string]any) ([]Allocation, []string) {
	t.Helper()
	ctx, diags := fxContext(b.table(), b.memory(slots, entries), options)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return rows, *diags
}

func TestInUseFreedAndUnusedSlots(t *testing.T) {
	entries := map[int]fxEntry{
		1: {va: vaA, tag: "CM10", bytes: 0x2000, kind: 1},
		3: {va: vaB | freedBit, tag: "MmSt", bytes: 0x3000, kind: 512},
	}
	rows, diags := run(t, fx19045, 8, entries, nil)
	if len(rows) != 1 || rows[0].Address != vaA || rows[0].Freed || rows[0].Tag != "CM10" || rows[0].Size != 0x2000 ||
		rows[0].Slot != 1 {
		t.Fatalf("default rows %+v, want only the in-use CM10 entry", rows)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "1 in use, 1 freed, 6 never used, 0 not readable") {
		t.Errorf("diagnostics %q do not count the slots", diags)
	}
	rows, _ = run(t, fx19045, 8, entries, map[string]any{OptionShowFree: true})
	if len(rows) != 2 || rows[0].Address != vaB || !rows[0].Freed || rows[1].Address != vaA {
		t.Fatalf("rows with freed %+v, want the freed MmSt entry first by address, its bit 0 cleared", rows)
	}
}

func TestPoolTypeNamesAndKinds(t *testing.T) {
	entries := map[int]fxEntry{
		0: {va: vaA, tag: "a", kind: 0},
		1: {va: vaB, tag: "b", kind: 2},
		2: {va: vaC, tag: "c", kind: 1025},
		3: {va: vaC + 0x1000, tag: "d", kind: 512},
		4: {va: vaC + 0x2000, tag: "e", kind: 5},
	}
	rows, _ := run(t, fx19045, 5, entries, nil)
	want := map[string][2]string{
		"a": {"NonPagedPool", "nonpaged"},
		"b": {"NonPagedPoolMustSucceed", "nonpaged"},
		"c": {"1025", "paged"},
		"d": {"NonPagedPoolNx", "nonpaged"},
		"e": {"PagedPoolCacheAligned", "paged"},
	}
	for _, r := range rows {
		w := want[r.Tag]
		if r.PoolType != w[0] || string(r.Pool) != w[1] || r.PoolFlags != "" {
			t.Errorf("tag %q: PoolType %q Pool %q PoolFlags %q, want %q %q and no flags", r.Tag, r.PoolType, r.Pool,
				r.PoolFlags, w[0], w[1])
		}
	}
}

func TestPoolFlagsNamesAndKinds(t *testing.T) {
	entries := map[int]fxEntry{
		0: {va: vaA, tag: "a", kind: 0x108},
		1: {va: vaB, tag: "b", kind: 0x42},
		2: {va: vaC, tag: "c", kind: 0x88},
		3: {va: vaC + 0x1000, tag: "d", kind: 0x940},
		4: {va: vaC + 0x2000, tag: "e", kind: 0x140},
		5: {va: vaC + 0x3000, tag: "f", kind: 0},
	}
	rows, _ := run(t, fx26100, 6, entries, nil)
	want := map[string][2]string{
		"a": {"POOL_FLAG_CACHE_ALIGNED|POOL_FLAG_PAGED", "paged"},
		"b": {"POOL_FLAG_UNINITIALIZED|POOL_FLAG_NON_PAGED", "nonpaged"},
		"c": {"POOL_FLAG_CACHE_ALIGNED|POOL_FLAG_NON_PAGED_EXECUTE", "nonpaged_execute"},
		"d": {"POOL_FLAG_NON_PAGED|POOL_FLAG_PAGED|0x800", ""},
		"e": {"POOL_FLAG_NON_PAGED|POOL_FLAG_PAGED", ""},
		"f": {"0x0", ""},
	}
	for _, r := range rows {
		w := want[r.Tag]
		if r.PoolFlags != w[0] || string(r.Pool) != w[1] || r.PoolType != "" {
			t.Errorf("tag %q: PoolFlags %q Pool %q PoolType %q, want %q %q and no type", r.Tag, r.PoolFlags, r.Pool,
				r.PoolType, w[0], w[1])
		}
	}
}

func TestTagText(t *testing.T) {
	for _, tc := range []struct {
		key  uint32
		want string
	}{
		{0x30314d43, "CM10"},
		{0x206c644d, "Mdl "},
		{0x00445648, "HVD"},
		{0x00005045, "EP"},
		{0x41004241, `AB\x00A`},
		{0x8041434b, `KCA\x80`},
	} {
		if got := tagText(tc.key); got != tc.want {
			t.Errorf("tag 0x%08x is %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestTagFilter(t *testing.T) {
	entries := map[int]fxEntry{
		0: {va: vaA, tag: "Mdl "},
		1: {va: vaB, tag: "CM10"},
		2: {va: vaC, tag: "cm10"},
	}
	rows, diags := run(t, fx19045, 3, entries, map[string]any{OptionTags: "Mdl, CM10, toolong"})
	if len(rows) != 2 || rows[0].Tag != "CM10" || rows[1].Tag != "Mdl " {
		t.Fatalf("rows %+v, want CM10 and the trimmed match of \"Mdl \", case kept", rows)
	}
	if !strings.Contains(strings.Join(diags, "\n"), `tag "toolong" matches no entry`) {
		t.Errorf("diagnostics %q do not name the impossible tag", diags)
	}
	rows, _ = run(t, fx19045, 3, entries, map[string]any{OptionTags: []string{"cm10"}})
	if len(rows) != 1 || rows[0].Tag != "cm10" {
		t.Fatalf("rows %+v, want only cm10", rows)
	}
}

func TestOptionErrors(t *testing.T) {
	b := fx19045
	for _, tc := range []struct {
		options map[string]any
		want    error
	}{
		{map[string]any{retiredTag: "CM10"}, ErrTagOptionRenamed},
		{map[string]any{OptionTags: 5}, tools.ErrOptionType},
		{map[string]any{OptionShowFree: "maybe"}, tools.ErrOptionType},
	} {
		ctx, _ := fxContext(b.table(), b.memory(2, nil), tc.options)
		if _, err := Run(ctx); !errors.Is(err, tc.want) {
			t.Errorf("options %v: %v, want %v", tc.options, err, tc.want)
		}
	}
}

func TestTableLocationRules(t *testing.T) {
	b := fx19045
	put := func(m *fxMemory, at, v uint64, n int) {
		for i := range n {
			m.buf[at+uint64(i)] = byte(v >> (8 * i))
		}
	}
	for _, tc := range []struct {
		name   string
		change func(m *fxMemory)
		limit  int
		want   error
	}{
		{"null pointer", func(m *fxMemory) { put(m, fxPointerAt, 0, 8) }, 0, ErrTableAddress},
		{"pointer off a page", func(m *fxMemory) { put(m, fxPointerAt, fxTable+0x18, 8) }, 0, ErrTableAddress},
		{"zero slots", func(m *fxMemory) { put(m, fxSizeAt, 0, 4) }, 0, ErrTableSize},
		{"over the limit", func(*fxMemory) {}, 3, ErrTableSize},
	} {
		m := b.memory(4, nil)
		tc.change(m)
		ctx, _ := fxContext(b.table(), m, nil)
		if tc.limit > 0 {
			ctx.Limits = limits.Limits{MaxTableEntries: tc.limit}
		}
		if _, err := Run(ctx); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	for _, missing := range []string{tableGlobal, sizeGlobal, entryType} {
		ctx, _ := fxContext(b.tableWithout(missing), b.memory(2, nil), nil)
		if _, err := Run(ctx); !errors.Is(err, ErrNoTable) {
			t.Errorf("table without %s: %v, want %v", missing, err, ErrNoTable)
		}
	}
}

func TestUnreadablePagesLoseOnlyTheirEntries(t *testing.T) {
	b := fx19045
	slots := 400
	entries := map[int]fxEntry{}
	for i := range slots {
		entries[i] = fxEntry{va: vaA + uint64(i)*0x1000, tag: "Tst1", bytes: 0x1000}
	}
	m := b.memory(slots, entries)
	m.holes = [][2]uint64{{fxTable + 0x1000, fxTable + 0x2000}}
	ctx, diags := fxContext(b.table(), m, nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Entries 170 to 341 touch the second page: 4096/24 rounds down to 170 for
	// the first and the 342nd entry starts past 8192.
	lost := 0
	for i := range slots {
		at := fxTable + uint64(i)*b.stride
		if at+b.stride > fxTable+0x1000 && at < fxTable+0x2000 {
			lost++
		}
	}
	if len(rows) != slots-lost {
		t.Fatalf("%d rows, want %d: only entries touching the hole are lost", len(rows), slots-lost)
	}
	joined := strings.Join(*diags, "\n")
	if !strings.Contains(joined, "table entries at 0x2000 (4096 bytes): not readable") ||
		!strings.Contains(joined, "not readable") {
		t.Errorf("diagnostics %q do not name the unreadable page", *diags)
	}
	ctx, _ = fxContext(b.table(), m, map[string]any{"strict": true})
	if _, err := Run(ctx); err == nil {
		t.Errorf("strict mode accepted an unreadable table page")
	}
}

func TestReadTableKeepsSlotOrderAndFreed(t *testing.T) {
	b := fx26100
	entries := map[int]fxEntry{
		0: {va: vaA, tag: "CM10", kind: 0x100},
		2: {va: vaB | freedBit, tag: "CM10", kind: 0x100},
		5: {va: vaC, tag: "MmSt", kind: 0x40},
	}
	ctx, _ := fxContext(b.table(), b.memory(6, entries), nil)
	rows, err := ReadTable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].Slot != 0 || rows[1].Slot != 2 || !rows[1].Freed || rows[2].Slot != 5 {
		t.Fatalf("rows %+v, want slots 0, 2 (freed), 5 in slot order", rows)
	}
}

func TestSameAddressInUseBeforeFreed(t *testing.T) {
	entries := map[int]fxEntry{
		0: {va: vaA | freedBit, tag: "old"},
		1: {va: vaA, tag: "new"},
	}
	rows, _ := run(t, fx19045, 2, entries, map[string]any{OptionShowFree: true})
	if len(rows) != 2 || rows[0].Tag != "new" || rows[1].Tag != "old" {
		t.Fatalf("rows %+v, want the in-use entry before the freed one at one address", rows)
	}
}
