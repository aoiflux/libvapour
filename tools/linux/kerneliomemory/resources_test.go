package kerneliomemory

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	kt "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const root = 0xffffffff82000000

func types(t testing.TB) *kt.Table {
	i := kt.NewTypes(8)
	i.Struct("resource", 64, map[string]kt.F{
		"start": {Off: 0, Type: kt.Base("long long unsigned int")}, "end": {Off: 8, Type: kt.Base("long long unsigned int")},
		"name": {Off: 16, Type: kt.Ptr(kt.Base("char"))}, "flags": {Off: 24, Type: kt.Base("long unsigned int")},
		"desc": {Off: 32, Type: kt.Base("long unsigned int")}, "parent": {Off: 40, Type: kt.Ptr(kt.Struct("resource"))},
		"sibling": {Off: 48, Type: kt.Ptr(kt.Struct("resource"))}, "child": {Off: 56, Type: kt.Ptr(kt.Struct("resource"))},
	})
	i.Symbol("iomem_resource", root, kt.Struct("resource"))
	return i.Table(t)
}

type res struct {
	at, start, end, parent, sibling, child uint64
	name                                   string
}

func put(m *kt.Memory, rs ...res) {
	for _, r := range rs {
		m.U64(r.at, r.start)
		m.U64(r.at+8, r.end)
		if r.name != "" {
			m.Str(r.at+0x100, r.name)
			m.U64(r.at+16, r.at+0x100)
		} else {
			m.U64(r.at+16, 0)
		}
		m.U64(r.at+24, 0x200)
		m.U64(r.at+40, r.parent)
		m.U64(r.at+48, r.sibling)
		m.U64(r.at+56, r.child)
	}
}

const (
	a  = root + 0x1000
	a1 = root + 0x2000
	a2 = root + 0x3000
	b  = root + 0x4000
	b1 = root + 0x5000
)

func tree() *kt.Memory {
	m := kt.NewMemory()
	put(m,
		res{at: root, end: ^uint64(0), child: a, name: "PCI mem"},
		res{at: a, start: 0, end: 0xfff, parent: root, sibling: b, child: a1, name: "Reserved"},
		res{at: a1, start: 0x100, end: 0x1ff, parent: a, sibling: a2, name: "one"},
		res{at: a2, start: 0x200, end: 0x2ff, parent: a, name: "two"},
		res{at: b, start: 0x1000, end: 0x9fbff, parent: root, child: b1, name: "System RAM"},
		res{at: b1, start: 0x2000, end: 0x2fff, parent: b},
	)
	return m
}

func run(t *testing.T, m *kt.Memory, opts map[string]any, lim limits.Limits) ([]Row, []string, error) {
	t.Helper()
	ctx, diags := kt.Context(m, types(t), opts)
	ctx.Limits = lim
	rows, err := Run(ctx)
	return rows, *diags, err
}

func TestTheTreeIsListedInPreOrderWithDepths(t *testing.T) {
	rows, diags, err := run(t, tree(), nil, limits.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{
		{Address: a, Depth: 0, Start: 0, End: 0xfff, Flags: 0x200, Name: "Reserved", NameState: NameRead},
		{Address: a1, Depth: 1, Start: 0x100, End: 0x1ff, Flags: 0x200, Name: "one", NameState: NameRead},
		{Address: a2, Depth: 1, Start: 0x200, End: 0x2ff, Flags: 0x200, Name: "two", NameState: NameRead},
		{Address: b, Depth: 0, Start: 0x1000, End: 0x9fbff, Flags: 0x200, Name: "System RAM", NameState: NameRead},
		{Address: b1, Depth: 1, Start: 0x2000, End: 0x2fff, Flags: 0x200, NameState: NameNull},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows\n got %+v\nwant %+v", rows, want)
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics %q, want none", diags)
	}
}

func TestBrokenInvariantsAreCountedAndRowsKept(t *testing.T) {
	m := tree()
	put(m, res{at: a2, start: 0x150, end: 0x2000, parent: b, name: "two"})
	rows, diags, err := run(t, m, nil, limits.Limits{})
	if err != nil || len(rows) != 5 {
		t.Fatalf("%d rows, %v", len(rows), err)
	}
	joined := strings.Join(diags, "\n")
	for _, want := range []string{"1 resources name a parent other", "1 resources are not inside", "1 resources start at or before"} {
		if !strings.Contains(joined, want) {
			t.Errorf("diagnostics %q lack %q", diags, want)
		}
	}
}

func TestAnUnreadableNodeEndsItsBranch(t *testing.T) {
	m := tree()
	m.Unmap(a1)
	rows, diags, err := run(t, m, nil, limits.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[1].Address != b {
		t.Errorf("rows %+v, want Reserved, System RAM and its child", rows)
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "resource at 0xffffffff82002000") {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := run(t, m, map[string]any{"strict": true}, limits.Limits{}); err == nil {
		t.Error("strict mode accepted a tree read in part")
	}
}

func TestACycleEndsTheWalk(t *testing.T) {
	m := tree()
	put(m, res{at: a2, start: 0x200, end: 0x2ff, parent: a, sibling: a1, name: "two"})
	rows, diags, err := run(t, m, nil, limits.Limits{})
	if err != nil || len(rows) != 5 {
		t.Fatalf("%d rows, %v", len(rows), err)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "reached twice") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestLimitsBoundTheWalk(t *testing.T) {
	rows, diags, err := run(t, tree(), nil, limits.Limits{MaxListEntries: 2})
	if err != nil || len(rows) != 2 {
		t.Fatalf("%d rows, %v", len(rows), err)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "MaxListEntries") {
		t.Errorf("diagnostics %q", diags)
	}
	rows, diags, _ = run(t, tree(), nil, limits.Limits{MaxRecursionDepth: 1})
	if len(rows) != 2 || !strings.Contains(strings.Join(diags, "\n"), "MaxRecursionDepth") {
		t.Errorf("rows %+v diagnostics %q", rows, diags)
	}
}

func TestAnUnreadableNameIsMarked(t *testing.T) {
	m := tree()
	m.U64(b+16, 0xffffffff9f000000)
	rows, _, err := run(t, m, nil, limits.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if rows[3].NameState != NameUnread || rows[3].Name != "" {
		t.Errorf("row %+v", rows[3])
	}
}

func TestTheRootAndTypeAreRequired(t *testing.T) {
	ctx, _ := kt.Context(tree(), kt.NewTypes(8).Table(t), nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoRoot) {
		t.Errorf("no symbol: %v", err)
	}
	i := kt.NewTypes(8)
	i.Symbol("iomem_resource", root, kt.Struct("resource"))
	ctx, _ = kt.Context(tree(), i.Table(t), nil)
	if _, err := Run(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("no type: %v", err)
	}
	ctx, _ = kt.Context(kt.NewMemory(), types(t), nil)
	if _, err := Run(ctx); err == nil {
		t.Error("an unreadable root gave no error")
	}
}

func FuzzResourceTree(f *testing.F) {
	f.Add([]byte{0x10, 0x20, 0x30}, uint8(4))
	f.Fuzz(func(t *testing.T, data []byte, step uint8) {
		m := kt.NewMemory()
		m.Map(root, 0x8000)
		m.Write(root, data)
		for i := 0; i < len(data) && i < 64; i++ {
			at := root + uint64(i)*0x40
			if data[i]%3 == 0 {
				m.U64(at+56, root+uint64(data[i]%32)*0x40)
			}
			if data[i]%5 == 0 {
				m.U64(at+48, root+uint64((int(data[i])+int(step))%64)*0x40)
			}
		}
		ctx, _ := kt.Context(m, types(t), nil)
		ctx.Limits = limits.Limits{MaxListEntries: 200}
		rows, err := Run(ctx)
		if err == nil && len(rows) > 200 {
			t.Fatalf("%d rows past the cap", len(rows))
		}
		seen := map[uint64]bool{}
		for _, r := range rows {
			if seen[r.Address] {
				t.Fatalf("resource 0x%x listed twice", r.Address)
			}
			seen[r.Address] = true
		}
	})
}
