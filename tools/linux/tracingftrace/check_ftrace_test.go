package tracingftrace

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const (
	mask      = 1<<48 - 1
	opsList   = Data + 0x9000
	listEnd   = Data + 0x9100
	heap      = 0xffff888001000000
	modAt     = ModuleArea + 0x10000
	modText   = ModuleArea + 0x40000
	vfsRead   = Text + 0x2000
	kernelCB  = Text + 0x3000
	opsSize   = 216
	opsNext   = 8
	opsFlags  = 16
	opsHash   = 0x58
	opsTramp  = 0x90
	hashBits  = 0
	hashBkts  = 8
	hashCount = 16
	hashFlags = 24
	entryIP   = 16
)

func types(f *Fixture, filters bool) {
	ty := f.Types
	vp := Ptr(Void())
	ty.Struct("hlist_head", 8, map[string]F{"first": {Off: 0, Type: Ptr(Struct("hlist_node"))}})
	ty.Struct("hlist_node", 16, map[string]F{"next": {Off: 0, Type: vp}, "pprev": {Off: 8, Type: vp}})
	ops := map[string]F{
		"func":       {Off: 0, Type: vp},
		"next":       {Off: opsNext, Type: Ptr(Struct("ftrace_ops"))},
		"flags":      {Off: opsFlags, Type: Base("long unsigned int")},
		"trampoline": {Off: opsTramp, Type: Base("long unsigned int")},
	}
	if filters {
		ops["func_hash"] = F{Off: opsHash, Type: Ptr(Struct("ftrace_ops_hash"))}
		ty.Struct("ftrace_ops_hash", 48, map[string]F{
			"notrace_hash": {Off: 0, Type: Ptr(Struct("ftrace_hash"))},
			"filter_hash":  {Off: 8, Type: Ptr(Struct("ftrace_hash"))},
		})
		ty.Struct("ftrace_hash", 48, map[string]F{
			"size_bits": {Off: hashBits, Type: Base("long unsigned int")},
			"buckets":   {Off: hashBkts, Type: Ptr(Struct("hlist_head"))},
			"count":     {Off: hashCount, Type: Base("long unsigned int")},
			"flags":     {Off: hashFlags, Type: Base("long unsigned int")},
		})
		ty.Struct("ftrace_func_entry", 32, map[string]F{
			"hlist": {Off: 0, Type: Struct("hlist_node")},
			"ip":    {Off: entryIP, Type: Base("long unsigned int")},
		})
	}
	ty.Struct("ftrace_ops", opsSize, ops)
	ty.Symbol("ftrace_ops_list", opsList, Ptr(Struct("ftrace_ops")))
	ty.Symbol("ftrace_list_end", listEnd, Struct("ftrace_ops"))
	ty.Symbol("vfs_read", vfsRead, Arr(0, Base("char")))
	ty.Symbol("ftrace_stub_handler", kernelCB, Arr(0, Base("char")))
}

type fixture struct {
	*Fixture
	ops []uint64
}

func newFixture(filters bool) *fixture {
	f := &fixture{Fixture: NewFixture(0)}
	types(f.Fixture, filters)
	f.AddModule(ModuleSpec{At: modAt, Name: "rk", Base: modText, TextSize: 0x1000})
	ks, sym, str := uint64(modAt+0x600), uint64(modAt+0x700), uint64(modAt+0x800)
	f.Mem.U64(modAt+ModKallsyms, ks)
	f.Mem.U64(ks, sym)
	f.Mem.U32(ks+8, 2)
	f.Mem.U64(ks+16, str)
	f.Mem.U64(ks+24, str+0x40)
	f.Mem.Map(sym, 48)
	f.Mem.U32(sym+24, 1)
	f.Mem.U8(sym+24+4, 0x12)
	f.Mem.U16(sym+24+6, 1)
	f.Mem.U64(sym+24+8, modText)
	f.Mem.Write(str, []byte("\x00hook_fn\x00"))
	f.Mem.Write(str+0x40, []byte("tT"))
	f.Mem.Map(opsList, 8)
	f.Mem.Map(listEnd, opsSize)
	f.Mem.U64(opsList, listEnd)
	return f
}

type hashSpec struct {
	bits    uint64
	mod     bool
	buckets map[uint64][]uint64
	null    bool
}

func (f *fixture) region(i int) uint64 { return heap + uint64(i)*0x2000 }

func (f *fixture) hash(at uint64, h hashSpec) uint64 {
	if h.null {
		return 0
	}
	m := f.Mem
	bkts := at + 0x100
	m.Map(at, 0x1000)
	m.U64(at+hashBits, h.bits)
	m.U64(at+hashBkts, bkts)
	var n uint64
	entry := at + 0x400
	for b, ips := range h.buckets {
		holder := bkts + b*8
		for _, ip := range ips {
			m.U64(holder, entry)
			m.U64(entry+8, holder)
			m.U64(entry+entryIP, ip)
			holder = entry
			entry += 32
			n++
		}
	}
	m.U64(at+hashCount, n)
	if h.mod {
		m.U64(at+hashFlags, 1)
	}
	return at
}

func (f *fixture) addOps(fn, flags uint64, filter, notrace hashSpec) uint64 {
	i := len(f.ops)
	at := f.region(i)
	m := f.Mem
	m.Map(at, 0x2000)
	m.U64(at, fn)
	m.U64(at+opsFlags, flags)
	m.U64(at+opsTramp, 0xffffffffc1000000+uint64(i)*0x1000)
	local := at + 0x28
	m.U64(at+opsHash, local)
	m.U64(local, f.hash(at+0x1000, notrace))
	m.U64(local+8, f.hash(at+0x1800, filter))
	m.U64(at+opsNext, listEnd)
	if i == 0 {
		m.U64(opsList, at)
	} else {
		m.U64(f.ops[i-1]+opsNext, at)
	}
	f.ops = append(f.ops, at)
	return at
}

func (f *fixture) run(t *testing.T, opts map[string]any) ([]Hook, *[]string, error) {
	t.Helper()
	ctx, diags := f.Context(t, opts)
	rows, err := Run(ctx)
	return rows, diags, err
}

func standard(f *fixture) {
	f.addOps(modText+0x10, 1|1<<6, hashSpec{bits: 2, buckets: map[uint64][]uint64{1: {vfsRead + 4}, 3: {modText + 0x20}}},
		hashSpec{null: true})
	f.addOps(kernelCB, 1, hashSpec{null: true}, hashSpec{bits: 0, buckets: map[uint64][]uint64{0: {vfsRead + 4, kernelCB}}})
	f.addOps(kernelCB+8, 1<<1, hashSpec{bits: 0, mod: true}, hashSpec{null: true})
}

func TestEachOpsGivesItsScopeAndOwners(t *testing.T) {
	f := newFixture(true)
	standard(f)
	rows, diags, err := f.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	mod := Hook{OpsAddress: f.ops[0] & mask, CallbackAddress: (modText + 0x10) & mask, Callback: "hook_fn+0x10",
		Module: "rk", ModuleAddress: modAt & mask, ModuleFound: true, TrampolineAddress: 0xffffffffc1000000 & mask,
		TrampolineOwner: TrampolineAllocated, FlagBits: 1 | 1<<6}
	first, second := mod, mod
	first.Scope, first.HookedAddress, first.HookedModule, first.HookedSymbol = ScopeFunction, (vfsRead+4)&mask, "kernel", "vfs_read+0x4"
	second.Scope, second.HookedAddress, second.HookedModule, second.HookedSymbol = ScopeFunction, (modText+0x20)&mask, "rk", "hook_fn+0x20"
	all := Hook{OpsAddress: f.ops[1] & mask, CallbackAddress: kernelCB & mask, Callback: "ftrace_stub_handler",
		Module: "kernel", ModuleFound: true, TrampolineAddress: 0xffffffffc1001000 & mask,
		TrampolineOwner: TrampolineAllocated, Scope: ScopeAll,
		Excluded: 2, FlagBits: 1}
	none := Hook{OpsAddress: f.ops[2] & mask, CallbackAddress: (kernelCB + 8) & mask, Callback: "ftrace_stub_handler+0x8",
		Module: "kernel", ModuleFound: true, TrampolineAddress: 0xffffffffc1002000 & mask,
		TrampolineOwner: TrampolineAllocated, Scope: ScopeNone,
		FlagBits: 1 << 1}
	want := []Hook{first, second, all, none}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d\n got %+v\nwant %+v", i, rows[i], want[i])
		}
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestTheFlagsOptionNamesTheSetBits(t *testing.T) {
	f := newFixture(true)
	standard(f)
	rows, diags, err := f.run(t, map[string]any{OptionShowFlags: true})
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Flags != "ENABLED,INITIALIZED" || rows[3].Flags != "DYNAMIC" {
		t.Errorf("flags %q, %q", rows[0].Flags, rows[3].Flags)
	}
	if !contains(*diags, "linux_banner: release not read") {
		t.Errorf("diagnostics %q, want the unread release reported", *diags)
	}
	if _, _, err := f.run(t, map[string]any{OptionShowFlags: 3}); err == nil {
		t.Error("a number for a bool option is accepted")
	}
}

func TestAHashWithTooManyBucketsIsUnread(t *testing.T) {
	f := newFixture(true)
	f.addOps(kernelCB, 1, hashSpec{bits: 64, buckets: map[uint64][]uint64{0: {vfsRead}}}, hashSpec{null: true})
	rows, diags, err := f.run(t, nil)
	if err != nil || len(rows) != 1 || rows[0].Scope != ScopeUnread {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !contains(*diags, "size_bits 64") {
		t.Errorf("diagnostics %q", *diags)
	}
	if _, _, err := f.run(t, map[string]any{"strict": true}); err == nil {
		t.Error("strict mode accepts an unread hash")
	}
}

func TestAnUnreadableFilterHashKeepsTheOps(t *testing.T) {
	f := newFixture(true)
	at := f.addOps(kernelCB, 1, hashSpec{null: true}, hashSpec{null: true})
	f.Mem.U64(at+0x28+8, 0xffff888055000000)
	rows, diags, err := f.run(t, nil)
	if err != nil || len(rows) != 1 || rows[0].Scope != ScopeUnread || rows[0].Callback != "ftrace_stub_handler" {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !contains(*diags, "filter_hash at 0x888055000000") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestAListThatComesBackOrBreaksIsReported(t *testing.T) {
	f := newFixture(true)
	standard(f)
	f.Mem.U64(f.ops[2]+opsNext, f.ops[0])
	rows, diags, err := f.run(t, nil)
	if err != nil || len(rows) != 4 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !contains(*diags, "comes back to an ops already walked") {
		t.Errorf("diagnostics %q", *diags)
	}
	if _, _, err := f.run(t, map[string]any{"strict": true}); err == nil {
		t.Error("strict mode accepts a cycle")
	}
	f.Mem.U64(f.ops[1]+opsNext, 0)
	rows, diags, _ = f.run(t, nil)
	if len(rows) != 3 || !contains(*diags, "null before ftrace_list_end") {
		t.Errorf("rows %d, diagnostics %q", len(rows), *diags)
	}
}

func TestWithoutFiltersEveryOpsTracesEveryFunction(t *testing.T) {
	f := newFixture(false)
	f.addOps(kernelCB, 1, hashSpec{null: true}, hashSpec{null: true})
	rows, _, err := f.run(t, nil)
	if err != nil || len(rows) != 1 || rows[0].Scope != ScopeAll || rows[0].Excluded != 0 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
}

func TestAnEmptyListGivesNoRows(t *testing.T) {
	rows, diags, err := newFixture(true).run(t, nil)
	if err != nil || len(rows) != 0 || len(*diags) != 0 {
		t.Errorf("rows %+v, diagnostics %q, %v", rows, *diags, err)
	}
}

func TestTheListMustBeInTheSymbolTable(t *testing.T) {
	f := NewFixture(0)
	ctx, _ := f.Context(t, nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoOpsList) {
		t.Errorf("no ftrace_ops_list: %v", err)
	}
	if _, err := tools.Get(Name); err != nil {
		t.Errorf("%s is not registered: %v", Name, err)
	}
}

func contains(diags []string, part string) bool {
	for _, d := range diags {
		if strings.Contains(d, part) {
			return true
		}
	}
	return false
}

func TestBitFourIsNamedByTheRunningRelease(t *testing.T) {
	for _, c := range []struct{ release, want string }{
		{"6.17.0-5-generic", "RECURSION,GRAPH,bit 20"},
		{"6.14.5-100.fc40.x86_64", "RECURSION,bit 19,bit 20"},
		{"6.4.0", "RECURSION,bit 19,bit 20"},
		{"6.1.0", "RECURSION,bit 19,bit 20"},
		{"4.19.0-27-amd64", "RECURSION_SAFE,bit 19,bit 20"},
		{"5.10.0", "bit 4,bit 19,bit 20"},
		{"4.14.0", "bit 4,GRAPH,bit 20"},
		{"", "bit 4,GRAPH,bit 20"},
		{"v6.1", "bit 4,GRAPH,bit 20"},
	} {
		if got := FlagNames(1<<4|1<<19|1<<20, c.release); got != c.want {
			t.Errorf("release %q: %q, want %q", c.release, got, c.want)
		}
	}
	if got := FlagNames(1<<16|1<<18, "6.10.0"); got != "PERMANENT,bit 18" {
		t.Errorf("release 6.10: %q, SUBOP is named from v6.14", got)
	}
}

func TestTheBannerReleaseChoosesTheBitNames(t *testing.T) {
	f := newFixture(true)
	f.addOps(kernelCB, 1|1<<4, hashSpec{null: true}, hashSpec{null: true})
	const banner = Data + 0xa000
	text := "Linux version 4.19.0-27-amd64 (builder@host) #1 SMP\n\x00"
	f.Types.Symbol("linux_banner", banner, Arr(uint64(len(text)), Base("char")))
	f.Mem.Map(banner, 0x1000)
	f.Mem.Write(banner, []byte(text))
	rows, diags, err := f.run(t, map[string]any{OptionShowFlags: true})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if rows[0].Flags != "ENABLED,RECURSION_SAFE" {
		t.Errorf("flags %q on a v4.19 kernel", rows[0].Flags)
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestATrampolineInsideAModuleNamesTheModule(t *testing.T) {
	f := newFixture(true)
	at := f.addOps(kernelCB, 1, hashSpec{null: true}, hashSpec{null: true})
	f.Mem.U64(at+opsTramp, modText+0x100)
	f.addOps(kernelCB, 1, hashSpec{null: true}, hashSpec{null: true})
	f.Mem.U64(f.ops[1]+opsTramp, 0)
	rows, _, err := f.run(t, nil)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if rows[0].TrampolineOwner != "rk" {
		t.Errorf("trampoline owner %q, want the module that holds it", rows[0].TrampolineOwner)
	}
	if rows[1].TrampolineAddress != 0 || rows[1].TrampolineOwner != "" {
		t.Errorf("no trampoline: %+v", rows[1])
	}
}
