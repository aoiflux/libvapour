package tracingtracepoints

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	ltt "github.com/aoiflux/libvapour/tools/linuxtrace/linuxtracetest"
)

const (
	section    = ltt.Data + 0x800
	tpSize     = 0x48
	tpFuncs    = 0x38
	tpKey      = 0x08
	funcSize   = 0x18
	modTPPtrs  = 0xf0
	modTPCount = 0xf8
	probeFn    = ltt.Text + 0x100
	probeFn2   = ltt.Text + 0x180
)

func declare(k *ltt.Kernel, pointerForm bool) {
	t := k.Table
	t.Struct("tracepoint", tpSize,
		ltt.M("name", 0, ltt.Ptr(ltt.Base("char"))),
		ltt.M("key", tpKey, ltt.Struct("static_key_false")),
		ltt.M("funcs", tpFuncs, ltt.Ptr(ltt.Struct("tracepoint_func"))))
	t.Struct("static_key_false", 0x10, ltt.M("key", 0, ltt.Struct("static_key")))
	t.Struct("static_key", 0x10, ltt.M("enabled", 0, ltt.Struct("atomic_t")))
	t.Struct("tracepoint_func", funcSize,
		ltt.M("func", 0, ltt.Ptr(ltt.Base("void"))),
		ltt.M("data", 8, ltt.Ptr(ltt.Base("void"))),
		ltt.M("prio", 0x10, ltt.Base("int")))
	entry := ltt.Base("int")
	if pointerForm {
		entry = ltt.Ptr(ltt.Struct("tracepoint"))
	}
	t.Struct("module", ltt.ModuleSize,
		ltt.M("state", ltt.ModuleState, ltt.Base("unsigned int")),
		ltt.M("list", ltt.ModuleList, ltt.Struct("list_head")),
		ltt.M("name", ltt.ModuleName, ltt.Array(ltt.Base("char"), ltt.ModuleNameLen)),
		ltt.M("mkobj", ltt.ModuleMkobj, ltt.Struct("module_kobject")),
		ltt.M("core_layout", ltt.ModuleCoreLayout, ltt.Struct("module_layout")),
		ltt.M("init_layout", ltt.ModuleInitLayout, ltt.Struct("module_layout")),
		ltt.M("kallsyms", ltt.ModuleKallsyms, ltt.Ptr(ltt.Struct("mod_kallsyms"))),
		ltt.M("tracepoints_ptrs", modTPPtrs, ltt.Ptr(entry)),
		ltt.M("num_tracepoints", modTPCount, ltt.Base("unsigned int")))
	t.Symbol("probe_kernel", probeFn, ltt.Func())
	t.Symbol("probe_other", probeFn2, ltt.Func())
}

type probe struct {
	fn, data uint64
	prio     int32
}

func tracepoint(k *ltt.Kernel, at uint64, name string, enabled bool, probes ...probe) {
	k.Mem.Map(at, tpSize)
	n := k.Alloc(uint64(len(name)) + 1)
	k.Mem.Str(n, name)
	k.Mem.U64(at, n)
	if enabled {
		k.Mem.U32(at+tpKey, 1)
	}
	if len(probes) == 0 {
		return
	}
	arr := k.Alloc(uint64(len(probes)+1) * funcSize)
	for i, p := range probes {
		e := arr + uint64(i)*funcSize
		k.Mem.U64(e, p.fn)
		k.Mem.U64(e+8, p.data)
		k.Mem.U32(e+0x10, uint32(p.prio))
	}
	k.Mem.U64(at+tpFuncs, arr)
}

func relativeSection(k *ltt.Kernel, at uint64, tps ...uint64) {
	k.Mem.Map(at, uint64(len(tps))*4)
	for i, tp := range tps {
		e := at + uint64(i)*4
		k.Mem.U32(e, uint32(int32(int64(tp-e))))
	}
}

func bounds(k *ltt.Kernel, start, size uint64) {
	k.Table.Symbol("__start___tracepoints_ptrs", start, nil)
	k.Table.Symbol("__stop___tracepoints_ptrs", start+size, nil)
}

func TestEveryTracepointGivesARowAndEachProbeItsOwn(t *testing.T) {
	k := ltt.NewKernel()
	declare(k, false)
	modBase := uint64(ltt.ModuleArea + 0x10000)
	mod := k.AddModule(ltt.Module{Name: "hooker", Base: modBase, Size: 0x8000, Text: 0x4000})
	idle, busy := uint64(ltt.Data+0x400), uint64(ltt.Data+0x480)
	tracepoint(k, idle, "sched_idle", false)
	tracepoint(k, busy, "sched_switch", true, probe{probeFn, 0x1111, 10}, probe{modBase + 0x40, 0, 0})
	relativeSection(k, section, idle, busy)
	bounds(k, section, 8)
	modTP := modBase + 0x5000
	tracepoint(k, modTP, "hooker_event", true, probe{probeFn2, 0, 0})
	modSection := modBase + 0x6000
	relativeSection(k, modSection, modTP)
	k.Mem.U64(mod+modTPPtrs, modSection)
	k.Mem.U32(mod+modTPCount, 1)
	ctx, diags, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kern := linuxmodule.KernelOwner
	want := []Probe{
		{Tracepoint: "sched_idle", TracepointAddress: idle, TracepointOwner: kern},
		{Tracepoint: "sched_switch", TracepointAddress: busy, TracepointOwner: kern, KeyEnabled: true, Probes: 2,
			ProbeAddress: probeFn, ProbeSymbol: "probe_kernel", DataAddress: 0x1111, Priority: 10, Module: kern,
			ModuleFound: true},
		{Tracepoint: "sched_switch", TracepointAddress: busy, TracepointOwner: kern, KeyEnabled: true, Probes: 2,
			ProbeAddress: modBase + 0x40, Module: "hooker", ModuleAddress: mod, ModuleFound: true},
		{Tracepoint: "hooker_event", TracepointAddress: modTP, TracepointOwner: "hooker", KeyEnabled: true, Probes: 1,
			ProbeAddress: probeFn2, ProbeSymbol: "probe_other", Module: kern, ModuleFound: true},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows\n got %+v\nwant %+v", rows, want)
	}
	if len(*diags) != 0 {
		t.Errorf("diags %q", *diags)
	}
}

func TestPointerEntriesAreReadWhenOnlyTheyNameTracepoints(t *testing.T) {
	k := ltt.NewKernel()
	declare(k, true)
	a, b := uint64(ltt.Data+0x400), uint64(ltt.Data+0x480)
	tracepoint(k, a, "a", false)
	tracepoint(k, b, "b", false)
	k.Mem.Map(section, 16)
	k.Mem.U64(section, a)
	k.Mem.U64(section+8, b)
	bounds(k, section, 16)
	ctx, _, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Tracepoint != "a" || rows[1].Tracepoint != "b" {
		t.Errorf("rows %+v", rows)
	}
}

func TestAKeyThatDisagreesWithTheProbesIsReported(t *testing.T) {
	k := ltt.NewKernel()
	declare(k, false)
	tp := uint64(ltt.Data + 0x400)
	tracepoint(k, tp, "odd", true)
	relativeSection(k, section, tp)
	bounds(k, section, 4)
	ctx, diags, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "static key enabled true with 0 probes") {
		t.Errorf("diags %q", *diags)
	}
}

func TestTheProbeArrayStopsAtMaxListEntries(t *testing.T) {
	k := ltt.NewKernel()
	declare(k, false)
	tp := uint64(ltt.Data + 0x400)
	tracepoint(k, tp, "many", true, probe{probeFn, 0, 0}, probe{probeFn2, 0, 0})
	relativeSection(k, section, tp)
	bounds(k, section, 4)
	ctx, diags, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Limits = limits.Limits{MaxListEntries: 1}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !strings.Contains(strings.Join(*diags, "|"), "more than 1 probes") {
		t.Errorf("rows %+v diags %q", rows, *diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Error("strict mode accepted a capped probe array")
	}
}

func TestMissingBoundsAndUnresolvedEntries(t *testing.T) {
	k := ltt.NewKernel()
	declare(k, false)
	ctx, _, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx); !errors.Is(err, ErrNoTracepoints) {
		t.Errorf("err = %v, want ErrNoTracepoints", err)
	}
	k = ltt.NewKernel()
	declare(k, false)
	k.Mem.Map(section, 8)
	bounds(k, section, 8)
	ctx, _, err = k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx); !errors.Is(err, ErrNoEntryForm) {
		t.Errorf("err = %v, want ErrNoEntryForm", err)
	}
}

func TestChooseForm(t *testing.T) {
	relative, pointer := formRelative, formPointer
	counts := func(r, p int) func(entryForm) int {
		return func(f entryForm) int {
			if f == formRelative {
				return r
			}
			return p
		}
	}
	for _, tc := range []struct {
		name  string
		size  uint64
		typed *entryForm
		r, p  int
		want  entryForm
		ok    bool
	}{
		{"more relative", 16, nil, 4, 0, formRelative, true},
		{"more pointer", 16, nil, 0, 2, formPointer, true},
		{"pointer excluded by size", 12, nil, 0, 9, formRelative, false},
		{"tie untyped", 16, nil, 2, 2, formRelative, true},
		{"tie typed pointer", 16, &pointer, 2, 2, formPointer, true},
		{"tie typed relative", 16, &relative, 2, 2, formRelative, true},
		{"none", 16, nil, 0, 0, formRelative, false},
	} {
		got, _, ok := chooseForm(tc.size, 8, tc.typed, counts(tc.r, tc.p))
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: got %v %v, want %v %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func FuzzDecodeEntries(f *testing.F) {
	f.Add([]byte{0xf8, 0xff, 0xff, 0xff, 0x10, 0, 0, 0}, uint64(0xffffffff81000000), false)
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, uint64(0), true)
	f.Fuzz(func(t *testing.T, raw []byte, start uint64, pointer bool) {
		form := formRelative
		if pointer {
			form = formPointer
		}
		w := form.width(8)
		got := decodeEntries(raw, start, form, 8, func(v uint64) uint64 { return v })
		if uint64(len(got)) != uint64(len(raw))/w {
			t.Fatalf("%d entries from %d bytes", len(got), len(raw))
		}
		for i, v := range got {
			at := start + uint64(i)*w
			if form == formRelative {
				off := int32(binary.LittleEndian.Uint32(raw[i*4:]))
				if v-at != uint64(int64(off)) {
					t.Fatalf("entry %d: %#x is not %#x%+d", i, v, at, off)
				}
			} else if v != binary.LittleEndian.Uint64(raw[i*8:]) {
				t.Fatalf("entry %d: %#x", i, v)
			}
		}
	})
}
