package tracingperf

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	ltt "github.com/aoiflux/libvapour/tools/linuxtrace/linuxtracetest"
)

const (
	eventSize  = 0x100
	eventOwner = 0x10
	eventPMU   = 0x30
	eventAttr  = 0x50
	eventProg  = 0x40
	attrType   = 0x00
	attrConfig = 0x08
	pmuName    = 0x08
	progTag    = 0x14
	progFunc   = 0x30
	progAux    = 0x38
	auxID      = 0x20
	auxName    = 0x28
	auxKsym    = 0x40
	ksymName   = 0x10
	auxSize    = auxKsym + ksymName + 512
)

func declare(k *ltt.Kernel, withProg, withKsym bool) {
	tb := k.Table
	members := []ltt.Member{
		ltt.M("owner_entry", eventOwner, ltt.Struct("list_head")),
		ltt.M("pmu", eventPMU, ltt.Ptr(ltt.Struct("pmu"))),
		ltt.M("attr", eventAttr, ltt.Struct("perf_event_attr")),
	}
	if withProg {
		members = append(members, ltt.M("prog", eventProg, ltt.Ptr(ltt.Struct("bpf_prog"))))
	}
	tb.Struct("perf_event", eventSize, members...)
	tb.Struct("perf_event_attr", 0x80, ltt.M("type", attrType, ltt.Base("unsigned int")),
		ltt.M("config", attrConfig, ltt.Base("long long unsigned int")))
	tb.Struct("pmu", 0x40, ltt.M("name", pmuName, ltt.Ptr(ltt.Base("char"))))
	tb.Struct("bpf_prog", 0x48, ltt.M("aux", progAux, ltt.Ptr(ltt.Struct("bpf_prog_aux"))),
		ltt.M("tag", progTag, ltt.Array(ltt.Base("unsigned char"), 8)),
		ltt.M("bpf_func", progFunc, ltt.Ptr(ltt.Func())))
	aux := []ltt.Member{ltt.M("id", auxID, ltt.Base("unsigned int")),
		ltt.M("name", auxName, ltt.Array(ltt.Base("char"), 16))}
	if withKsym {
		aux = append(aux, ltt.M("ksym", auxKsym, ltt.Struct("bpf_ksym")))
	}
	tb.Struct("bpf_prog_aux", auxSize, aux...)
	tb.Struct("bpf_ksym", ksymName+512, ltt.M("name", ksymName, ltt.Array(ltt.Base("char"), 512)))
}

type spec struct {
	pmu          string
	typ          uint32
	config       uint64
	name, symbol string
	id           uint32
	tag          []byte
	noProg       bool
}

func event(k *ltt.Kernel, s spec) (node, ev, prog uint64) {
	ev = k.Alloc(eventSize)
	p := k.Alloc(0x40)
	n := k.Alloc(uint64(len(s.pmu)) + 1)
	k.Mem.Str(n, s.pmu)
	k.Mem.U64(p+pmuName, n)
	k.Mem.U64(ev+eventPMU, p)
	k.Mem.U32(ev+eventAttr+attrType, s.typ)
	k.Mem.U64(ev+eventAttr+attrConfig, s.config)
	if !s.noProg {
		prog = k.Alloc(0x48)
		aux := k.Alloc(auxSize)
		k.Mem.U32(aux+auxID, s.id)
		k.Mem.Str(aux+auxName, s.name)
		k.Mem.Str(aux+auxKsym+ksymName, s.symbol)
		k.Mem.Write(prog+progTag, s.tag)
		k.Mem.U64(prog+progFunc, ltt.Text+0x900)
		k.Mem.U64(prog+progAux, aux)
		k.Mem.U64(ev+eventProg, prog)
	}
	return ev + eventOwner, ev, prog
}

func TestEventsWithAProgramAreListedPerThread(t *testing.T) {
	k := ltt.NewKernel()
	declare(k, true, true)
	n1, e1, p1 := event(k, spec{pmu: "tracepoint", typ: 2, config: 312, name: "short1", id: 7,
		symbol: "bpf_prog_6deef7357e7b4530_short1"})
	n2, _, _ := event(k, spec{pmu: "software", typ: 1, noProg: true})
	n3, e3, p3 := event(k, spec{pmu: "kprobe", typ: 9, id: 8, tag: []byte{1, 2, 3, 4, 5, 6, 7, 8}})
	k.AddTask(ltt.Task{PID: 100, TGID: 100, Comm: "loader", PerfEvents: []uint64{n1, n2},
		Threads: []ltt.Task{{PID: 101, TGID: 100, Comm: "loader:w", PerfEvents: []uint64{n3}}}})
	k.AddTask(ltt.Task{PID: 200, TGID: 200, Comm: "idle"})
	ctx, diags, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	code := uint64(ltt.Text + 0x900)
	want := []Event{
		{PID: 100, TID: 100, Process: "loader", EventAddress: e1, PMU: "tracepoint", Type: 2, Config: 312,
			ProgramAddress: p1, ProgramID: 7, ProgramName: "short1", ProgramSymbol: "bpf_prog_6deef7357e7b4530_short1",
			ProgramCode: code},
		{PID: 100, TID: 101, Process: "loader:w", EventAddress: e3, PMU: "kprobe", Type: 9, ProgramAddress: p3,
			ProgramID: 8, ProgramSymbol: "bpf_prog_0102030405060708", ProgramCode: code},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows\n got %+v\nwant %+v", rows, want)
	}
	if len(*diags) != 0 {
		t.Errorf("diags %q", *diags)
	}
}

func TestWithoutKsymTheSymbolIsBuiltFromTagAndName(t *testing.T) {
	k := ltt.NewKernel()
	declare(k, true, false)
	n, _, _ := event(k, spec{pmu: "tracepoint", name: "probe", tag: []byte{0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3}})
	k.AddTask(ltt.Task{PID: 1, TGID: 1, Comm: "init", PerfEvents: []uint64{n}})
	ctx, _, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].ProgramSymbol != "bpf_prog_deadbeef00010203_probe" {
		t.Errorf("rows %+v err %v", rows, err)
	}
}

func TestAKernelWithoutPerfEventProgHasNoRows(t *testing.T) {
	k := ltt.NewKernel()
	declare(k, false, true)
	n, _, _ := event(k, spec{pmu: "tracepoint", noProg: true})
	k.AddTask(ltt.Task{PID: 1, TGID: 1, Comm: "init", PerfEvents: []uint64{n}})
	ctx, diags, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 || len(*diags) != 1 || !strings.Contains((*diags)[0], "CONFIG_BPF_SYSCALL") {
		t.Errorf("rows %v err %v diags %q", rows, err, *diags)
	}
}

func TestAnUnreadableProgramIsKeptAndFailsStrictMode(t *testing.T) {
	k := ltt.NewKernel()
	declare(k, true, true)
	n, ev, _ := event(k, spec{pmu: "tracepoint", noProg: true})
	k.Mem.U64(ev+eventProg, 0xffff888077000000)
	k.AddTask(ltt.Task{PID: 1, TGID: 1, Comm: "init", PerfEvents: []uint64{n}})
	ctx, diags, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || len(*diags) != 1 || !strings.Contains((*diags)[0], "bpf_prog at") {
		t.Errorf("rows %+v err %v diags %q", rows, err, *diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Error("strict mode accepted an unreadable program")
	}
}

func TestNoPerfEventList(t *testing.T) {
	k := ltt.NewKernel()
	ctx, _, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx); !errors.Is(err, ErrNoPerfEvents) {
		t.Errorf("err = %v, want ErrNoPerfEvents", err)
	}
}

func FuzzProgramSymbol(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8}, "sys_enter")
	f.Add([]byte{}, "")
	f.Fuzz(func(t *testing.T, tag []byte, name string) {
		s := programSymbol(tag, name)
		rest, ok := strings.CutPrefix(s, "bpf_prog_")
		if !ok || len(rest) < 2*len(tag) {
			t.Fatalf("%q", s)
		}
		if strings.ToLower(rest[:2*len(tag)]) != rest[:2*len(tag)] {
			t.Fatalf("tag not lower-case hex: %q", s)
		}
		tail := rest[2*len(tag):]
		if (name == "") != (tail == "") || (name != "" && tail != "_"+name) {
			t.Fatalf("name part %q for %q", tail, name)
		}
	})
}
