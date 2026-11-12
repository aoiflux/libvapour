package kernelsymbols

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	ksyms "github.com/aoiflux/libvapour/symbols/kallsyms"
	lt "github.com/aoiflux/libvapour/symbols/linuxkernel/linuxtest"
	"github.com/aoiflux/libvapour/tools"
	lot "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const modBase uint64 = 0xffffffffc0100000

func physical() memory.MemoryReader {
	buf := lt.Capture(0, []string{"T_stext", "Tfoo", "B_end"}, []uint32{0, 0x10, 0x100})
	lt.PutNote(buf, 0x100, "OSRELEASE=6.17.0\n"+lt.LayoutKeys(0)+lt.KallsymsKeys(0))
	return &lt.Memory{Buf: buf}
}

func session(options map[string]any) (tools.Context, *[]string) {
	k := lot.NewKernel(1700000000, 0)
	l := lot.AddKallsymsLists(k, lot.AddModuleTypes(k), false)
	text := modBase + 0x10000
	m := l.Module("alpha", modBase, []lot.ElfSym{
		{},
		{Name: "alpha_main", Value: text, Size: 0x40, Type: 't'},
		{Name: "alpha_helper", Value: text + 0x40, Type: 'd'},
	}, []lot.Export{{Name: "alpha_main", Value: text}})
	l.Mods.List(m)
	l.FtraceMap(m, []lot.FtraceFunc{{Name: "alpha_init", IP: 0xffffffffd0000000, Size: 0x20}})
	l.Trampoline(0xffffffffc0400000, 0x100)
	l.BPF("bpf_prog_6deef7357e7b4530_sd_fw_egress", 0xffffffffa0001000, 0xffffffffa0001080)
	if options == nil {
		options = map[string]any{}
	}
	options[tools.OptionPhysicalMemory] = physical()
	return k.Context(options)
}

func text(rows []Row) string {
	var out []string
	for _, r := range rows {
		exp := fmt.Sprint(r.Exported)
		if r.ExportedUnknown {
			exp = "unknown"
		}
		out = append(out, fmt.Sprintf("%#x %s %d %s %s %s %s %q", r.Address, r.Type, r.Size, exp, r.Subsystem,
			r.Module, r.Name, r.Description))
	}
	return strings.Join(out, "\n")
}

var (
	core = []string{
		fmt.Sprintf("%#x T 16 unknown core kernel _stext \"code\"", uint64(lt.KernelBase)),
		fmt.Sprintf("%#x T 240 unknown core kernel foo \"code\"", uint64(lt.KernelBase+0x10)),
		fmt.Sprintf("%#x B 0 unknown core kernel _end \"zero-filled data\"", uint64(lt.KernelBase+0x100)),
	}
	modules = []string{
		"0xffffffffc0110000 T 64 true module alpha alpha_main \"code\"",
		"0xffffffffc0110040 d 0 false module alpha alpha_helper \"writable data\"",
	}
	ftrace = []string{
		"0xffffffffd0000000 T 32 true ftrace alpha alpha_init \"code\"",
		"0xffffffffc0400000 t 256 false ftrace __builtin__ftrace ftrace_trampoline \"code\"",
	}
	bpf = []string{"0xffffffffa0001000 t 128 false bpf bpf bpf_prog_6deef7357e7b4530_sd_fw_egress \"code\""}
)

func lines(parts ...[]string) string {
	var all []string
	for _, p := range parts {
		all = append(all, p...)
	}
	return strings.Join(all, "\n")
}

func TestEverySourceIsListedInProcOrder(t *testing.T) {
	ctx, _ := session(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := text(rows), lines(core, modules, ftrace, bpf); got != want {
		t.Errorf("rows\n%s\nwant\n%s", got, want)
	}
}

func TestTheOptionsSelectSources(t *testing.T) {
	for _, tc := range []struct {
		options []string
		want    string
	}{
		{[]string{OptionModules}, lines(modules)},
		{[]string{OptionBPF, OptionFtrace}, lines(ftrace, bpf)},
		{[]string{OptionBPF, OptionCore}, lines(core, bpf)},
	} {
		options := map[string]any{}
		for _, o := range tc.options {
			options[o] = "true"
		}
		ctx, _ := session(options)
		rows, err := Run(ctx)
		if err != nil {
			t.Fatalf("%v: %v", tc.options, err)
		}
		if got := text(rows); got != tc.want {
			t.Errorf("%v: rows\n%s\nwant\n%s", tc.options, got, tc.want)
		}
	}
	for _, o := range []string{OptionCore, OptionModules, OptionFtrace, OptionBPF} {
		ctx, _ := session(map[string]any{o: "ture"})
		if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) || !strings.Contains(err.Error(), o) {
			t.Errorf("%s: %v", o, err)
		}
	}
}

func TestOnlyTheCoreListsWithoutASymbolTable(t *testing.T) {
	for _, options := range []map[string]any{{}, {OptionFtrace: true}} {
		options[tools.OptionPhysicalMemory] = physical()
		if _, err := Run(tools.Context{Options: options}); !errors.Is(err, tools.ErrMissingMemoryReader) ||
			!strings.Contains(err.Error(), OptionCore) {
			t.Errorf("%v: %v", options, err)
		}
	}
	rows, err := Run(tools.Context{Options: map[string]any{tools.OptionPhysicalMemory: physical(), OptionCore: true}})
	if err != nil || len(rows) != 3 {
		t.Errorf("core alone: %d rows, %v", len(rows), err)
	}
	if _, err := Run(tools.Context{Options: map[string]any{OptionCore: true}}); !errors.Is(err, ErrNoPhysical) {
		t.Errorf("no physical memory: %v", err)
	}
}

func TestUnnamedCoreSymbolsAreLeftOut(t *testing.T) {
	rows := CoreRows(ksyms.Table{Symbols: []ksyms.Symbol{{Name: "a", Type: 'T'}, {Type: 't'}, {Name: "b"}}})
	if len(rows) != 2 || rows[0].Name != "a" || rows[1].Name != "b" || rows[1].Type != "" || rows[1].Description != "" {
		t.Errorf("rows %+v", rows)
	}
}

func TestLettersAreDescribedByClass(t *testing.T) {
	for letter, want := range map[byte]string{'t': "code", 'T': "code", 'R': "read-only data", 'A': "absolute or per-CPU value",
		'U': "undefined", 'u': "", 'V': "weak object", 'W': "weak symbol", 'N': "debugging information", 'x': "", 0: ""} {
		if got := Describe(letter); got != want {
			t.Errorf("%q: %q, want %q", letter, got, want)
		}
	}
}

func FuzzDescribe(f *testing.F) {
	f.Add(byte('t'))
	f.Fuzz(func(t *testing.T, letter byte) {
		d := Describe(letter)
		if 'A' <= letter && letter <= 'Z' && letter != 'U' && d != Describe(letter-'A'+'a') {
			t.Fatalf("%q and its lower case differ", letter)
		}
	})
}

func FuzzCoreRows(f *testing.F) {
	f.Add([]byte("T_stext\x00tfoo\x00\x00b"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var table ksyms.Table
		for i, part := range strings.Split(string(data), "\x00") {
			s := ksyms.Symbol{Address: uint64(i)}
			if part != "" {
				s.Type, s.Name = part[0], part[1:]
			}
			table.Symbols = append(table.Symbols, s)
		}
		last := -1
		for _, r := range CoreRows(table) {
			if r.Name == "" || int(r.Address) <= last || r.Subsystem != "core" || !r.ExportedUnknown {
				t.Fatalf("row %+v after address %d", r, last)
			}
			last = int(r.Address)
		}
	})
}
