package processenvironment

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	paramsVA  = uint64(0x00007ff600200000)
	blockVA   = uint64(0x00007ff600300000)
	pebParams = uint64(0x20)
	envAt     = uint64(0x80)
	envSizeAt = uint64(0x3f0)
	exitAt    = uint64(0x840)
)

func utf16Block(strs ...string) []byte {
	var out []byte
	for _, s := range strs {
		for _, u := range utf16.Encode([]rune(s)) {
			out = binary.LittleEndian.AppendUint16(out, u)
		}
		out = append(out, 0, 0)
	}
	return out
}

type winProc struct {
	pid    uint64
	name   string
	noPeb  bool
	block  []byte
	size   uint64
	noEnv  bool
	exited bool
}

type winFixture struct {
	f     *testsupport.ProcessFixture
	diags []string
}

func newWinFixture(t *testing.T, procs ...winProc) *winFixture {
	t.Helper()
	specs := make([]testsupport.FixtureProcess, len(procs))
	for i, p := range procs {
		specs[i] = testsupport.FixtureProcess{PID: p.pid, Name: p.name, NoPeb: p.noPeb}
	}
	f := testsupport.BuildProcessFixture(specs)
	f.Table.AddStruct(symbols.StructType{Name: "_PEB", Size: 0x400, Fields: []symbols.Field{
		{Name: "Ldr", Offset: testsupport.FixtureLdrOffset}, {Name: "ProcessParameters", Offset: pebParams}}})
	f.Table.AddStruct(symbols.StructType{Name: "_RTL_USER_PROCESS_PARAMETERS", Size: 0x440, Fields: []symbols.Field{
		{Name: "Environment", Offset: envAt},
		{Name: "EnvironmentSize", Offset: envSizeAt, Type: symbols.TypeRef{Name: "unsigned long long"}}}})
	st, _ := f.Table.Struct("_EPROCESS")
	st.Fields = append(st.Fields, symbols.Field{Name: "ExitTime", Offset: exitAt})
	f.Table.AddStruct(st)
	for _, p := range procs {
		_, epPA := f.EPROCESS(p.pid)
		if p.exited {
			f.Memory.WriteU64(epPA+exitAt, 133000000000000000)
		}
		if p.noPeb {
			continue
		}
		raw, _ := f.Memory.ReadAt(epPA+testsupport.FixturePebOffset, 8)
		peb := binary.LittleEndian.Uint64(raw)
		as := f.Space(p.pid)
		pebPA := as.MapPage(peb)
		f.Memory.WriteU64(pebPA+pebParams, paramsVA)
		paramsPA := as.MapPage(paramsVA)
		if !p.noEnv {
			f.Memory.WriteU64(paramsPA+envAt, blockVA)
		}
		f.Memory.WriteU64(paramsPA+envSizeAt, p.size)
		for off := uint64(0); off < uint64(len(p.block)); off += 0x1000 {
			pa := as.MapPage(blockVA + off)
			f.Memory.WriteAt(pa, p.block[off:min(off+0x1000, uint64(len(p.block)))])
		}
	}
	return &winFixture{f: f}
}

func (w *winFixture) ctx(options map[string]any) tools.Context {
	ctx := w.f.Context()
	ctx.Options["diagnostics"] = &w.diags
	for k, v := range options {
		ctx.Options[k] = v
	}
	return ctx
}

func names(rows []EnvVar) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Variable + "=" + r.Value
	}
	return out
}

func said(diags []string, part string) bool {
	return slices.ContainsFunc(diags, func(d string) bool { return strings.Contains(d, part) })
}

func TestVariablesComeInBlockOrderAndStopAtTheTerminator(t *testing.T) {
	block := utf16Block("=C:=C:\\Users\\mew", "Path=C:\\Windows", "EMPTY=", "", "STALE=old")
	w := newWinFixture(t, winProc{pid: 1300, name: "cmd.exe", block: block, size: uint64(len(block))})
	rows, err := Run(w.ctx(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"=C:=C:\\Users\\mew", "Path=C:\\Windows", "EMPTY="}
	if !slices.Equal(names(rows), want) {
		t.Fatalf("rows %q, want %q", names(rows), want)
	}
	ep, _ := w.f.EPROCESS(1300)
	if r := rows[0]; r.PID != 1300 || r.Process != "cmd.exe" || r.EPROCESS != ep || r.Block != blockVA || r.Variable != "=C:" {
		t.Errorf("row %+v", r)
	}
	if len(w.diags) != 0 {
		t.Errorf("diagnostics %q", w.diags)
	}
}

func TestAStringWithoutANameIsSkippedAndSaidSo(t *testing.T) {
	block := utf16Block("garbage", "A=1", "")
	w := newWinFixture(t, winProc{pid: 8, name: "a.exe", block: block, size: uint64(len(block))})
	rows, _ := Run(w.ctx(nil))
	if !slices.Equal(names(rows), []string{"A=1"}) || !said(w.diags, "1 strings without a name, skipped") {
		t.Errorf("rows %q diags %q", names(rows), w.diags)
	}
}

func TestWithoutASizeTheBlockIsReadToItsTerminator(t *testing.T) {
	block := utf16Block("A=1", "B=2", "")
	w := newWinFixture(t, winProc{pid: 8, name: "a.exe", block: block, size: 0})
	rows, _ := Run(w.ctx(nil))
	if len(rows) != 2 || len(w.diags) != 0 {
		t.Errorf("rows %q diags %q", names(rows), w.diags)
	}
}

func TestACutBlockKeepsItsCompleteStrings(t *testing.T) {
	block := utf16Block("A=1", "B=2")
	for len(block) < 0x1000 {
		block = append(block, 'C', 0)
	}
	w := newWinFixture(t, winProc{pid: 8, name: "a.exe", block: block, size: 0x3000})
	rows, _ := Run(w.ctx(nil))
	if !slices.Equal(names(rows), []string{"A=1", "B=2"}) || !said(w.diags, "of 0x3000 bytes read") {
		t.Errorf("rows %q diags %q", names(rows), w.diags)
	}
	w = newWinFixture(t, winProc{pid: 8, name: "a.exe", block: block, size: uint64(len(block))})
	if _, _ = Run(w.ctx(nil)); !said(w.diags, "no terminator") {
		t.Errorf("diags %q", w.diags)
	}
	w = newWinFixture(t, winProc{pid: 8, name: "a.exe", block: block, size: 1 << 40})
	if _, _ = Run(w.ctx(nil)); !said(w.diags, "is over MaxBufferBytes") {
		t.Errorf("diags %q", w.diags)
	}
}

func TestProcessesWithoutABlock(t *testing.T) {
	block := utf16Block("A=1", "")
	w := newWinFixture(t,
		winProc{pid: 4, name: "System", noPeb: true},
		winProc{pid: 8, name: "noenv.exe", noEnv: true},
		winProc{pid: 12, name: "gone.exe", exited: true, block: block, size: uint64(len(block))},
		winProc{pid: 16, name: "live.exe", block: block, size: uint64(len(block))},
	)
	rows, err := Run(w.ctx(nil))
	if err != nil || len(rows) != 1 || rows[0].PID != 16 {
		t.Fatalf("rows %+v %v", rows, err)
	}
	if !said(w.diags, "pid 8: Environment is 0") || !said(w.diags, "1 exited processes not read") || said(w.diags, "pid 4") {
		t.Errorf("diags %q", w.diags)
	}
	rows, _ = Run(w.ctx(map[string]any{"pid": "8,16"}))
	if len(rows) != 1 || rows[0].PID != 16 {
		t.Errorf("pid set: %+v", rows)
	}
}

type failAt struct {
	memory.MemoryReader
	at uint64
}

func (f failAt) ReadAt(at, size uint64) ([]byte, error) {
	if at <= f.at && f.at < at+size {
		return nil, memory.ErrUnmapped
	}
	return f.MemoryReader.ReadAt(at, size)
}

func TestAPebThatDoesNotReadFailsStrictMode(t *testing.T) {
	w := newWinFixture(t, winProc{pid: 8, name: "a.exe", block: utf16Block("A=1", ""), size: 8})
	ep, _ := w.f.EPROCESS(8)
	ctx := w.ctx(nil)
	ctx.Memory = failAt{MemoryReader: ctx.Memory, at: ep + testsupport.FixturePebOffset}
	if rows, err := Run(ctx); err != nil || len(rows) != 0 || !said(w.diags, "Peb does not read") {
		t.Errorf("rows %v err %v diags %q", rows, err, w.diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "Peb does not read") {
		t.Errorf("strict: %v", err)
	}
}

func TestAMissingMemberStopsTheTool(t *testing.T) {
	w := newWinFixture(t, winProc{pid: 8, name: "a.exe"})
	w.f.Table.AddStruct(symbols.StructType{Name: "_RTL_USER_PROCESS_PARAMETERS", Size: 0x440})
	if _, err := Run(w.ctx(nil)); !errors.Is(err, ErrNoEnvironmentMember) {
		t.Errorf("err %v", err)
	}
}

func TestSplittingAWindowsBlock(t *testing.T) {
	odd := append(utf16Block("A=1", ""), 0x41)
	if b := splitWindowsBlock(odd); len(b.vars) != 1 || !b.terminated {
		t.Errorf("odd byte: %+v", b)
	}
	surrogate := []byte{'X', 0, '=', 0, 0x00, 0xd8, 0, 0, 0, 0}
	if b := splitWindowsBlock(surrogate); len(b.vars) != 1 || b.vars[0].value != "\ufffd" {
		t.Errorf("lone surrogate: %+v", b)
	}
	if b := splitWindowsBlock(utf16Block("", "A=1")); len(b.vars) != 0 || !b.terminated {
		t.Errorf("leading terminator: %+v", b)
	}
}
