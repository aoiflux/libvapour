package threadscan

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	userPID   = uint64(0x200)
	systemPID = uint64(4)
	vadStart  = uint64(0x00007ff700000000)
	vadEnd    = uint64(0x00007ff70000ffff)
	created   = uint64(133_000_000_000_000_000)
)

type world struct {
	fx     *testsupport.ProcessFixture
	places []testsupport.S50Placement
	diags  *[]string
}

func (w world) ctx() tools.Context {
	ctx := w.fx.Context()
	ctx.Options["diagnostics"] = w.diags
	return ctx
}

func (w world) place(tid uint64) testsupport.S50Placement {
	for _, p := range w.places {
		if p.TID == tid {
			return p
		}
	}
	return testsupport.S50Placement{}
}

func build(t testing.TB, threads []testsupport.S50Thread) world {
	t.Helper()
	fx := testsupport.BuildPooledProcessFixture([]testsupport.FixtureProcess{
		{PID: systemPID, Name: "System", NoPeb: true},
		{PID: userPID, Name: "app.exe", NoPeb: true,
			VADs: []testsupport.FixtureVAD{{Start: vadStart, End: vadEnd, Path: `\Windows\System32\app.dll`}}},
	})
	places := fx.AddS50Threads(threads, `\SystemRoot\system32\drivers\disk.sys`)
	return world{fx: fx, places: places, diags: &[]string{}}
}

func scanThreads() []testsupport.S50Thread {
	module := testsupport.S50ModuleBase()
	return []testsupport.S50Thread{
		{TID: 8, Owner: systemPID, Pooled: true, Created: created, Start: module + 0x10, Win32Start: module + 0x10},
		{TID: 0x210, Owner: userPID, Pooled: true, Created: created, Start: vadStart + 0x10, Win32Start: vadStart + 0x20},
		{TID: 0x214, Owner: userPID, Pooled: true, Unlisted: true, Created: created, Exited: created + 1,
			StartInvalid: true, Start: 0xffffd00000123450, Win32Start: vadStart + 0x40},
		{TID: 0x219, Owner: userPID, Pooled: true, Created: created},
		{TID: 0x21c, Owner: userPID, Pooled: true, Unmapped: true, Created: created, Win32Start: vadStart + 0x50},
		{TID: 0x220, Owner: userPID, Created: created},
	}
}

func TestTheScanFindsThreadsWhetherOrNotAListHoldsThem(t *testing.T) {
	w := build(t, scanThreads())
	rows, err := Run(w.ctx())
	if err != nil {
		t.Fatal(err)
	}
	byTID := map[uint64]Thread{}
	for _, r := range rows {
		byTID[r.TID] = r
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows %v, want TIDs 8, 0x210, 0x214, 0x21c (diagnostics %q)", len(rows), byTID, *w.diags)
	}
	if _, ok := byTID[0x219]; ok {
		t.Error("TID 0x219 is not a multiple of 4; the thread check refuses it")
	}
	if _, ok := byTID[0x220]; ok {
		t.Error("TID 0x220 has no pool header")
	}
	userEP, _ := w.fx.EPROCESS(userPID)
	for _, tid := range []uint64{8, 0x210, 0x214} {
		r, p := byTID[tid], w.place(tid)
		if r.Offset != p.Physical || r.VirtualOffset != p.Virtual {
			t.Errorf("TID 0x%x at 0x%x / 0x%x, want 0x%x / 0x%x", tid, r.Offset, r.VirtualOffset, p.Physical, p.Virtual)
		}
	}
	if r := byTID[0x210]; r.PID != userPID || r.Process != userEP || r.StartPath != `\Windows\System32\app.dll` {
		t.Errorf("user thread %+v", r)
	}
	if r := byTID[8]; r.StartPath != `\SystemRoot\system32\drivers\disk.sys` || r.Win32StartPath != r.StartPath {
		t.Errorf("system thread paths %q %q", r.StartPath, r.Win32StartPath)
	}
	if r := byTID[0x214]; !r.StartAddressInvalid || r.StartAddress != 0 || r.ExitTime.IsZero() ||
		r.Win32StartPath != `\Windows\System32\app.dll` {
		t.Errorf("unlisted exited thread %+v", r)
	}
	if r := byTID[0x21c]; r.VirtualOffset != 0 || r.Offset != w.place(0x21c).Physical || r.Win32StartPath != `\Windows\System32\app.dll` {
		t.Errorf("unmapped thread %+v", r)
	}
	if !hasDiag(*w.diags, "windows.thread.scan: 4 threads from") {
		t.Errorf("no count diagnostic: %q", *w.diags)
	}
	if rows[len(rows)-1].TID != 0x21c {
		t.Errorf("the row with no kernel address comes last: %+v", rows)
	}
}

func TestAnOwnerThatFailsTheProcessCheckNamesNoFile(t *testing.T) {
	const freed = uint64(0xfffff80005000000)
	w := build(t, []testsupport.S50Thread{{TID: 0x230, Owner: userPID, OwnerAddress: freed, Pooled: true, Unlisted: true,
		Created: created, Win32Start: vadStart + 0x20}})
	rows, err := Run(w.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Process != freed || rows[0].Win32StartPath != "" {
		t.Fatalf("rows %+v", rows)
	}
	if !hasDiag(*w.diags, "_EPROCESS at 0xfffff80005000000: owning file of start addresses not found") {
		t.Errorf("diagnostics %q", *w.diags)
	}
}

func TestScanOwnersGivesEachAcceptedThreadsProcess(t *testing.T) {
	w := build(t, scanThreads())
	owned, err := ScanOwners(w.ctx())
	if err != nil {
		t.Fatal(err)
	}
	sysEP, _ := w.fx.EPROCESS(systemPID)
	userEP, _ := w.fx.EPROCESS(userPID)
	counts := map[uint64]int{}
	for _, o := range owned {
		counts[o.Process]++
	}
	if len(owned) != 4 || counts[sysEP] != 1 || counts[userEP] != 3 {
		t.Fatalf("owned %+v", owned)
	}
}

func TestTheScanNeedsPhysicalMemory(t *testing.T) {
	w := build(t, scanThreads())
	ctx := w.ctx()
	delete(ctx.Options, tools.OptionPhysicalMemory)
	if _, err := Run(ctx); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Fatalf("err %v, want ErrNoPhysicalMemory", err)
	}
}

func TestTheScanNeedsTheThreadCheck(t *testing.T) {
	w := build(t, scanThreads())
	tab := w.fx.Table
	cid, _ := tab.Struct("_CLIENT_ID")
	cid.Fields = cid.Fields[:1]
	tab.AddStruct(cid)
	if _, err := Run(w.ctx()); !errors.Is(err, ErrNoThreadCheck) {
		t.Fatalf("err %v, want ErrNoThreadCheck", err)
	}
}

// A body that ends at a page the capture lacks, so members past it do not read.
type pageReader struct {
	base uint64
	data []byte
}

func (p pageReader) ReadAt(off, n uint64) ([]byte, error) {
	if off < p.base || off+n > p.base+uint64(len(p.data)) {
		return nil, errors.New("not captured")
	}
	return p.data[off-p.base : off-p.base+n], nil
}

func (p pageReader) Size() uint64 { return p.base + uint64(len(p.data)) }

func columnTable() *symbols.Table { return testsupport.NewS50Table() }

const body = uint64(0x10000)

func TestTheColumnRules(t *testing.T) {
	tab := columnTable()
	r := NewColumnReader(tools.Context{Symbols: tab}, "test")
	raw := make([]byte, testsupport.S50ThreadSize)
	binary.LittleEndian.PutUint64(raw[testsupport.S50ThreadCreateTime:], created)
	binary.LittleEndian.PutUint64(raw[testsupport.S50ThreadExitTime:], 0xffffd00000100408)
	binary.LittleEndian.PutUint64(raw[testsupport.S50ThreadStartAddress:], 0x7ff700001000)
	binary.LittleEndian.PutUint64(raw[testsupport.S50KThreadProcess:], 0xffffd00000200000)
	c := r.Read(pageReader{base: body, data: raw}, body)
	if c.CreateTime.IsZero() || !c.ExitTime.IsZero() || c.ExitTimeUnreadable || c.StartAddress != 0x7ff700001000 ||
		c.StartAddressInvalid || c.Process != 0xffffd00000200000 {
		t.Errorf("columns %+v", c)
	}
	if got := c.CreateTime; !got.Equal(time.Unix(int64(created/10_000_000)-11644473600, 0).UTC()) {
		t.Errorf("CreateTime %v", got)
	}

	raw[testsupport.S50ThreadFlags] = 1 << testsupport.S50StartInvalidBit
	if c := r.Read(pageReader{base: body, data: raw}, body); c.StartAddress != 0 || !c.StartAddressInvalid {
		t.Errorf("StartAddressInvalid set: %+v", c)
	}
	if c := r.Read(pageReader{base: body, data: raw[:testsupport.S50ThreadCreateTime]}, body); r.Unread(c) != "StartAddress" ||
		c.Process != 0xffffd00000200000 {
		t.Errorf("a body cut before CreateTime: unread %q, %+v", r.Unread(c), c)
	}
}

func TestAnUnreadColumnIsKeptOrSkippedAndRefusedInStrictMode(t *testing.T) {
	tab := columnTable()
	diags := []string{}
	ctx := tools.Context{Symbols: tab, Options: map[string]any{"diagnostics": &diags}}
	r := NewColumnReader(ctx, "test")
	c := Columns{CreateTimeUnreadable: true}
	if err := r.ReportUnread(ctx, 4, 8, 0x1000, c); err != nil || !hasDiag(diags, "test: pid 4 tid 8 _ETHREAD at 0x1000: CreateTime does not read, kept") {
		t.Errorf("err %v diagnostics %q", err, diags)
	}
	if keep, err := r.KeepListed(ctx, 4, 8, 0x1000, c); keep || err != nil || !hasDiag(diags, "skipped") {
		t.Errorf("keep %v err %v diagnostics %q", keep, err, diags)
	}
	ctx.Options["strict"] = true
	if err := r.ReportUnread(ctx, 4, 8, 0x1000, c); err == nil {
		t.Error("strict mode keeps an unread column")
	}
	if _, err := r.KeepListed(ctx, 4, 8, 0x1000, c); err == nil {
		t.Error("strict mode skips an unread column silently")
	}
	if r.Unread(Columns{}) != "" {
		t.Error("a row that read is unread")
	}
}

func TestAColumnTheTableLacksIsReportedOnce(t *testing.T) {
	diags := []string{}
	ctx := tools.Context{Symbols: symbols.NewTable("bare", 8), Options: map[string]any{"diagnostics": &diags}}
	NewColumnReader(ctx, "test").ReportAbsent(ctx)
	if len(diags) != 5 || !hasDiag(diags, "test: symbol table has no _KTHREAD.Process: Process unreadable on every thread") {
		t.Errorf("diagnostics %q", diags)
	}
}

func FuzzThreadColumns(f *testing.F) {
	tab := columnTable()
	r := NewColumnReader(tools.Context{Symbols: tab}, "fuzz")
	seed := make([]byte, testsupport.S50ThreadSize)
	binary.LittleEndian.PutUint64(seed[testsupport.S50ThreadExitTime:], created)
	f.Add(seed)
	f.Add(seed[:0x300])
	f.Fuzz(func(t *testing.T, raw []byte) {
		c := r.Read(pageReader{base: body, data: raw}, body)
		if !c.ExitTimeUnreadable && !c.ExitTime.IsZero() {
			v := binary.LittleEndian.Uint64(raw[testsupport.S50ThreadExitTime:])
			if v>>63 != 0 || v == 0 {
				t.Fatalf("exit time %v from 0x%x", c.ExitTime, v)
			}
		}
		if c.StartAddressInvalid && c.StartAddress != 0 {
			t.Fatalf("StartAddressInvalid with address 0x%x", c.StartAddress)
		}
	})
}

func hasDiag(diags []string, part string) bool {
	for _, d := range diags {
		if strings.Contains(d, part) {
			return true
		}
	}
	return false
}
