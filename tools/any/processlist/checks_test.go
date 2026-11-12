package processlist

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	ckEPROCESS   = uint64(0xffffd00000100000)
	ckETHREAD    = uint64(0xffffd00000200000)
	ckPID        = uint64(0x2e8)
	ckCreated    = uint64(0x308)
	ckExited     = uint64(0x310)
	ckName       = uint64(0x450)
	ckThreadHead = uint64(0x488)
	ckRoot       = uint64(0x28)
	ckCid        = uint64(0x630)
	ckThreadTime = uint64(0x5e0)
	ckSystemTime = uint64(0x14)
	ckBootTime   = uint64(0xfffff80000300000)
	ckBootBias   = uint64(0xfffff80000300040)
	ckShared     = uint64(0xFFFFF78000000000)
	ckLinkA      = uint64(0xffffd00000400578)
	ckLinkB      = uint64(0xffffd00000500578)
	ckRootValue  = uint64(0x1ad000)
	ckPhysical   = uint64(0x40000000)
	ckTick       = uint64(10_000_000)
)

var (
	ckNow  = checkFileTime(time.Date(2026, 5, 6, 18, 24, 25, 0, time.UTC))
	ckBoot = ckNow - 3600*ckTick
	ckBias = 300 * ckTick
)

func checkFileTime(t time.Time) uint64 {
	const secondsFrom1601To1970 = 11644473600
	return uint64(t.Unix()+secondsFrom1601To1970) * ckTick
}

// Sparse 4 KiB pages; a read of a page never written fails, as a hole in a
// capture does.
type ckMemory map[uint64]*[4096]byte

func (m ckMemory) page(addr uint64) *[4096]byte {
	p, ok := m[addr&^0xFFF]
	if !ok {
		p = new([4096]byte)
		m[addr&^0xFFF] = p
	}
	return p
}

func (m ckMemory) put(addr uint64, b []byte) {
	for i, v := range b {
		m.page(addr + uint64(i))[(addr+uint64(i))&0xFFF] = v
	}
}

func (m ckMemory) put64(addr, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	m.put(addr, b[:])
}

func (m ckMemory) ReadAt(addr, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := uint64(0); i < size; i++ {
		p, ok := m[(addr+i)&^0xFFF]
		if !ok {
			return nil, errors.New("page not captured")
		}
		out[i] = p[(addr+i)&0xFFF]
	}
	return out, nil
}

func (m ckMemory) Size() uint64 { return 1<<64 - 1 }

type ckPhys struct{ size uint64 }

func (p ckPhys) ReadAt(uint64, uint64) ([]byte, error) { return nil, errors.New("unused") }
func (p ckPhys) Size() uint64                          { return p.size }

func checkSymbols(omit ...string) *symbols.Table {
	skip := map[string]bool{}
	for _, o := range omit {
		skip[o] = true
	}
	fields := func(typ string, fs ...symbols.Field) []symbols.Field {
		out := []symbols.Field{}
		for _, f := range fs {
			if !skip[typ+"."+f.Name] {
				out = append(out, f)
			}
		}
		return out
	}
	t := symbols.NewTable("checks", 8)
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x800, Fields: fields("_EPROCESS",
		symbols.Field{Name: "Pcb", Offset: 0},
		symbols.Field{Name: "UniqueProcessId", Offset: ckPID},
		symbols.Field{Name: "CreateTime", Offset: ckCreated},
		symbols.Field{Name: "ExitTime", Offset: ckExited},
		symbols.Field{Name: "ImageFileName", Offset: ckName, Type: symbols.TypeRef{Name: "unsigned char", ArrayLength: 15}},
		symbols.Field{Name: "ThreadListHead", Offset: ckThreadHead},
	)})
	t.AddStruct(symbols.StructType{Name: "_KPROCESS", Size: 0x438, Fields: fields("_KPROCESS",
		symbols.Field{Name: "DirectoryTableBase", Offset: ckRoot},
	)})
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 0x10, Fields: []symbols.Field{
		{Name: "Flink", Offset: 0}, {Name: "Blink", Offset: 8},
	}})
	t.AddStruct(symbols.StructType{Name: "_ETHREAD", Size: 0x800, Fields: fields("_ETHREAD",
		symbols.Field{Name: "Cid", Offset: ckCid},
		symbols.Field{Name: "CreateTime", Offset: ckThreadTime},
	)})
	t.AddStruct(symbols.StructType{Name: "_CLIENT_ID", Size: 0x10, Fields: fields("_CLIENT_ID",
		symbols.Field{Name: "UniqueProcess", Offset: 0},
		symbols.Field{Name: "UniqueThread", Offset: 8},
	)})
	t.AddStruct(symbols.StructType{Name: "_KUSER_SHARED_DATA", Size: 0x800, Fields: fields("_KUSER_SHARED_DATA",
		symbols.Field{Name: "SystemTime", Offset: ckSystemTime},
	)})
	if !skip["KeBootTime"] {
		t.AddSymbol(symbols.Symbol{Name: "KeBootTime", Address: ckBootTime})
	}
	t.AddSymbol(symbols.Symbol{Name: "KeBootTimeBias", Address: ckBootBias})
	return t
}

type ckImage struct {
	mem ckMemory
	ctx tools.Context
}

// One running process and one of its threads, both created a minute after
// boot, in a capture taken an hour after boot.
func newCkImage(omit ...string) ckImage {
	mem := ckMemory{}
	mem.put64(ckShared+ckSystemTime, ckNow)
	mem.put64(ckBootTime, ckBoot)
	mem.put64(ckBootBias, ckBias)

	var name [15]byte
	copy(name[:], "svchost.exe")
	mem.put(ckEPROCESS+ckName, name[:])
	mem.put64(ckEPROCESS+ckPID, 1300)
	mem.put64(ckEPROCESS+ckCreated, ckBoot+60*ckTick)
	mem.put64(ckEPROCESS+ckExited, 0)
	mem.put64(ckEPROCESS+ckRoot, ckRootValue)
	mem.put64(ckEPROCESS+ckThreadHead, ckLinkA)
	mem.put64(ckEPROCESS+ckThreadHead+8, ckLinkB)

	mem.put64(ckETHREAD+ckCid, 1300)
	mem.put64(ckETHREAD+ckCid+8, 1304)
	mem.put64(ckETHREAD+ckThreadTime, ckBoot+60*ckTick)

	return ckImage{mem: mem, ctx: tools.Context{
		Memory:  mem,
		Symbols: checkSymbols(omit...),
		Options: map[string]any{tools.OptionPhysicalMemory: ckPhys{ckPhysical}},
	}}
}

func (im ckImage) process() error {
	_, err := NewProcessCheck(im.ctx).Check(im.mem, ckEPROCESS)
	return err
}

func (im ckImage) thread() error { return NewThreadCheck(im.ctx).Check(im.mem, ckETHREAD) }

func TestTheWindowRunsFromBootLessBiasToCaptureTimePlusAllowance(t *testing.T) {
	w := ReadTimeWindow(newCkImage().ctx)
	if w.Earliest != ckBoot-ckBias || w.Latest != ckNow+captureAllowance {
		t.Errorf("window [%d, %d], want [%d, %d]", w.Earliest, w.Latest, ckBoot-ckBias, ckNow+captureAllowance)
	}
}

func TestTheWindowFallsBackWhenTheClockDoesNotRead(t *testing.T) {
	im := newCkImage()
	delete(im.mem, (ckShared+ckSystemTime)&^0xFFF)
	delete(im.mem, ckBootTime&^0xFFF)
	if w := ReadTimeWindow(im.ctx); w.Earliest != 1 || w.Latest != maxFileTime {
		t.Errorf("window [%d, %d], want [1, %d]", w.Earliest, w.Latest, maxFileTime)
	}
	if w := ReadTimeWindow(newCkImage("KeBootTime").ctx); w.Earliest != 1 {
		t.Errorf("earliest %d without KeBootTime, want 1", w.Earliest)
	}
}

func TestANegativeBiasWidensTheWindowByItsSize(t *testing.T) {
	im := newCkImage()
	im.mem.put64(ckBootBias, uint64(-int64(ckBias)))
	if w := ReadTimeWindow(im.ctx); w.Earliest != ckBoot-ckBias {
		t.Errorf("earliest %d, want %d", w.Earliest, ckBoot-ckBias)
	}
	im.mem.put64(ckBootBias, ckBoot+1)
	if w := ReadTimeWindow(im.ctx); w.Earliest != 1 {
		t.Errorf("earliest %d with a bias past the boot time, want 1", w.Earliest)
	}
}

func TestTheFixtureProcessAndThreadPass(t *testing.T) {
	im := newCkImage()
	id, err := NewProcessCheck(im.ctx).Check(im.mem, ckEPROCESS)
	if err != nil || id.PID != 1300 || id.Name != "svchost.exe" {
		t.Fatalf("got %+v, %v", id, err)
	}
	if err := im.thread(); err != nil {
		t.Fatalf("thread: %v", err)
	}
}

func TestEachProcessRuleRejectsOnItsOwn(t *testing.T) {
	for _, c := range []struct {
		name  string
		at    uint64
		value uint64
		want  error
	}{
		{"empty name", ckName, 0, ErrNoImageName},
		{"pid 0", ckPID, 0, ErrBadID},
		{"pid not a multiple of 4", ckPID, 1302, ErrBadID},
		{"pid past a dword", ckPID, 0x100000000, ErrBadID},
		{"created before boot less bias", ckCreated, ckBoot - ckBias - 1, ErrCreateTime},
		{"created past the allowance", ckCreated, ckNow + captureAllowance + 1, ErrCreateTime},
		{"created at 0", ckCreated, 0, ErrCreateTime},
		{"exited before created", ckExited, ckBoot + 59*ckTick, ErrExitTime},
		{"exited past the allowance", ckExited, ckNow + captureAllowance + 1, ErrExitTime},
		{"page-table root of flag bits only", ckRoot, 0xFFF, ErrPageTableRoot},
		{"page-table root past physical memory", ckRoot, ckPhysical, ErrPageTableRoot},
		{"thread Flink in user space", ckThreadHead, 0x7FFFFFFF0000, ErrThreadLinks},
		{"thread Blink in user space", ckThreadHead + 8, 0x10000, ErrThreadLinks},
	} {
		t.Run(c.name, func(t *testing.T) {
			im := newCkImage()
			im.mem.put64(ckEPROCESS+c.at, c.value)
			if err := im.process(); !errors.Is(err, c.want) {
				t.Errorf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestWhatAProcessMayHold(t *testing.T) {
	for _, c := range []struct {
		name  string
		at    uint64
		value uint64
	}{
		{"the largest pid", ckPID, maxID},
		{"created at the window's start", ckCreated, ckBoot - ckBias},
		{"created a minute after the capture time", ckCreated, ckNow + 60*ckTick},
		{"exited at its creation time", ckExited, ckBoot + 60*ckTick},
		{"a page-table root with flag bits set", ckRoot, ckRootValue | 0x18},
		{"an empty thread list", ckThreadHead, ckEPROCESS + ckThreadHead},
	} {
		t.Run(c.name, func(t *testing.T) {
			im := newCkImage()
			im.mem.put64(ckEPROCESS+c.at, c.value)
			if c.at == ckThreadHead {
				im.mem.put64(ckEPROCESS+ckThreadHead+8, c.value)
			}
			if err := im.process(); err != nil {
				t.Errorf("rejected: %v", err)
			}
		})
	}
}

func TestWithoutPhysicalMemoryTheRootOnlyHasToFitFiftyTwoBits(t *testing.T) {
	im := newCkImage()
	im.ctx.Options = nil
	im.mem.put64(ckEPROCESS+ckRoot, ckPhysical)
	if err := im.process(); err != nil {
		t.Errorf("rejected: %v", err)
	}
	im.mem.put64(ckEPROCESS+ckRoot, 1<<52)
	if err := im.process(); !errors.Is(err, ErrPageTableRoot) {
		t.Errorf("got %v, want %v", err, ErrPageTableRoot)
	}
}

func TestAProcessCheckWithoutItsRequiredMembersRejectsEverything(t *testing.T) {
	for _, m := range []string{"_EPROCESS.ImageFileName", "_EPROCESS.UniqueProcessId"} {
		im := newCkImage(m)
		check := NewProcessCheck(im.ctx)
		if _, err := check.Check(im.mem, ckEPROCESS); check.Usable() || !errors.Is(err, ErrCheckUnusable) {
			t.Errorf("without %s: usable %v, err %v", m, check.Usable(), err)
		}
	}
}

func TestAnAbsentOptionalMemberDropsOnlyItsRule(t *testing.T) {
	for _, c := range []struct {
		member string
		at     uint64
		value  uint64
	}{
		{"_EPROCESS.CreateTime", ckCreated, 0},
		{"_EPROCESS.ExitTime", ckExited, 1},
		{"_KPROCESS.DirectoryTableBase", ckRoot, 0},
		{"_EPROCESS.ThreadListHead", ckThreadHead, 0x1000},
	} {
		im := newCkImage(c.member)
		im.mem.put64(ckEPROCESS+c.at, c.value)
		if err := im.process(); err != nil {
			t.Errorf("without %s: rejected: %v", c.member, err)
		}
	}
}

func TestAnUnreadMemberRejectsTheProcess(t *testing.T) {
	im := newCkImage()
	if _, err := NewProcessCheck(im.ctx).Check(im.mem, 0xffffd00000900000); !errors.Is(err, ErrMemberUnread) {
		t.Errorf("got %v, want %v", err, ErrMemberUnread)
	}
}

func TestEachThreadRuleRejectsOnItsOwn(t *testing.T) {
	for _, c := range []struct {
		name  string
		at    uint64
		value uint64
		want  error
	}{
		{"tid 0", ckCid + 8, 0, ErrBadID},
		{"tid not a multiple of 4", ckCid + 8, 1305, ErrBadID},
		{"owner 0, as an idle thread or a zeroed body", ckCid, 0, ErrBadID},
		{"owner past a dword", ckCid, 0x100000004, ErrBadID},
		{"created before the window", ckThreadTime, ckBoot - ckBias - 1, ErrCreateTime},
		{"created past the allowance", ckThreadTime, ckNow + captureAllowance + 1, ErrCreateTime},
	} {
		t.Run(c.name, func(t *testing.T) {
			im := newCkImage()
			im.mem.put64(ckETHREAD+c.at, c.value)
			if err := im.thread(); !errors.Is(err, c.want) {
				t.Errorf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestASystemThreadMayPredateTheClock(t *testing.T) {
	for _, created := range []uint64{0, 0x17f2b4} {
		im := newCkImage()
		im.mem.put64(ckETHREAD+ckCid, 4)
		im.mem.put64(ckETHREAD+ckThreadTime, created)
		if err := im.thread(); err != nil {
			t.Errorf("created %#x: rejected: %v", created, err)
		}
	}
	im := newCkImage()
	im.mem.put64(ckETHREAD+ckCid, 4)
	im.mem.put64(ckETHREAD+ckThreadTime, ckNow+captureAllowance+1)
	if err := im.thread(); !errors.Is(err, ErrCreateTime) {
		t.Errorf("got %v, want %v", err, ErrCreateTime)
	}
}

func TestAThreadMayStartBeforeItsProcess(t *testing.T) {
	im := newCkImage()
	im.mem.put64(ckETHREAD+ckThreadTime, ckBoot+60*ckTick-400)
	if err := im.thread(); err != nil {
		t.Errorf("rejected: %v", err)
	}
}

func TestAThreadCheckWithoutTheCidIsUnusable(t *testing.T) {
	im := newCkImage("_ETHREAD.Cid")
	check := NewThreadCheck(im.ctx)
	if check.Usable() || !errors.Is(check.Check(im.mem, ckETHREAD), ErrCheckUnusable) {
		t.Error("a thread check without _ETHREAD.Cid claims to be usable")
	}
	im = newCkImage("_ETHREAD.CreateTime")
	im.mem.put64(ckETHREAD+ckThreadTime, 0)
	if err := NewThreadCheck(im.ctx).Check(im.mem, ckETHREAD); err != nil {
		t.Errorf("without CreateTime: rejected: %v", err)
	}
}

func TestSystemSpaceFollowsThePointerSize(t *testing.T) {
	for _, c := range []struct {
		addr, pointer uint64
		want          bool
	}{
		{0xFFFF800000000000, 8, true},
		{0xFF00000000000000, 8, true},
		{0x00007FFFFFFFFFFF, 8, false},
		{0x80000000, 8, false},
		{0x80000000, 4, true},
		{0x7FFFFFFF, 4, false},
		{0x100000000, 4, false},
	} {
		if got := inSystemSpace(c.addr, c.pointer); got != c.want {
			t.Errorf("inSystemSpace(%#x, %d) = %v, want %v", c.addr, c.pointer, got, c.want)
		}
	}
}

func FuzzProcessAndThreadChecks(f *testing.F) {
	im := newCkImage()
	seed, _ := im.mem.ReadAt(ckEPROCESS, 0x800)
	f.Add(seed)
	f.Add(make([]byte, 0x800))
	f.Fuzz(func(t *testing.T, body []byte) {
		im := newCkImage()
		im.mem.put(ckEPROCESS, body)
		im.mem.put(ckETHREAD, body)
		w := ReadTimeWindow(im.ctx)
		u64 := func(base, at uint64) (uint64, bool) {
			b, err := im.mem.ReadAt(base+at, 8)
			if err != nil {
				return 0, false
			}
			return binary.LittleEndian.Uint64(b), true
		}
		if id, err := NewProcessCheck(im.ctx).Check(im.mem, ckEPROCESS); err == nil {
			created, _ := u64(ckEPROCESS, ckCreated)
			exited, _ := u64(ckEPROCESS, ckExited)
			root, _ := u64(ckEPROCESS, ckRoot)
			flink, _ := u64(ckEPROCESS, ckThreadHead)
			blink, _ := u64(ckEPROCESS, ckThreadHead+8)
			head := ckEPROCESS + ckThreadHead
			switch {
			case id.Name == "" || !validID(id.PID):
				t.Fatalf("accepted %+v", id)
			case !w.Holds(created), exited != 0 && (!w.Holds(exited) || exited < created):
				t.Fatalf("accepted times %d, %d", created, exited)
			case root&^0xFFF == 0 || root&^0xFFF >= ckPhysical:
				t.Fatalf("accepted root %#x", root)
			case flink != head && flink>>63 == 0, blink != head && blink>>63 == 0:
				t.Fatalf("accepted links %#x, %#x", flink, blink)
			}
		}
		if err := NewThreadCheck(im.ctx).Check(im.mem, ckETHREAD); err == nil {
			owner, _ := u64(ckETHREAD, ckCid)
			tid, _ := u64(ckETHREAD, ckCid+8)
			created, _ := u64(ckETHREAD, ckThreadTime)
			if !validID(owner) || !validID(tid) || created > w.Latest || owner != 4 && created < w.Earliest {
				t.Fatalf("accepted thread %d/%d created %d", owner, tid, created)
			}
		}
	})
}
