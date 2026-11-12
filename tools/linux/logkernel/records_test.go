package logkernel

import (
	"errors"
	"strings"
	"testing"

	lt "github.com/aoiflux/libvapour/symbols/linuxkernel/linuxtest"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const (
	logBufSym      = 0xffffffff83000000
	logBufLenSym   = 0xffffffff83000010
	logFirstIdxSym = 0xffffffff83000020
	logNextIdxSym  = 0xffffffff83000030
	logFirstSeqSym = 0xffffffff83000040
	logNextSeqSym  = 0xffffffff83000050
	logBufAt       = 0xffffffff85000000
)

type logFix struct {
	types   *Types
	mem     *Memory
	hdr     uint64
	caller  bool
	size    uint64
	first   uint64
	next    uint64
	seq0    uint64
	seqN    uint64
	noSeq   bool
	typName string
	opts    map[string]any
}

func logTypes(i *Types, name string, caller bool) uint64 {
	size := uint64(16)
	fields := map[string]F{
		"ts_nsec": fld(0, Base("long long unsigned int")), "len": fld(8, Base("short unsigned int")),
		"text_len": fld(10, Base("short unsigned int")), "dict_len": fld(12, Base("short unsigned int")),
		"facility": fld(14, Base("unsigned char")), "flags": fld(15, Bits(0, 5, "unsigned char")),
		"level": fld(15, Bits(5, 3, "unsigned char")),
	}
	if caller {
		fields["caller_id"] = fld(16, Base("unsigned int"))
		size = 20
	}
	i.Struct(name, size, fields)
	return size
}

func newLog(size uint64, caller bool) *logFix {
	f := &logFix{types: NewTypes(8), mem: NewMemory(), size: size, caller: caller, typName: "printk_log"}
	f.hdr = logTypes(f.types, f.typName, caller)
	f.mem.Map(logBufAt, size)
	return f
}

// store writes one record as log_store does, with the end marker when the
// record and one more header would not fit.
func (f *logFix) store(text, dict string, level, facility, flags uint8, ts uint64, caller uint32) {
	body := uint64(len(text) + len(dict))
	l := (f.hdr + body + 3) &^ 3
	if f.next+l+f.hdr > f.size {
		f.mem.Write(logBufAt+f.next, make([]byte, f.hdr))
		f.next = 0
	}
	at := logBufAt + f.next
	f.mem.U64(at, ts)
	f.mem.U16(at+8, uint16(l))
	f.mem.U16(at+10, uint16(len(text)))
	f.mem.U16(at+12, uint16(len(dict)))
	f.mem.U8(at+14, facility)
	f.mem.U8(at+15, flags|level<<5)
	if f.caller {
		f.mem.U32(at+16, caller)
	}
	f.mem.Write(at+f.hdr, []byte(text+dict))
	f.next += l
	f.seqN++
}

func (f *logFix) symbols() {
	i := f.types
	i.Symbol("log_buf", logBufSym, Ptr(Base("char")))
	i.Symbol("log_buf_len", logBufLenSym, Base("unsigned int"))
	i.Symbol("log_first_idx", logFirstIdxSym, Base("unsigned int"))
	i.Symbol("log_next_idx", logNextIdxSym, Base("unsigned int"))
	if !f.noSeq {
		i.Symbol("log_first_seq", logFirstSeqSym, Base("long long unsigned int"))
		i.Symbol("log_next_seq", logNextSeqSym, Base("long long unsigned int"))
	}
	f.mem.U64(logBufSym, logBufAt)
	f.mem.U32(logBufLenSym, uint32(f.size))
	f.mem.U32(logFirstIdxSym, uint32(f.first))
	f.mem.U32(logNextIdxSym, uint32(f.next))
	f.mem.U64(logFirstSeqSym, f.seq0)
	f.mem.U64(logNextSeqSym, f.seqN)
}

func (f *logFix) run(t *testing.T) ([]Row, []string, error) {
	t.Helper()
	f.symbols()
	ctx, diags := Context(f.mem, f.types.Table(t), f.opts)
	rows, err := Run(ctx)
	return rows, *diags, err
}

func TestRecordsAreWalkedFromFirstToNext(t *testing.T) {
	f := newLog(512, true)
	f.seq0, f.seqN = 10, 10
	f.store("Linux version 5.9.0", "", 5, 0, 2, 0, 0)
	f.store("pci 0000:00:02.0: [1234:1111]", "SUBSYSTEM=pci\x00DEVICE=+pci:0000:00:02.0", 6, 0, 2, 1_000, 1)
	f.store("two\nlines", "", 3, 1, flagCont, 2_000, 0x80000001)
	rows, diags, err := f.run(t)
	if err != nil || len(diags) != 0 {
		t.Fatalf("%v %q", err, diags)
	}
	want := []Row{
		{Sequence: 10, HasSequence: true, HasTimestamp: true, Facility: "kern", HasFacility: true, Level: LevelNotice, Caller: "T0", Final: true, Line: "Linux version 5.9.0", LineEscaped: "Linux version 5.9.0"},
		{Sequence: 11, HasSequence: true, TimestampNsec: 1_000, HasTimestamp: true, Facility: "kern", HasFacility: true, Level: LevelInfo, Caller: "T1",
			Subsystem: "pci", Device: "+pci:0000:00:02.0", Final: true, Line: "pci 0000:00:02.0: [1234:1111]", LineEscaped: "pci 0000:00:02.0: [1234:1111]"},
		{Sequence: 12, HasSequence: true, TimestampNsec: 2_000, HasTimestamp: true, Facility: "user", FacilityNumber: 1, HasFacility: true, Level: LevelErr, Caller: "C1",
			Fragment: true, Final: true, Line: "two", LineEscaped: "two"},
		{Sequence: 12, HasSequence: true, TimestampNsec: 2_000, HasTimestamp: true, Facility: "user", FacilityNumber: 1, HasFacility: true, Level: LevelErr, Caller: "C1",
			Fragment: true, Final: true, Line: "lines", LineEscaped: "lines"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d\n got %s\nwant %s", i, describe(rows[i]), describe(want[i]))
		}
	}
}

func TestTheWalkGoesOnAtZeroAfterTheEndMarker(t *testing.T) {
	f := newLog(128, false)
	f.next, f.first = 64, 64
	f.store("aaaaaaaaaaaaaaaaaaaaaaaa", "", 6, 0, 0, 1, 0)
	f.store("bbbbbbbbbbbbbbbbbbbbbbbb", "", 6, 0, 0, 2, 0)
	f.store("c", "", 6, 0, 0, 3, 0)
	rows, diags, err := f.run(t)
	if err != nil || len(diags) != 0 {
		t.Fatalf("%v %q", err, diags)
	}
	if got := lines(rows); got != strings.Repeat("a", 24)+"|"+strings.Repeat("b", 24)+"|c" {
		t.Errorf("lines %q", got)
	}
	if rows[0].Caller != "" {
		t.Errorf("a header without caller_id gives no caller: %q", rows[0].Caller)
	}
}

func TestAFullBufferHasEqualOffsetsAndTheSequenceTellsItFromEmpty(t *testing.T) {
	f := newLog(80, false)
	f.store("dropped by third", "", 6, 0, 0, 1, 0)
	f.store("0123456789abcdef", "", 6, 0, 0, 2, 0)
	f.store("written over 1st", "", 6, 0, 0, 3, 0)
	f.first, f.seq0 = 32, 1
	if f.next != 32 || f.seqN != 3 {
		t.Fatalf("fixture: next %d, seq %d", f.next, f.seqN)
	}
	rows, diags, err := f.run(t)
	if err != nil || len(diags) != 0 || lines(rows) != "0123456789abcdef|written over 1st" || rows[1].Sequence != 2 {
		t.Fatalf("rows %v, diags %q, err %v", rows, diags, err)
	}
	f.seq0 = f.seqN
	if rows, _, _ := f.run(t); len(rows) != 0 {
		t.Errorf("equal sequence numbers mean empty: %v", rows)
	}
}

func TestWithoutSequenceNumbersTheWalkEndsAtTheNextOffset(t *testing.T) {
	f := newLog(512, false)
	f.noSeq = true
	f.store("one", "", 6, 0, 0, 1, 0)
	f.store("two", "", 6, 0, 0, 2, 0)
	rows, diags, err := f.run(t)
	if err != nil || len(diags) != 0 || lines(rows) != "one|two" || rows[0].HasSequence {
		t.Fatalf("rows %v, diags %q, err %v", rows, diags, err)
	}
	empty := newLog(512, false)
	empty.noSeq = true
	empty.mem.Write(logBufAt, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 3, 0})
	rows, diags, err = empty.run(t)
	if err != nil || len(rows) != 0 || len(diags) != 0 {
		t.Errorf("equal offsets and no valid record there mean empty: %v %q %v", rows, diags, err)
	}
}

func TestAnInvalidRecordEndsTheWalk(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(f *logFix)
		cause error
	}{
		{"len below the parts", func(f *logFix) { f.mem.U16(logBufAt+28+8, 18) }, errRecordHeader},
		{"padding of eight", func(f *logFix) { f.mem.U16(logBufAt+28+8, 32) }, errRecordHeader},
		{"past the buffer", func(f *logFix) { f.mem.U16(logBufAt+28+8, 0x200) }, errRecordHeader},
		{"past the first record after the wrap", func(f *logFix) { f.mem.U16(logBufAt+28+8, 0) }, errRecordHeader},
		{"unreadable", func(f *logFix) { f.mem.Unmap(logBufAt) }, skipErrors[skipUnread]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newLog(512, false)
			f.store("first record", "", 6, 0, 0, 1, 0)
			f.store("second", "", 6, 0, 0, 2, 0)
			f.store("third", "", 6, 0, 0, 3, 0)
			c.edit(f)
			rows, diags, err := f.run(t)
			if err != nil {
				t.Fatal(err)
			}
			if c.name != "unreadable" && lines(rows) != "first record" {
				t.Errorf("the records before the bad one are kept: %q", lines(rows))
			}
			if len(diags) != 1 || !strings.Contains(diags[0], c.cause.Error()) || !strings.HasPrefix(diags[0], Name+": record at 0x") {
				t.Errorf("diags %q", diags)
			}
			f.opts = map[string]any{"strict": true}
			if _, _, err := f.run(t); err == nil {
				t.Error("strict mode: a walk that ended early is an error")
			}
		})
	}
}

func TestARecordBufferHeaderOutOfRangeIsRefused(t *testing.T) {
	cases := []struct {
		name string
		want error
		edit func(f *logFix)
	}{
		{"empty buffer", ErrHeader, func(f *logFix) { f.size = 0 }},
		{"first past the end", ErrHeader, func(f *logFix) { f.first = 600 }},
		{"sequence backwards", ErrHeader, func(f *logFix) { f.seq0 = 9 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newLog(512, false)
			f.store("x", "", 6, 0, 0, 1, 0)
			c.edit(f)
			if _, _, err := f.run(t); !errors.Is(err, c.want) {
				t.Errorf("err %v, want %v", err, c.want)
			}
		})
	}
	f := newLog(512, false)
	f.size = 1 << 30
	if _, _, err := f.run(t); !errors.Is(err, ErrLimit) {
		t.Errorf("a buffer over MaxBufferBytes: %v", err)
	}
}

func TestTheRecordHeaderMayBeStructLogOrComeFromVMCoreInfo(t *testing.T) {
	old := newLog(256, false)
	old.types = NewTypes(8)
	old.typName = "log"
	logTypes(old.types, "log", false)
	old.store("v3.5 record", "", 4, 0, 0, 7, 0)
	rows, _, err := old.run(t)
	if err != nil || lines(rows) != "v3.5 record" || rows[0].Level != LevelWarning {
		t.Fatalf("struct log: %v %v", rows, err)
	}

	f := newLog(256, true)
	f.store("from vmcoreinfo", "", 2, 3, flagCont, 9, 4)
	f.types = NewTypes(8)
	buf := make([]byte, 0x4000)
	lt.PutNote(buf, 0x1000, "OSRELEASE=5.9.0\nSIZE(printk_log)=20\nOFFSET(printk_log.ts_nsec)=0\nOFFSET(printk_log.len)=8\n"+
		"OFFSET(printk_log.text_len)=10\nOFFSET(printk_log.dict_len)=12\nOFFSET(printk_log.caller_id)=16\n")
	f.opts = withPhysical(nil, &lt.Memory{Buf: buf})
	rows, _, err = f.run(t)
	want := Row{Sequence: 0, HasSequence: true, TimestampNsec: 9, HasTimestamp: true, Facility: "daemon", FacilityNumber: 3, HasFacility: true, Level: LevelCrit,
		Caller: "T4", Fragment: true, Final: true, Line: "from vmcoreinfo", LineEscaped: "from vmcoreinfo"}
	if err != nil || len(rows) != 1 || rows[0] != want {
		t.Errorf("rows %v, err %v, want %s", rows, err, describe(want))
	}
}
