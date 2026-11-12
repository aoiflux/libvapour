package logkernel

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

func TestTheRingGivesOneRowPerLineInRecordOrder(t *testing.T) {
	f := newRing(4, 10, 0)
	f.add(rec{text: "Linux version 6.17.0", level: 5, caller: 0})
	f.add(rec{text: "first\nsecond", level: 6, ts: 1_500_000_123, caller: 0x80000002})
	f.add(rec{text: "usb 1-1: new device", level: 6, ts: 2_000_000_000, caller: 77, subsystem: "usb", device: "c189:1"})
	f.add(rec{text: "tail", level: 4, facility: 3, flags: flagCont, ts: 3, caller: 9})
	rows, diags, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{
		{Sequence: 0, HasSequence: true, HasTimestamp: true, Facility: "kern", HasFacility: true, Level: LevelNotice, Caller: "T0", Final: true, Line: "Linux version 6.17.0", LineEscaped: "Linux version 6.17.0"},
		{Sequence: 1, HasSequence: true, TimestampNsec: 1_500_000_123, HasTimestamp: true, Facility: "kern", HasFacility: true, Level: LevelInfo, Caller: "C2", Final: true, Line: "first", LineEscaped: "first"},
		{Sequence: 1, HasSequence: true, TimestampNsec: 1_500_000_123, HasTimestamp: true, Facility: "kern", HasFacility: true, Level: LevelInfo, Caller: "C2", Final: true, Line: "second", LineEscaped: "second"},
		{Sequence: 2, HasSequence: true, TimestampNsec: 2_000_000_000, HasTimestamp: true, Facility: "kern", HasFacility: true, Level: LevelInfo, Caller: "T77",
			Subsystem: "usb", Device: "c189:1", Final: true, Line: "usb 1-1: new device", LineEscaped: "usb 1-1: new device"},
		{Sequence: 3, HasSequence: true, TimestampNsec: 3, HasTimestamp: true, Facility: "daemon", FacilityNumber: 3, HasFacility: true, Level: LevelWarning, Caller: "T9",
			Fragment: true, Final: true, Line: "tail", LineEscaped: "tail"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %v, want %d", rows, len(want))
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d\n got %s\nwant %s", i, describe(rows[i]), describe(want[i]))
		}
	}
	if len(diags) != 0 {
		t.Errorf("the bootstrap descriptor is not a record and gives no diagnostic: %q", diags)
	}
}

func TestDescriptorStatesDecideWhatIsRead(t *testing.T) {
	f := newRing(4, 10, 0)
	f.add(rec{text: "final"})
	f.add(rec{text: "being written", state: fxReserved})
	f.add(rec{text: "recycled", state: fxReusable})
	overwritten := f.add(rec{text: "other id"})
	f.add(rec{text: "waiting for a continuation", state: fxCommitted})
	f.mem.U64(f.descAt(overwritten), kernelState[fxFinalized]<<stateTop|(overwritten+16)&idMask64)
	f.opts = map[string]any{"strict": true}
	rows, diags, err := f.run(t)
	if err != nil {
		t.Fatalf("kernel states are not read failures, even in strict mode: %v", err)
	}
	if got := lines(rows); got != "final|waiting for a continuation" {
		t.Errorf("lines %q", got)
	}
	if len(rows) == 2 && (!rows[0].Final || rows[1].Final) {
		t.Errorf("only the finalized record is final: %s, %s", describe(rows[0]), describe(rows[1]))
	}
	all := strings.Join(diags, "\n")
	for _, why := range []skip{skipReserved, skipReusable, skipMiss} {
		if !strings.Contains(all, "descriptors skipped: 1: "+skipErrors[why].Error()) {
			t.Errorf("no diagnostic for %v in %q", skipErrors[why], diags)
		}
	}
	if !strings.HasPrefix(diags[0], Name+": ring at 0xffff83000100: ") {
		t.Errorf("diagnostic form %q", diags[0])
	}
}

func TestABlockPastTheArrayEndIsStoredFromIndexZero(t *testing.T) {
	f := newRing(4, 8, 256-16)
	f.add(rec{text: "twenty bytes of text"})
	f.add(rec{text: "next"})
	rows, diags, err := f.run(t)
	if err != nil || len(diags) != 0 {
		t.Fatalf("%v %q", err, diags)
	}
	if got := lines(rows); got != "twenty bytes of text|next" {
		t.Errorf("lines %q", got)
	}
}

func TestAnEmptyLineHasNoDataBlock(t *testing.T) {
	f := newRing(4, 10, 0)
	f.add(rec{emptyLine: true})
	f.add(rec{text: "trailing newline\n"})
	rows, _, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if got := lines(rows); got != "|trailing newline|" || len(rows) != 3 {
		t.Errorf("lines %q", got)
	}
}

func TestBrokenRecordsAreSkipped(t *testing.T) {
	cases := []struct {
		name   string
		why    skip
		strict bool
		breakR func(f *ringFix, id uint64)
	}{
		{"lost data", skipLost, false, func(f *ringFix, id uint64) {
			f.mem.U64(f.descAt(id)+8, lposFailed)
			f.mem.U64(f.descAt(id)+16, lposFailed)
		}},
		{"misaligned block", skipInvalid, true, func(f *ringFix, id uint64) { f.mem.U64(f.descAt(id)+8, 4) }},
		{"next before begin", skipInvalid, true, func(f *ringFix, id uint64) {
			begin := f.read(f.descAt(id) + 8)
			f.mem.U64(f.descAt(id)+16, begin-16)
		}},
		{"outside head and tail", skipInvalid, true, func(f *ringFix, id uint64) {
			f.headLpos -= 8
			f.header()
		}},
		{"block id", skipDisagree, true, func(f *ringFix, id uint64) {
			f.mem.U64(dataAt+f.read(f.descAt(id)+8)&0x3ff, id+1)
		}},
		{"text past the block", skipInvalid, true, func(f *ringFix, id uint64) { f.mem.U16(f.infoAt(id)+16, 200) }},
		{"seq at another index", skipDisagree, true, func(f *ringFix, id uint64) { f.mem.U64(f.infoAt(id), 5) }},
		{"unreadable data", skipUnread, true, func(f *ringFix, id uint64) { f.mem.Unmap(dataAt) }},
		{"unreadable info", skipUnread, true, func(f *ringFix, id uint64) { f.mem.Unmap(infosAt) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRing(4, 10, 0)
			id := f.add(rec{text: "the broken one"})
			c.breakR(f, id)
			rows, diags, err := f.run(t)
			if err != nil || len(rows) != 0 {
				t.Fatalf("rows %v, err %v", rows, err)
			}
			if len(diags) != 1 || !strings.Contains(diags[0], skipErrors[c.why].Error()) {
				t.Errorf("diags %q, want %v", diags, skipErrors[c.why])
			}
			f.opts = map[string]any{"strict": true}
			_, _, err = f.run(t)
			if c.strict != (err != nil) {
				t.Errorf("strict mode error %v, want one: %v", err, c.strict)
			}
		})
	}
}

func (f *ringFix) read(at uint64) uint64 {
	b, err := f.mem.ReadAt(at, 8)
	if err != nil {
		panic(err)
	}
	return le(b)
}

func TestARingHeaderOutOfRangeIsRefused(t *testing.T) {
	cases := []struct {
		name string
		want error
		edit func(f *ringFix)
	}{
		{"null prb", ErrHeader, func(f *ringFix) { f.mem.U64(prbSym, 0) }},
		{"no count bits", ErrHeader, func(f *ringFix) { f.mem.U32(ringAt, 0) }},
		{"too many count bits", ErrHeader, func(f *ringFix) { f.mem.U32(ringAt, maxCountBits+1) }},
		{"too many size bits", ErrHeader, func(f *ringFix) { f.mem.U32(ringAt+48, maxSizeBits+1) }},
		{"null descriptors", ErrHeader, func(f *ringFix) { f.mem.U64(ringAt+8, 0) }},
		{"head far from tail", ErrHeader, func(f *ringFix) { f.mem.U64(ringAt+24, f.tailID+16) }},
		{"data head far from tail", ErrHeader, func(f *ringFix) { f.mem.U64(ringAt+64, f.tailLpos+1<<10+8) }},
		{"unreadable ring", ErrHeader, func(f *ringFix) { f.mem.U64(prbSym, 0xffffffff90000000) }},
		{"over the buffer cap", ErrLimit, func(f *ringFix) { f.lim = limits.Limits{MaxBufferBytes: 512, MaxTextBytes: 512, MaxNameBytes: 256} }},
		{"over the table cap", ErrLimit, func(f *ringFix) { f.lim = limits.Limits{MaxTableEntries: 8} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRing(4, 10, 0)
			f.add(rec{text: "x"})
			c.edit(f)
			_, _, err := f.run(t)
			if !errors.Is(err, c.want) || !strings.HasPrefix(err.Error(), Name+": ") {
				t.Errorf("err %v, want %v", err, c.want)
			}
		})
	}
}

func TestTheLayoutCanComeFromVMCoreInfo(t *testing.T) {
	typed := newRing(4, 10, 0)
	typed.add(rec{text: "a", level: 3, facility: 1, flags: flagCont, caller: 5, subsystem: "pci", device: "+pci:0000:00:01.0"})
	typed.add(rec{text: "b\nc", level: 7, ts: 42})
	want, _, err := typed.run(t)
	if err != nil {
		t.Fatal(err)
	}
	typed.types = NewTypes(8)
	typed.types.Symbol("prb", prbSym, Ptr(Void()))
	if _, _, err := typed.run(t); !errors.Is(err, ErrLayout) || !strings.Contains(err.Error(), "printk_info.seq") {
		t.Errorf("no types and no VMCOREINFO: %v, want ErrLayout naming the members", err)
	}
	typed.opts = withPhysical(nil, vmcoreinfoNote())
	got, _, err := typed.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("rows %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d\n got %s\nwant %s", i, describe(got[i]), describe(want[i]))
		}
	}
}

func TestNoLogSymbolIsErrNoLog(t *testing.T) {
	f := newRing(4, 10, 0)
	f.types = NewTypes(8)
	f.types.Symbol("init_task", prbSym, Ptr(Void()))
	if _, _, err := f.run(t); !errors.Is(err, ErrNoLog) {
		t.Errorf("err %v", err)
	}
}

func TestNamesFollowTheKernelAndRFC5424(t *testing.T) {
	for n, want := range map[uint8]Facility{0: "kern", 1: "user", 9: "cron", 5: "", 15: "", 16: "local0", 23: "local7", 200: ""} {
		if got := facilityName(n); got != want {
			t.Errorf("facility %d: %q, want %q", n, got, want)
		}
	}
	if callerText(0x80000003) != "C3" || callerText(1234) != "T1234" {
		t.Error("caller text")
	}
}

func TestAFacilityWithoutANameKeepsItsNumber(t *testing.T) {
	f := newRing(4, 10, 0)
	f.add(rec{text: "from /dev/kmsg", level: 6, facility: 5})
	f.add(rec{text: "from a user", level: 6, facility: 1})
	rows, _, err := f.run(t)
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %v", err, rows)
	}
	if r := rows[0]; r.Facility != "" || r.FacilityNumber != 5 || !r.HasFacility {
		t.Errorf("facility 5: %s", describe(r))
	}
	if r := rows[1]; r.Facility != "user" || r.FacilityNumber != 1 || !r.HasFacility {
		t.Errorf("facility 1: %s", describe(r))
	}
}

func TestTheEscapedLineKeepsTheBytesTheDecodedLineReplaces(t *testing.T) {
	f := newRing(4, 10, 0)
	f.add(rec{text: "tab\there \\ high \xff\xfe del \x7f caf\xc3\xa9", level: 6})
	rows, _, err := f.run(t)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%v %v", err, rows)
	}
	if want := "tab\there \\ high �� del \x7f café"; rows[0].Line != want {
		t.Errorf("decoded %q, want %q", rows[0].Line, want)
	}
	if want := `tab\x09here \x5c high \xff\xfe del \x7f caf\xc3\xa9`; rows[0].LineEscaped != want {
		t.Errorf("escaped %q, want %q", rows[0].LineEscaped, want)
	}
}
