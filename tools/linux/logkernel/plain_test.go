package logkernel

import (
	"errors"
	"strings"
	"testing"

	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const (
	logEndSym = 0xffffffff83000060
	plainAt   = 0xffffffff86000000
)

type plainFix struct {
	types *Types
	mem   *Memory
	size  uint64
	end   uint64
	opts  map[string]any
}

func newPlain(size uint64) *plainFix {
	f := &plainFix{types: NewTypes(8), mem: NewMemory(), size: size}
	f.types.Symbol("log_buf", logBufSym, Ptr(Base("char")))
	f.types.Symbol("log_buf_len", logBufLenSym, Base("int"))
	f.types.Symbol("log_end", logEndSym, Base("unsigned int"))
	f.mem.Map(plainAt, size)
	return f
}

// emit writes characters as emit_log_char does: at log_end masked by the
// length, which is a power of two.
func (f *plainFix) emit(s string) {
	for i := 0; i < len(s); i++ {
		f.mem.U8(plainAt+f.end&(f.size-1), s[i])
		f.end++
	}
}

func (f *plainFix) run(t *testing.T) ([]Row, []string, error) {
	t.Helper()
	f.mem.U64(logBufSym, plainAt)
	f.mem.U32(logBufLenSym, uint32(f.size))
	f.mem.U32(logEndSym, uint32(f.end))
	ctx, diags := Context(f.mem, f.types.Table(t), f.opts)
	rows, err := Run(ctx)
	return rows, *diags, err
}

func TestTheCharacterRingGivesItsPrefixesAndTimes(t *testing.T) {
	f := newPlain(256)
	f.emit("<5>[    0.000000] Linux version 3.4.0\n<4>[ 1234.500001] warm\n<14>from user space\n<6>[    2.0] odd time\n<3>still being written")
	rows, diags, err := f.run(t)
	if err != nil || len(diags) != 0 {
		t.Fatalf("%v %q", err, diags)
	}
	want := []Row{
		{HasTimestamp: true, Facility: "kern", HasFacility: true, Level: LevelNotice, Final: true, Line: "Linux version 3.4.0", LineEscaped: "Linux version 3.4.0"},
		{TimestampNsec: 1234_500_001_000, HasTimestamp: true, Facility: "kern", HasFacility: true, Level: LevelWarning, Final: true, Line: "warm", LineEscaped: "warm"},
		{Facility: "user", FacilityNumber: 1, HasFacility: true, Level: LevelInfo, Final: true, Line: "from user space", LineEscaped: "from user space"},
		{Facility: "kern", HasFacility: true, Level: LevelInfo, Final: true, Line: "[    2.0] odd time", LineEscaped: "[    2.0] odd time"},
		{Facility: "kern", HasFacility: true, Level: LevelErr, Line: "still being written", LineEscaped: "still being written"},
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

func TestAFullCharacterRingStartsAtTheOldestCharacter(t *testing.T) {
	f := newPlain(64)
	f.emit("<6>first line that will be cut by the wrap\n")
	f.emit("<6>second, long enough to wrap\n<6>third\n")
	rows, _, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	got := lines(rows)
	if !strings.HasSuffix(got, "|second, long enough to wrap|third") || strings.HasPrefix(got, "first") {
		t.Errorf("lines %q", got)
	}
	if rows[0].Level != "" || rows[0].HasFacility {
		t.Errorf("the cut first line has no prefix: %s", describe(rows[0]))
	}
}

func TestAnUnreadablePageSplitsTheCharacterRing(t *testing.T) {
	f := newPlain(2 * pageSize)
	f.emit("<6>one\n" + strings.Repeat("x", pageSize) + "\n<6>two\n")
	f.mem.Unmap(plainAt + pageSize)
	rows, diags, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 || rows[0].Line != "one" || len(diags) != 1 || !strings.Contains(diags[0], "log_buf at 0xffff86000000") {
		t.Errorf("rows %d, diags %q", len(rows), diags)
	}
	f.opts = map[string]any{"strict": true}
	if _, _, err := f.run(t); err == nil {
		t.Error("strict mode: missing bytes are an error")
	}
}

func TestACharacterRingHeaderOutOfRangeIsRefused(t *testing.T) {
	f := newPlain(96)
	if _, _, err := f.run(t); !errors.Is(err, ErrHeader) {
		t.Errorf("a length that is not a power of two: %v", err)
	}
	f = newPlain(1 << 30)
	if _, _, err := f.run(t); !errors.Is(err, ErrLimit) {
		t.Errorf("a ring over MaxBufferBytes: %v", err)
	}
}

func TestPlainPrefixesThatDoNotParseKeepTheWholeLine(t *testing.T) {
	for _, line := range []string{"<x>text", "<>text", "<6", "no prefix", "<99999999999999999999999>overflow"} {
		r := plainLine([]byte(line))
		if r.hasLevel || r.hasTs || string(r.text) != line {
			t.Errorf("%q: %+v", line, r)
		}
	}
}
