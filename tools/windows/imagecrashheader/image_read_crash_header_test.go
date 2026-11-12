package imagecrashheader

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

type flat []byte

func (f flat) ReadAt(off, n uint64) ([]byte, error) {
	if off+n > uint64(len(f)) {
		return nil, memory.ErrOutOfBounds
	}
	return f[off : off+n], nil
}

func (f flat) Size() uint64 { return uint64(len(f)) }

type dump struct {
	flat
	h memory.CrashDumpHeader
}

func (d dump) CrashHeader() memory.CrashDumpHeader { return d.h }

func context(phys memory.MemoryReader) (tools.Context, *[]string) {
	var diags []string
	return tools.Context{Memory: phys, Symbols: symbols.NewTable("s66", 8), Profile: profiles.WindowsX64Profile{},
		Options: map[string]any{tools.OptionPhysicalMemory: phys, "diagnostics": &diags}}, &diags
}

func header() memory.CrashDumpHeader {
	h := memory.CrashDumpHeader{
		MajorVersion: 15, MinorVersion: 26100, DirectoryTableBase: 0x1ad000, PfnDataBase: 0xffffb20000000000,
		PsLoadedModuleList: 0xfffff80000123450, PsActiveProcessHead: 0xfffff80000123460, MachineImageType: 0x8664,
		NumberProcessors: 4, BugCheckCode: 0xe2, KdDebuggerDataBlock: 0xfffff80000200000, NumberOfRuns: 3,
		NumberOfPages: 0x80000, DumpType: 1, DumpTypeIntact: true,
		SystemTime: 133000000000000000, SystemUpTime: 36_000_000_000,
	}
	copy(h.Comment[:], "manual dump\x00ignored")
	return h
}

func TestTheRowCarriesTheHeaderTheLayerParsed(t *testing.T) {
	ctx, _ := context(dump{flat: make(flat, 4096), h: header()})
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	r := rows[0]
	if r.Signature != "PAGE" || r.MajorVersion != 15 || r.MinorVersion != 26100 || r.DirectoryTableBase != 0x1ad000 ||
		r.MachineImageType != 0x8664 || r.NumberProcessors != 4 || r.BugCheckCode != 0xe2 || r.NumberOfRuns != 3 ||
		r.NumberOfPages != 0x80000 || r.KdDebuggerDataBlock != 0xfffff80000200000 {
		t.Errorf("row %+v", r)
	}
	if !r.DumpTypeKnown || r.DumpType != "full" || r.Comment != "manual dump" {
		t.Errorf("dump type %q known %v, comment %q", r.DumpType, r.DumpTypeKnown, r.Comment)
	}
	if !r.SystemUpTimeValid || r.SystemUpTime != time.Hour {
		t.Errorf("up time %v valid %v", r.SystemUpTime, r.SystemUpTimeValid)
	}
	want := time.Date(2022, 6, 18, 4, 26, 40, 0, time.UTC)
	if !r.SystemTimeValid || !r.SystemTime.Equal(want) {
		t.Errorf("system time %v valid %v, want %v", r.SystemTime, r.SystemTimeValid, want)
	}
}

func TestOverrunFieldsAreNotGiven(t *testing.T) {
	h := header()
	h.DumpTypeIntact, h.NumberOfRuns = false, 300
	ctx, diags := context(dump{flat: make(flat, 4096), h: h})
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	r := rows[0]
	if r.DumpTypeKnown || r.DumpType != "" || r.SystemTimeValid || r.SystemUpTimeValid || r.Comment != "" {
		t.Errorf("row %+v", r)
	}
	if r.PsActiveProcessHead != h.PsActiveProcessHead {
		t.Errorf("fields before the run array lost")
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "300 physical memory runs overrun DumpType") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestAnotherDumpTypeIsGivenByNumber(t *testing.T) {
	if got := dumpTypeName(5); got != "5" {
		t.Errorf("dump type 5 named %q", got)
	}
}

func TestACommentOfTheFillPatternIsNoComment(t *testing.T) {
	if got := commentText([]byte("PAGEPAGEPAGE")); got != "" {
		t.Errorf("fill pattern gave %q", got)
	}
	if got := commentText([]byte("PAGEPAGEPAG")); got != "PAGEPAGEPAG" {
		t.Errorf("text %q", got)
	}
}

func TestACommentThatIsNotUTF8IsReplaced(t *testing.T) {
	if got := commentText([]byte{'a', 0xff, 'b'}); got != "a�b" {
		t.Errorf("comment %q", got)
	}
}

func TestARawImageIsNoCrashDump(t *testing.T) {
	ctx, _ := context(make(flat, 4096))
	if _, err := Run(ctx); !errors.Is(err, ErrNotCrashDump) {
		t.Errorf("raw image: %v", err)
	}
}

func TestUpTimeIsTicksOf100Nanoseconds(t *testing.T) {
	if d, ok := UpTime(10); !ok || d != time.Microsecond {
		t.Errorf("10 ticks: %v %v", d, ok)
	}
	if _, ok := UpTime(1 << 63); ok {
		t.Error("an up time past time.Duration was accepted")
	}
}
