package imagestrings

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
)

func TestALineIsADecimalOffsetABlankAndTheString(t *testing.T) {
	cases := []struct {
		line, text, reason string
		offset             uint64
	}{
		{line: "4096 hello world", offset: 4096, text: "hello world"},
		{line: "   12\tcmd.exe /c", offset: 12, text: "cmd.exe /c"},
		{line: "7 trailing\r", offset: 7, text: "trailing"},
		{line: "0007  two blanks", offset: 7, text: " two blanks"},
		{line: "hello", reason: "no decimal offset"},
		{line: "12:text", reason: "no blank after the offset"},
		{line: "12 ", reason: "no string after the offset"},
		{line: "99999999999999999999 big", reason: "offset does not fit 64 bits"},
	}
	for _, c := range cases {
		off, text, reason := ParseLine([]byte(c.line))
		if reason != c.reason || (reason == "" && (off != c.offset || text != c.text)) {
			t.Errorf("%q: %d %q %q", c.line, off, text, reason)
		}
	}
	if _, text, _ := ParseLine([]byte{'1', ' ', 'a', 0xe9}); text != "aé" {
		t.Errorf("Latin-1 text decoded as %q", text)
	}
}

func TestReadLinesCountsRejectsAndStopsAtTheLimits(t *testing.T) {
	in := "1 a\n\nbad\n" + strings.Repeat("x", 40) + "\n2 b"
	lines, rejected, err := ReadLines(strings.NewReader(in), 16, 10)
	if err != nil || len(lines) != 2 || lines[1].Number != 5 || lines[1].Text != "b" {
		t.Fatalf("lines %+v, err %v", lines, err)
	}
	if len(rejected) != 2 || rejected[0].Number != 3 || rejected[1].Number != 4 || !strings.Contains(rejected[1].Reason, "longer than 16") {
		t.Errorf("rejected %+v", rejected)
	}
	if _, _, err := ReadLines(strings.NewReader("1 a\n2 b\n3 c\n"), 16, 2); !errors.Is(err, ErrTooManyLines) {
		t.Errorf("line limit: %v", err)
	}
}

const (
	sharedVA = uint64(0xfffff80000700000)
	userVA   = uint64(0x10000)
	otherVA  = uint64(0x7ff600000000)
)

type fixture struct {
	ctx    tools.Context
	shared uint64
	only   uint64
}

func newFixture(t *testing.T) fixture {
	f := testsupport.BuildProcessFixture([]testsupport.FixtureProcess{
		{PID: 4, Name: "first.exe", NoPeb: true},
		{PID: 8, Name: "second.exe", NoPeb: true},
	})
	shared := f.Kernel.MapPage(sharedVA)
	f.Space(4).Map(otherVA, shared)
	f.Space(8).Map(userVA, shared)
	only := f.Space(8).MapPage(userVA + 0x1000)
	f.Space(8).Map(sharedVA+0x1000, only)
	ctx := f.Context()
	ctx.Options[tools.OptionPhysicalMemory] = memory.MemoryReader(f.Memory)
	ctx.Options[tools.OptionKernelDTB] = f.Kernel.DTB
	ctx.Options[tools.OptionPagingMode] = "x64"
	return fixture{ctx: ctx, shared: shared, only: only}
}

func writeStrings(t *testing.T, ctx tools.Context, lines ...string) {
	path := filepath.Join(t.TempDir(), "strings.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx.Options[OptionFile] = path
}

func TestEachStringGetsEveryVirtualAddressOfItsPage(t *testing.T) {
	f := newFixture(t)
	var diags []string
	f.ctx.Options["diagnostics"] = &diags
	writeStrings(t, f.ctx, fmt.Sprintf("%d shared", f.shared+0x20), fmt.Sprintf("%d user only", f.only+0x8),
		fmt.Sprintf("%d nowhere", f.ctx.Memory.Size()+0x1000))
	rows, err := Run(f.ctx)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	want := []Mapping{
		{Kernel: true, Address: sharedVA + 0x20},
		{PID: 4, Process: "first.exe", Address: otherVA + 0x20},
		{PID: 8, Process: "second.exe", Address: userVA + 0x20},
	}
	if fmt.Sprint(rows[0].Mappings) != fmt.Sprint(want) {
		t.Errorf("shared page mappings %+v, want %+v", rows[0].Mappings, want)
	}
	if rows[0].Result != fmt.Sprintf("kernel 0x%x; pid 4 0x%x; pid 8 0x%x", sharedVA+0x20, otherVA+0x20, userVA+0x20) {
		t.Errorf("result %q", rows[0].Result)
	}
	only := rows[1].Mappings
	if len(only) != 1 || only[0].PID != 8 || only[0].Address != userVA+0x1008 {
		t.Errorf("a process's kernel-half mapping was listed or the user one lost: %+v", only)
	}
	if rows[2].InMemory || len(rows[2].Mappings) != 0 || rows[2].Result != "" {
		t.Errorf("offset past the image %+v", rows[2])
	}
	if !strings.Contains(strings.Join(diags, "\n"), "1 strings lie at file offsets that hold no physical memory") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestThePIDOptionNarrowsTheProcessesMapped(t *testing.T) {
	f := newFixture(t)
	f.ctx.Options["pid"] = uint64(8)
	writeStrings(t, f.ctx, fmt.Sprintf("%d shared", f.shared))
	rows, err := Run(f.ctx)
	if err != nil || len(rows) != 1 || len(rows[0].Mappings) != 2 || rows[0].Mappings[1].PID != 8 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
}

type segmented struct {
	memory.MemoryReader
	segs []memory.Segment
}

func (s segmented) Segments() []memory.Segment { return s.segs }

func TestASegmentedImageMapsFileOffsetsThroughItsSegments(t *testing.T) {
	f := newFixture(t)
	phys := f.ctx.Options[tools.OptionPhysicalMemory].(memory.MemoryReader)
	f.ctx.Options[tools.OptionPhysicalMemory] = memory.MemoryReader(segmented{phys,
		[]memory.Segment{{PhysicalBase: 0, FileOffset: 0x2000, Length: phys.Size()}}})
	writeStrings(t, f.ctx, fmt.Sprintf("%d shared", f.shared+0x2000), "16 in the header")
	rows, err := Run(f.ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	if rows[0].PhysicalAddress != f.shared || len(rows[0].Mappings) != 3 {
		t.Errorf("segmented offset: %+v", rows[0])
	}
	if rows[1].InMemory {
		t.Errorf("a header offset was taken as memory: %+v", rows[1])
	}
}

func TestRefusals(t *testing.T) {
	f := newFixture(t)
	if _, err := Run(f.ctx); !errors.Is(err, ErrNoFile) {
		t.Errorf("no file: %v", err)
	}
	writeStrings(t, f.ctx, "1 a")
	delete(f.ctx.Options, tools.OptionKernelDTB)
	if _, err := Run(f.ctx); !errors.Is(err, ErrNoKernelRoot) {
		t.Errorf("no kernel root: %v", err)
	}
	delete(f.ctx.Options, tools.OptionPhysicalMemory)
	if _, err := Run(f.ctx); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Errorf("no physical layer: %v", err)
	}
	f.ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(f.ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("linux: %v", err)
	}
}
