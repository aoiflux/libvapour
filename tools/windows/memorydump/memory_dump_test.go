package memorydump

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

func s68Fixture() *testsupport.ProcessFixture {
	f := testsupport.BuildProcessFixture([]testsupport.FixtureProcess{
		{PID: 1200, Name: "one.exe", VADs: []testsupport.FixtureVAD{
			{Start: 0x10000, End: 0x11fff, Protection: 4},
			{Start: 0x7ff600000000, End: 0x7ff600000fff, Path: `\Windows\System32\one.exe`, Protection: 7, VadType: 2},
		}},
		{PID: 3000, Name: "two.exe", VADs: []testsupport.FixtureVAD{
			{Start: 0x20000, End: 0x20fff, Protection: 4},
			{Start: 0x50000, End: 0x50fff, Protection: 4},
		}},
	})
	f.Space(1200).MapData(0x10000, bytes.Repeat([]byte{0xA1}, 0x1000))
	f.Space(1200).MapData(0x7ff600000000, bytes.Repeat([]byte{0xB2}, 0x1000))
	f.Space(3000).MapData(0x20000, bytes.Repeat([]byte{0xC3}, 0x1000))
	return f
}

func runDump(t *testing.T, ctx tools.Context, opts map[string]any) ([]Artifact, []string, string, error) {
	t.Helper()
	dir := t.TempDir()
	var diags []string
	ctx.Options["diagnostics"] = &diags
	ctx.Options[tools.OptionOutputDir] = dir
	for k, v := range opts {
		ctx.Options[k] = v
	}
	rows, err := Run(ctx)
	return rows, diags, dir, err
}

func TestEachRangeIsWrittenWithItsUnreadPagesAsGaps(t *testing.T) {
	rows, _, dir, err := runDump(t, s68Fixture().Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows, want 4", len(rows))
	}
	first := rows[0]
	if first.PID != 1200 || first.Start != 0x10000 || first.End != 0x11fff || first.Size != 0x2000 || first.Captured != 0x1000 {
		t.Errorf("first row %+v", first)
	}
	if !first.Written() || first.Complete() || len(first.Gaps) != 1 || first.Gaps[0].Start != 0x11000 || first.Gaps[0].Length != 0x1000 {
		t.Errorf("first row gaps %+v, want the unmapped second page", first.Gaps)
	}
	data, err := os.ReadFile(filepath.Join(dir, first.FileName))
	if err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte{0xA1}, 0x1000), make([]byte, 0x1000)...)
	if !bytes.Equal(data, want) {
		t.Errorf("file holds %d bytes not equal to the range with a zeroed gap", len(data))
	}
	if !strings.HasPrefix(first.FileName, "region.pid1200.") || !strings.HasSuffix(first.FileName, ".bin") {
		t.Errorf("file name %q is not an S00 region name", first.FileName)
	}
	image := rows[1]
	if image.Type != "image" || image.Path != `\Windows\System32\one.exe` || !image.Complete() {
		t.Errorf("image row %+v", image)
	}
	if other := rows[2]; other.PID != 3000 || other.Captured != 0x1000 {
		t.Errorf("third row %+v: each range is read under its own process's root", other)
	} else if b, _ := os.ReadFile(filepath.Join(dir, other.FileName)); !bytes.Equal(b, bytes.Repeat([]byte{0xC3}, 0x1000)) {
		t.Errorf("pid 3000's file does not hold its own page")
	}
	if empty := rows[3]; empty.Written() || empty.Skipped != ErrNothingRead.Error() {
		t.Errorf("a range with no page in the capture: %+v", empty)
	} else if _, err := os.Stat(filepath.Join(dir, empty.FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a range with no page in the capture left a file: %v", err)
	}
}

func TestTheAddressAndPIDOptionsChooseRanges(t *testing.T) {
	rows, _, _, err := runDump(t, s68Fixture().Context(), map[string]any{OptionAddress: uint64(0x7ff600000800)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Start != 0x7ff600000000 {
		t.Errorf("address filter rows %+v", rows)
	}
	rows, _, _, err = runDump(t, s68Fixture().Context(), map[string]any{"pid": uint64(3000)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].PID != 3000 || rows[1].PID != 3000 {
		t.Errorf("pid rows %+v", rows)
	}
}

func TestARangeOverTheLimitIsListedNotWrittenEvenInStrictMode(t *testing.T) {
	rows, diags, dir, err := runDump(t, s68Fixture().Context(), map[string]any{tools.OptionMaxDumpSize: uint64(0x1000), "strict": true})
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Written() || !strings.Contains(rows[0].Skipped, ErrOverLimit.Error()) {
		t.Errorf("first row %+v, want it refused by the limit", rows[0])
	}
	if _, err := os.Stat(filepath.Join(dir, rows[0].FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused range left a file: %v", err)
	}
	if !rows[1].Written() || !rows[2].Written() {
		t.Errorf("ranges within the limit not written: %+v", rows[1:])
	}
	if !strings.Contains(strings.Join(diags, "\n"), "1 ranges of 8192 to 8192 bytes over the 4096-byte dump limit") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestAnExistingFileIsNeverReplaced(t *testing.T) {
	f := s68Fixture()
	ctx := f.Context()
	dir := t.TempDir()
	ctx.Options[tools.OptionOutputDir] = dir
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range again {
		if r.Written() || r.FileName != rows[i].FileName {
			t.Errorf("second run row %+v replaced or renamed the first run's file", r)
		}
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Errorf("strict second run: no error for a file that exists")
	}
}

func TestAProcessWithoutAnAddressSpaceKeepsItsRowsUnwritten(t *testing.T) {
	f := s68Fixture()
	ctx := f.Context()
	dtb := f.DirectoryTableBase(3000)
	inner := ctx.ProcessMemory
	ctx.ProcessMemory = func(d uint64) (memory.MemoryReader, error) {
		if d == dtb {
			return nil, errors.New("no layer")
		}
		return inner(d)
	}
	rows, diags, _, err := runDump(t, ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rows[2].Written() || !rows[0].Written() {
		t.Errorf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "pid 3000: user memory not read") {
		t.Errorf("diagnostics %q", diags)
	}
	ctx.Options["strict"] = true
	ctx.Options[tools.OptionOutputDir] = t.TempDir()
	if _, err := Run(ctx); !errors.Is(err, tools.ErrProcessSpaceUnavailable) {
		t.Errorf("strict: %v, want %v", err, tools.ErrProcessSpaceUnavailable)
	}
}

func TestAnOutputDirectoryIsRequired(t *testing.T) {
	if _, err := Run(s68Fixture().Context()); !errors.Is(err, ErrNoOutputDir) {
		t.Errorf("Run: %v, want %v", err, ErrNoOutputDir)
	}
}
