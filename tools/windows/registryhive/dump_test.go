package registryhive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aoiflux/libvapour/tools"
)

func TestAHiveFileIsTheBaseBlockAndTheStableStorage(t *testing.T) {
	img, sys, _ := twoHiveImage()
	dir := t.TempDir()
	rows, err := RunDump(img.context(map[string]any{tools.OptionOutputDir: dir}))
	if err != nil || len(rows) != 2 {
		t.Fatalf("%d rows %v", len(rows), err)
	}
	r := rows[0]
	if r.Skipped != "" || r.Size != 2*fxBlock || r.Captured != r.Size || len(r.Gaps) != 0 || r.BaseBlockUnreadable {
		t.Fatalf("row %+v", r)
	}
	got, err := os.ReadFile(filepath.Join(dir, r.FileName))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := img.mem.ReadAt(sys.base, fxBlock)
	if !bytes.Equal(got[:fxBlock], base) || !bytes.Equal(got[fxBlock:], sys.storage[0].data) {
		t.Error("file content differs from memory")
	}
}

func TestAMissingPageAndBaseBlockAreGapsInTheFile(t *testing.T) {
	img := newFxImage()
	h := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\X`})
	h.root = h.key(0, fxKey{name: "ROOT", flags: keyHiveRoot})
	h.cell(0, make([]byte, 2*fxBlock))
	h.commit()
	img.mem.drop(h.storage[0].bin + fxBlock)
	img.mem.drop(h.base)
	d := DumpHive(img.context(nil), Hive{Address: h.cmhive, FileFullPath: `\REGISTRY\MACHINE\X`}, nil, t.TempDir())
	if d.Skipped != "" || !d.BaseBlockUnreadable || d.Size != 4*fxBlock || d.Captured != 2*fxBlock {
		t.Fatalf("dump %+v", d)
	}
	if len(d.Gaps) != 2 || d.Gaps[0].Start != 0 || d.Gaps[1].Start != 2*fxBlock || d.Gaps[1].Length != fxBlock {
		t.Errorf("gaps %+v", d.Gaps)
	}
}

func TestAHiveOverTheDumpLimitIsRefusedWhole(t *testing.T) {
	img, sys, _ := twoHiveImage()
	dir := t.TempDir()
	ctx := img.context(map[string]any{tools.OptionMaxDumpSize: uint64(fxBlock)})
	d := DumpHive(ctx, Hive{Address: sys.cmhive, FileFullPath: "SYSTEM"}, nil, dir)
	if d.Skipped == "" {
		t.Fatal("not refused")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("%d files written", len(entries))
	}
}

func TestDumpingNeedsAnOutputDirectory(t *testing.T) {
	img, _, _ := twoHiveImage()
	if _, err := RunDump(img.context(nil)); !errors.Is(err, ErrNoOutputDir) {
		t.Errorf("%v", err)
	}
}

func TestReadStableReportsUnmappedBlocksAsGaps(t *testing.T) {
	img, sys, _ := twoHiveImage()
	l := sys.layer(t, img.context(nil))
	b, gaps := l.ReadStable(0, 2*fxBlock)
	if len(b) != 2*fxBlock || len(gaps) != 1 || gaps[0].Start != fxBlock {
		t.Errorf("gaps %+v", gaps)
	}
	if n, known := l.StableStoreLengthKnown(); !known || n != l.StableStoreLength() {
		t.Error("length")
	}
}

func TestAMapEntryNeedsOnlyItsBlockOffsetAndBinAddress(t *testing.T) {
	img, sys, _ := twoHiveImage()
	st := sys.storage[0]
	page := img.alloc(2 * fxBlock)
	table := page + fxBlock - fxEntryBin - 8
	img.mem.u64(table, 0)
	img.mem.u64(table+fxEntryBin, st.bin|fxBinFlags)
	img.mem.u64(st.mapD, table)
	img.mem.drop(page + fxBlock)
	d := DumpHive(img.context(nil), Hive{Address: sys.cmhive, FileFullPath: "SYSTEM"}, nil, t.TempDir())
	if d.Skipped != "" || len(d.Gaps) != 0 || d.Captured != d.Size || d.Size != 2*fxBlock {
		t.Fatalf("an entry whose MemAlloc is out of memory must still map its block: %+v", d)
	}
}
