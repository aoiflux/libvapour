package memory

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func openCrash(t *testing.T, file image) *CrashDumpReader {
	t.Helper()
	r, ok, err := crashDumpDetector{}.Detect(file)
	if err != nil || !ok {
		t.Fatalf("detect: %v %v", ok, err)
	}
	return r.(*CrashDumpReader)
}

func pageByte(t *testing.T, r MemoryReader, page uint64) byte {
	t.Helper()
	b, err := r.ReadAt(page*crashPageBytes, crashPageBytes)
	if err != nil {
		t.Fatalf("page 0x%x: %v", page, err)
	}
	return b[crashPageBytes-1]
}

func TestRunsAppearAtTheirPagesInFileOrder(t *testing.T) {
	r := openCrash(t, crashFile([]run{{1, 2}, {0x10, 1}, {0x20, 3}}, nil))
	for _, p := range []uint64{1, 2, 0x10, 0x20, 0x22} {
		if got := pageByte(t, r, p); got != byte(p) {
			t.Errorf("page 0x%x holds the bytes of page 0x%x", p, got)
		}
	}
	for _, p := range []uint64{0, 3, 0x11, 0x1f} {
		if _, err := r.ReadAt(p*crashPageBytes, 1); !errors.Is(err, ErrUnmapped) {
			t.Errorf("page 0x%x: %v, want ErrUnmapped", p, err)
		}
	}
	if r.Size() != 0x23*crashPageBytes || len(MappedRanges(r)) != 3 || !IsImmutableSnapshot(r) {
		t.Errorf("size 0x%x ranges %v", r.Size(), MappedRanges(r))
	}
}

func TestTheHeaderFieldsAreReadAtTheirMeasuredOffsets(t *testing.T) {
	h := openCrash(t, crashFile([]run{{1, 2}, {5, 1}}, nil)).CrashHeader()
	if h.MajorVersion != 15 || h.MinorVersion != 26100 || h.DirectoryTableBase != 0x1ad000 || h.PfnDataBase != 0xffffa00000000000 ||
		h.PsLoadedModuleList != 0xfffff80000100000 || h.PsActiveProcessHead != 0xfffff80000100010 || h.MachineImageType != 0x8664 ||
		h.NumberProcessors != 2 || h.BugCheckCode != 0xe2 || h.KdDebuggerDataBlock != 0xfffff80000200000 || h.NumberOfRuns != 2 ||
		h.NumberOfPages != 3 {
		t.Errorf("header %+v", h)
	}
	if !h.DumpTypeIntact || h.DumpType != crashDumpTypeFull || h.SystemTime != 133000000000000000 || h.SystemUpTime != 36_000_000_000 ||
		!strings.HasPrefix(string(h.Comment[:]), "test dump\x00") || h.RepairedRun != -1 {
		t.Errorf("fields after the run array: %+v", h)
	}
}

func manyRuns(n int) []run {
	runs := make([]run, n)
	for i := range runs {
		runs[i] = run{uint64(2 * i), 1}
	}
	return runs
}

func TestARunArrayThatReachesDumpTypeHidesTheFieldsAfterIt(t *testing.T) {
	h := openCrash(t, crashFile(manyRuns(crashOverwrittenRun), nil)).CrashHeader()
	if !h.DumpTypeIntact {
		t.Error("240 runs end at DumpType and leave it intact")
	}
	runs := manyRuns(crashOverwrittenRun + 5)
	r := openCrash(t, crashFile(runs, nil))
	h = r.CrashHeader()
	if h.DumpTypeIntact || h.DumpType != 0 || h.SystemTime != 0 || h.SystemUpTime != 0 || h.Comment != [crashCommentLength]byte{} {
		t.Errorf("overrun fields given: %+v", h)
	}
	if h.RepairedRun != -1 || len(r.containerNotes()) != 0 {
		t.Errorf("consistent counts were repaired: %d", h.RepairedRun)
	}
}

func overwriteSlot(value uint64) func([]byte) {
	return func(h []byte) { binary.LittleEndian.PutUint64(h[crashRequiredAt:], value) }
}

func TestTheOverwrittenRunIsRecountedFromThePageTotal(t *testing.T) {
	runs := manyRuns(crashOverwrittenRun + 9)
	file := crashFile(runs, overwriteSlot(0x744f2000))
	r := openCrash(t, file)
	h := r.CrashHeader()
	if h.RepairedRun != crashOverwrittenRun || h.RepairedPageCount != 1 {
		t.Fatalf("repaired run %d count 0x%x", h.RepairedRun, h.RepairedPageCount)
	}
	last := uint64(2 * (crashOverwrittenRun + 8))
	if got := pageByte(t, r, last); got != byte(last) {
		t.Errorf("pages after the recounted run are misplaced: 0x%x", got)
	}
	if notes := r.containerNotes(); len(notes) != 1 || !strings.Contains(notes[0], "0x744f2000") {
		t.Errorf("notes %q", notes)
	}
}

func TestCrashDumpsWhoseRunsCannotBeTrustedAreRefused(t *testing.T) {
	le := binary.LittleEndian
	long := manyRuns(crashOverwrittenRun + 9)
	cases := map[string]image{
		"counts disagree, slot not overrun": crashFile([]run{{1, 2}, {5, 1}}, func(h []byte) { le.PutUint64(h[crashTotalAt:], 4) }),
		"two counts damaged": crashFile(long, func(h []byte) {
			overwriteSlot(9)(h)
			le.PutUint64(h[crashRunsAt+crashRunBytes*3+8:], 5)
		}),
		"recount would reach the next run": crashFile(long, func(h []byte) {
			overwriteSlot(9)(h)
			le.PutUint64(h[crashTotalAt:], uint64(len(long))+3)
		}),
		"descending":      crashFile([]run{{8, 1}, {2, 1}}, nil),
		"overlapping":     crashFile([]run{{2, 4}, {4, 1}}, nil),
		"no runs":         crashFile(nil, nil),
		"too many runs":   crashFile([]run{{1, 1}}, func(h []byte) { le.PutUint32(h[crashDescriptorAt:], crashMaxRuns+1) }),
		"not full":        crashFile([]run{{1, 1}}, func(h []byte) { le.PutUint32(h[crashDumpTypeAt:], 2) }),
		"page overflow":   crashFile([]run{{^uint64(0) / crashPageBytes, 1}}, nil),
		"header only":     crashFile([]run{{1, 1}}, nil)[:crashHeaderBytes],
		"short header":    crashFile([]run{{1, 1}}, nil)[:crashHeaderBytes-1],
		"32-bit":          crashFile([]run{{1, 1}}, func(h []byte) { copy(h[4:], crashKind32) }),
		"pages truncated": crashFile([]run{{1, 3}}, nil)[:crashHeaderBytes+2*crashPageBytes],
	}
	for name, file := range cases {
		_, ok, err := crashDumpDetector{}.Detect(file)
		if !ok || !errors.Is(err, ErrCrashDump) {
			t.Errorf("%s: claimed %v err %v", name, ok, err)
		}
	}
}

func TestOnlyThe64BitSignatureIsClaimed(t *testing.T) {
	for _, head := range []string{"PAGE", "PAGEDU6", "PAGEPAGE", "DU64PAGE"} {
		if _, ok, _ := (crashDumpDetector{}).Detect(image(head)); ok {
			t.Errorf("%q claimed", head)
		}
	}
}
