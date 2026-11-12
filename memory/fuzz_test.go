package memory

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

func fuzzLimits() limits.Limits {
	l := limits.Default()
	l.MaxTableEntries, l.MaxListEntries, l.MaxBufferBytes = 64, 64, 1<<16
	return l
}

// Whatever a parser accepts must serve each segment's file bytes at its
// physical address and refuse the address after a segment that a hole
// follows.
func checkServes(t *testing.T, file image, r *SegmentedReader) {
	t.Helper()
	segs := r.Segments()
	for i, s := range segs {
		n := min(s.Length, 64)
		got, err := r.ReadAt(s.PhysicalBase, n)
		if err != nil || !bytes.Equal(got, file[s.FileOffset:s.FileOffset+n]) {
			t.Fatalf("segment %+v: %v", s, err)
		}
		if i > 0 && segs[i-1].PhysicalBase+segs[i-1].Length > s.PhysicalBase {
			t.Fatalf("segments overlap: %+v %+v", segs[i-1], s)
		}
	}
}

func FuzzCrashDump(f *testing.F) {
	f.Add([]byte(crashFile([]run{{1, 2}, {8, 1}}, nil)))
	f.Add([]byte(crashFile(manyRuns(crashOverwrittenRun+2), overwriteSlot(7))))
	f.Add([]byte("PAGEDU64"))
	f.Fuzz(func(t *testing.T, data []byte) {
		file := image(data)
		r, ok, err := crashDumpDetector{}.Detect(file)
		if err != nil || !ok {
			return
		}
		c := r.(*CrashDumpReader)
		h := c.CrashHeader()
		var pages uint64
		for _, s := range c.Segments() {
			pages += s.Length / crashPageBytes
		}
		if pages != h.NumberOfPages || h.NumberOfRuns == 0 || h.NumberOfRuns > crashMaxRuns {
			t.Fatalf("pages 0x%x header 0x%x runs %d", pages, h.NumberOfPages, h.NumberOfRuns)
		}
		checkServes(t, file, c.SegmentedReader)
	})
}

func FuzzLime(f *testing.F) {
	f.Add([]byte(limeFile([]limeRange{{0x1000, pattern(32, 1)}, {0x3000, pattern(8, 2)}})))
	f.Add(append([]byte(limeFile([]limeRange{{0, []byte{1}}})), 0, 0, 0))
	f.Fuzz(func(t *testing.T, data []byte) {
		file := image(data)
		r, ok, err := limeDetector{fuzzLimits()}.Detect(file)
		if err != nil || !ok {
			return
		}
		checkServes(t, file, r.(*SegmentedReader))
	})
}

func FuzzELFCore(f *testing.F) {
	f.Add([]byte(elfSpec{wide: true, notes: []elfNoteSpec{prstatusNote, vmcoreNote}, loads: []elfLoadSpec{{phys: 0x1000, data: pattern(64, 1)}}}.build()))
	f.Add([]byte(elfSpec{big: true, notes: []elfNoteSpec{{noteOwnerCore, noteAuxv, []byte{1}}}, loads: []elfLoadSpec{{phys: 0, data: pattern(8, 1)}}}.build()))
	f.Add([]byte(elfSpec{wide: true, extendedPh: true, loads: []elfLoadSpec{{phys: 0x2000, data: pattern(8, 1)}, {phys: 0x2000, data: pattern(4, 1)}}}.build()))
	f.Fuzz(func(t *testing.T, data []byte) {
		file := image(data)
		r, ok, err := elfCoreDetector{fuzzLimits()}.Detect(file)
		if err != nil || !ok {
			return
		}
		checkServes(t, file, r.(*SegmentedReader))
	})
}

func FuzzSegmentedRead(f *testing.F) {
	f.Add([]byte{0, 0x10, 0, 0x10, 0x20, 0x08, 0x10, 0x08}, uint64(0x18), uint64(0x10))
	f.Fuzz(func(t *testing.T, table []byte, offset, size uint64) {
		file := image(pattern(256, 5))
		var segs []Segment
		for i := 0; i+4 <= len(table) && len(segs) < 16; i += 4 {
			segs = append(segs, Segment{PhysicalBase: uint64(binary.LittleEndian.Uint16(table[i:])), FileOffset: uint64(table[i+2]), Length: uint64(table[i+3])})
		}
		r, err := NewSegmentedReader(file, segs)
		if err != nil {
			return
		}
		size %= 1 << 12
		got, err := r.ReadAt(offset, size)
		if err != nil {
			return
		}
		if uint64(len(got)) != size {
			t.Fatalf("0x%x bytes for a read of 0x%x", len(got), size)
		}
		for i := uint64(0); i < size; i++ {
			at := offset + i
			for _, s := range r.Segments() {
				if at >= s.PhysicalBase && at < s.PhysicalBase+s.Length && got[i] != file[s.FileOffset+at-s.PhysicalBase] {
					t.Fatalf("byte at physical 0x%x", at)
				}
			}
		}
	})
}

func FuzzScanWindows(f *testing.F) {
	f.Add(uint64(16), uint64(3), uint16(100))
	f.Fuzz(func(t *testing.T, step, overlap uint64, n uint16) {
		step = step%512 + 1
		overlap %= 512
		data := image(pattern(int(n), 2))
		owned := make([]int, n)
		ScanWindows(data, step, overlap, func(base uint64, w []byte) bool {
			if uint64(len(w)) > step+overlap || !bytes.Equal(w, data[base:base+uint64(len(w))]) {
				t.Fatalf("window at 0x%x of %d bytes", base, len(w))
			}
			for i := uint64(0); i < min(step, uint64(len(w))); i++ {
				owned[base+i]++
			}
			return false
		})
		for i, c := range owned {
			if c != 1 {
				t.Fatalf("offset %d owned %d times", i, c)
			}
		}
	})
}

// A claimed file must carry a valid RFC 1950 header; nothing is ever served.
func FuzzZlibDetect(f *testing.F) {
	f.Add([]byte{0x78, 0x9c, 0x63, 0x60, 0x18, 0x05, 0x00, 0x00})
	f.Add([]byte{0x78, 0x01, 0x01, 0x04, 0x00, 0xfb, 0xff, 1, 2, 3, 4})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, ok, err := zlibDetector{}.Detect(image(data))
		if r != nil || ok != (err != nil) {
			t.Fatalf("reader %v claimed %v err %v", r, ok, err)
		}
		if ok && (data[0]&0x0f != 8 || data[0]>>4 > 7 || (uint16(data[0])<<8|uint16(data[1]))%31 != 0 || data[1]&0x20 != 0) {
			t.Fatalf("claimed % x without a valid header", data[:2])
		}
	})
}
