package pe

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

var fuzzLimits = limits.Limits{MaxTableEntries: 1 << 12, MaxNameBytes: 256, MaxTextBytes: 1 << 16, MaxBufferBytes: 1 << 16}

func FuzzParseHeaders(f *testing.F) {
	f.Add(buildImage(true, 0x140000000))
	f.Add(buildImage(false, 0x400000)[:0x200])
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHeaders(b)
		var short *TruncatedError
		if errors.As(err, &short) {
			if short.Need <= short.Have || short.Have != uint64(len(b)) {
				t.Fatalf("need %d with %d bytes", short.Need, short.Have)
			}
			return
		}
		if err != nil {
			return
		}
		if h.HeaderSpan() > uint64(len(b)) || len(h.Sections) != int(h.File.NumberOfSections) {
			t.Fatalf("span %d of %d bytes, %d sections", h.HeaderSpan(), len(b), len(h.Sections))
		}
		for _, s := range h.Sections {
			if len(s.Name) > sectionNameSize || strings.IndexByte(s.Name, 0) >= 0 {
				t.Fatalf("section name %q", s.Name)
			}
		}
		for i := range 16 {
			dir, err := h.DataDirectory(b, i)
			if err != nil {
				continue
			}
			read, err := h.ReadDataDirectory(flat(b), i)
			if err != nil || read != dir {
				t.Fatalf("directory %d: %+v from the buffer, %+v %v through ReadRVA", i, dir, read, err)
			}
		}
	})
}

func FuzzParseExports(f *testing.F) {
	ex := buildExportsAt(0x20, 0x100, 0x180, 1, []exSlot{{0x2000, []string{"A", "B"}}, {0, nil}, {0x2010, nil}}, map[int]string{1: "X.Y"})
	f.Add(ex.img, ex.dir.VirtualAddress, ex.dir.Size)
	f.Fuzz(func(t *testing.T, b []byte, rva, size uint32) {
		exports, err := ParseExports(flat(b), DataDirectory{rva, size}, fuzzLimits)
		if err != nil {
			return
		}
		for _, e := range exports {
			if strings.IndexByte(e.Name, 0) >= 0 || int64(len(e.Name)) > fuzzLimits.MaxNameBytes || e.NameUnreadable && e.Name != "" {
				t.Fatalf("name %q unreadable %v", e.Name, e.NameUnreadable)
			}
			inside := uint64(e.RVA) >= uint64(rva) && uint64(e.RVA) < uint64(rva)+uint64(size)
			if e.forwarded() != inside {
				t.Fatalf("RVA 0x%x, directory 0x%x+0x%x, forwarder %q unreadable %v", e.RVA, rva, size, e.Forwarder, e.ForwarderUnreadable)
			}
			base := uint64(binary.LittleEndian.Uint32(b[rva+offExportOrdinalBase:]))
			count := uint64(binary.LittleEndian.Uint32(b[rva+offExportAddressEntries:]))
			if uint64(e.Ordinal) < base || uint64(e.Ordinal) >= base+count {
				t.Fatalf("ordinal %d outside %d+%d", e.Ordinal, base, count)
			}
		}
	})
}

func FuzzParseImports(f *testing.F) {
	small := imLayout{dir: 0x10, lookup: 0x40, iat: 0x60, strs: 0x80, size: 0xC0}
	f.Add(buildImportsAt(small, true, []imLibrary{{name: "a.dll", entries: []imEntry{{name: "F"}, {ordinal: 3}}}}), true, uint32(small.dir), uint32(40))
	f.Add(buildImportsAt(small, false, []imLibrary{{name: "b.dll", noOFT: true, entries: []imEntry{{ordinal: 1}}}}), false, uint32(small.dir), uint32(40))
	f.Fuzz(func(t *testing.T, b []byte, plus bool, rva, size uint32) {
		table, err := ParseImports(flat(b), plus, DataDirectory{rva, size}, fuzzLimits)
		if err != nil {
			return
		}
		if len(table.Descriptors) > fuzzLimits.MaxTableEntries || uint64(len(table.Descriptors)) > uint64(size)/ImportDescriptorSize {
			t.Fatalf("%d descriptors", len(table.Descriptors))
		}
		width := uint32(4)
		if plus {
			width = 8
		}
		for _, d := range table.Descriptors {
			for i, imp := range d.Imports {
				if imp.SlotRVA != d.FirstThunk+uint32(i)*width {
					t.Fatalf("slot 0x%x for entry %d of 0x%x", imp.SlotRVA, i, d.FirstThunk)
				}
				if imp.ByOrdinal && (imp.Name != "" || imp.NameErr != nil) {
					t.Fatalf("ordinal import with a name: %+v", imp)
				}
			}
		}
	})
}

func FuzzReadCodeView(f *testing.F) {
	img := make([]byte, 0x1800)
	dbEntry(img, 0, DebugTypeCodeView, dbRecord(img, 0x1200, codeViewMagic, `x\k.pdb`, 2), 0x1200)
	f.Add(img, dbDir, uint32(debugDirectoryEntrySize))
	f.Fuzz(func(t *testing.T, b []byte, rva, size uint32) {
		cv, err := ReadCodeView(flat(b), DataDirectory{rva, size})
		if err != nil {
			return
		}
		if cv.PDBPath == "" || strings.IndexByte(cv.PDBPath, 0) >= 0 || int64(len(cv.PDBPath)) > limits.DefaultMaxNameBytes {
			t.Fatalf("path %q", cv.PDBPath)
		}
		if cv.RVA == 0 || string(b[cv.RVA:cv.RVA+4]) != codeViewMagic {
			t.Fatalf("record at 0x%x", cv.RVA)
		}
	})
}

func FuzzReadVersion(f *testing.F) {
	img, _ := buildResources()
	copy(img[0x3400:], versionInfo(0x3400, vsFixed))
	f.Add(img[:0x3600], rsDir, uint32(0x1000))
	f.Fuzz(func(t *testing.T, b []byte, rva, size uint32) {
		leaves, err := FindResources(flat(b), DataDirectory{rva, size}, RTVersion, fuzzLimits)
		if err == nil && len(leaves) == 0 {
			t.Fatal("no leaves and no error")
		}
		info, err := ReadVersion(flat(b), DataDirectory{rva, size}, fuzzLimits)
		if err == nil && info.Signature != FixedFileInfoSignature {
			t.Fatalf("signature 0x%x", info.Signature)
		}
	})
}

func FuzzParseVersionInfo(f *testing.F) {
	f.Add(versionInfo(0x3000, vsFixed), uint32(0x3000))
	f.Add(versionInfo(0x3002, vsFixed), uint32(0x3002))
	f.Fuzz(func(t *testing.T, b []byte, rva uint32) {
		info, err := ParseVersionInfo(b, rva)
		if err != nil {
			return
		}
		value := valueOffset(rva)
		if (uint32(value)+rva)%4 != 0 || info.Signature != FixedFileInfoSignature || value+FixedFileInfoSize > len(b) {
			t.Fatalf("value at %d, rva 0x%x, signature 0x%x", value, rva, info.Signature)
		}
	})
}
