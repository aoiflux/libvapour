package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

const fxOptionalOffset = uint64(fxLfanew) + 4 + FileHeaderSize

func fxSectionHeader(i int, plus bool) uint64 {
	size := uint64(fxOptSize32)
	if plus {
		size = uint64(fxOptSize64)
	}
	return fxOptionalOffset + size + uint64(i)*SectionHeaderSize
}

func fxDirectory(img []byte, plus bool, index int, rva, size uint32) {
	at := fxOptionalOffset + offOptDataDirectory32
	if plus {
		at = fxOptionalOffset + offOptDataDirectory64
	}
	at += uint64(index) * dataDirectoryEntrySize
	binary.LittleEndian.PutUint32(img[at:], rva)
	binary.LittleEndian.PutUint32(img[at+4:], size)
}

func mustRebuild(t *testing.T, img []byte, base uint64) Rebuilt {
	t.Helper()
	out, err := Rebuild(img, base, limits.Limits{})
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	return out
}

func TestRebuiltFileParsesAndEachSectionSitsAtItsRVA(t *testing.T) {
	for _, plus := range []bool{true, false} {
		img := buildImage(plus, 0x10000)
		base := uint64(0x7FF612340000)
		if !plus {
			base = 0x00450000
		}
		out := mustRebuild(t, img, base)
		f, err := pe.NewFile(bytes.NewReader(out.File))
		if err != nil {
			t.Fatalf("plus %v: debug/pe: %v", plus, err)
		}
		if len(f.Sections) != len(fxSections) || len(out.Sections) != len(fxSections) {
			t.Fatalf("plus %v: %d sections parsed, %d placed", plus, len(f.Sections), len(out.Sections))
		}
		for i, s := range f.Sections {
			want := fxSections[i]
			if s.Offset != want.va || s.Size != fxSectAlignment {
				t.Errorf("%s: raw 0x%x+0x%x, want 0x%x+0x%x", s.Name, s.Offset, s.Size, want.va, fxSectAlignment)
			}
			if s.VirtualSize != want.virtualSize {
				t.Errorf("%s: VirtualSize changed to 0x%x", s.Name, s.VirtualSize)
			}
			data, err := s.Data()
			if err != nil || !bytes.Equal(data, img[want.va:want.va+fxSectAlignment]) {
				t.Errorf("%s: data differs from memory at its RVA (%v)", s.Name, err)
			}
		}
		var got uint64
		switch oh := f.OptionalHeader.(type) {
		case *pe.OptionalHeader64:
			got = oh.ImageBase
		case *pe.OptionalHeader32:
			got = uint64(oh.ImageBase)
		}
		if got != base || !out.ImageBaseSet || out.OriginalImageBase != 0x10000 {
			t.Errorf("plus %v: ImageBase 0x%x set %v original 0x%x", plus, got, out.ImageBaseSet, out.OriginalImageBase)
		}
		if !out.SizeOfImageAligned || out.FileAlignmentSet || out.SizeOfHeadersSet {
			t.Errorf("plus %v: flags %+v on a well-formed image", plus, out)
		}
	}
}

func TestRebuildChangesNoByteOutsideTheFieldsItRewrites(t *testing.T) {
	img := buildImage(true, 0x10000)
	out := mustRebuild(t, img, 0x7FF600000000)
	changed := map[uint64]bool{}
	for i := uint64(0); i < 8; i++ {
		changed[fxOptionalOffset+offOptImageBase64+i] = true
	}
	for i := uint64(0); i < 4; i++ {
		changed[fxOptionalOffset+offOptCheckSum+i] = true
	}
	for i := range fxSections {
		for j := uint64(16); j < 24; j++ {
			changed[fxSectionHeader(i, true)+j] = true
		}
	}
	for i := range img {
		if !changed[uint64(i)] && img[i] != out.File[i] {
			t.Fatalf("byte 0x%x changed from 0x%02x to 0x%02x", i, img[i], out.File[i])
		}
	}
}

func TestTheCheckSumIsZeroedBecauseTheFileIsNotTheLinkersFile(t *testing.T) {
	for _, plus := range []bool{true, false} {
		img := buildImage(plus, 0x10000)
		out := mustRebuild(t, img, 0x10000)
		h, err := ParseHeaders(out.File)
		if err != nil {
			t.Fatal(err)
		}
		if h.Optional.CheckSum != 0 || !out.CheckSumCleared {
			t.Errorf("plus %v: CheckSum 0x%x cleared %v", plus, h.Optional.CheckSum, out.CheckSumCleared)
		}
		again := mustRebuild(t, out.File, 0x10000)
		if again.CheckSumCleared {
			t.Errorf("plus %v: a zero CheckSum reported as cleared", plus)
		}
	}
}

func TestA32BitImageAboveFourGigabytesKeepsItsImageBase(t *testing.T) {
	img := buildImage(false, 0x400000)
	out := mustRebuild(t, img, 0x100000000)
	if out.ImageBaseSet || binary.LittleEndian.Uint32(out.File[fxOptionalOffset+offOptImageBase32:]) != 0x400000 {
		t.Fatalf("ImageBase set %v", out.ImageBaseSet)
	}
}

func TestSectionsPastSizeOfImageAreEmptyOrCut(t *testing.T) {
	img := buildImage(true, 0x10000)
	binary.LittleEndian.PutUint32(img[fxSectionHeader(1, true)+offSectVirtualSize:], 0x3000)
	binary.LittleEndian.PutUint32(img[fxSectionHeader(2, true)+offSectVirtualAddress:], 0x5000)
	out := mustRebuild(t, img, 0x10000)
	if len(out.Clipped) != 1 || out.Clipped[0] != ".data" || len(out.Empty) != 1 || out.Empty[0] != ".rdata" {
		t.Fatalf("clipped %v empty %v", out.Clipped, out.Empty)
	}
	data := fxSectionHeader(1, true)
	if raw := binary.LittleEndian.Uint32(out.File[data+offSectSizeOfRawData:]); raw != 0x2000 {
		t.Errorf(".data raw size 0x%x, want the 0x2000 left in the image", raw)
	}
	rdata := fxSectionHeader(2, true)
	if binary.LittleEndian.Uint32(out.File[rdata+offSectSizeOfRawData:]) != 0 ||
		binary.LittleEndian.Uint32(out.File[rdata+offSectPointerToRawData:]) != 0 {
		t.Error(".rdata keeps raw data outside the file")
	}
	if _, err := pe.NewFile(bytes.NewReader(out.File)); err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
}

func TestAZeroVirtualSizeTakesTheRawSize(t *testing.T) {
	img := buildImage(true, 0x10000)
	at := fxSectionHeader(0, true)
	binary.LittleEndian.PutUint32(img[at+offSectVirtualSize:], 0)
	binary.LittleEndian.PutUint32(img[at+offSectSizeOfRawData:], 0x200)
	out := mustRebuild(t, img, 0x10000)
	if raw := binary.LittleEndian.Uint32(out.File[at+offSectSizeOfRawData:]); raw != fxSectAlignment {
		t.Fatalf("raw size 0x%x, want 0x%x", raw, fxSectAlignment)
	}
}

func TestAnUnusableFileAlignmentBecomesTheSectionAlignment(t *testing.T) {
	for _, fa := range []uint32{0, 0x300, 0x2000} {
		img := buildImage(true, 0x10000)
		binary.LittleEndian.PutUint32(img[fxOptionalOffset+offOptFileAlignment:], fa)
		out := mustRebuild(t, img, 0x10000)
		got := binary.LittleEndian.Uint32(out.File[fxOptionalOffset+offOptFileAlignment:])
		if !out.FileAlignmentSet || got != fxSectAlignment {
			t.Errorf("FileAlignment 0x%x: now 0x%x, set %v", fa, got, out.FileAlignmentSet)
		}
	}
}

func TestSizeOfHeadersEndsAtTheFirstSection(t *testing.T) {
	img := buildImage(true, 0x10000)
	binary.LittleEndian.PutUint32(img[fxOptionalOffset+offOptSizeOfHeaders:], 0x1800)
	out := mustRebuild(t, img, 0x10000)
	if got := binary.LittleEndian.Uint32(out.File[fxOptionalOffset+offOptSizeOfHeaders:]); got != 0x1000 || !out.SizeOfHeadersSet {
		t.Fatalf("SizeOfHeaders 0x%x set %v", got, out.SizeOfHeadersSet)
	}
}

func TestTheCertificateEntryAndCOFFSymbolsAreCleared(t *testing.T) {
	img := buildImage(true, 0x10000)
	fxDirectory(img, true, DirectoryEntryCertificate, 0x5000, 0x800)
	binary.LittleEndian.PutUint32(img[uint64(fxLfanew)+4+offFilePointerToSymbolTable:], 0x6000)
	binary.LittleEndian.PutUint32(img[uint64(fxLfanew)+4+offFileNumberOfSymbols:], 4)
	out := mustRebuild(t, img, 0x10000)
	h, err := ParseHeaders(out.File)
	if err != nil {
		t.Fatal(err)
	}
	if dir, _ := h.DataDirectory(out.File, DirectoryEntryCertificate); dir != (DataDirectory{}) || !out.CertificateCleared {
		t.Errorf("certificate entry %+v cleared %v", dir, out.CertificateCleared)
	}
	if binary.LittleEndian.Uint64(out.File[uint64(fxLfanew)+4+offFilePointerToSymbolTable:]) != 0 || !out.SymbolTableCleared {
		t.Error("COFF symbol table pointer kept")
	}
}

func TestDebugEntriesPointAtTheirRVA(t *testing.T) {
	img := buildImage(true, 0x10000)
	const dir = 0x3000
	fxDirectory(img, true, DirectoryEntryDebug, dir, 3*debugDirectoryEntrySize)
	entries := []struct{ rva, size, pointer, want uint32 }{
		{0x3100, 0x40, 0x1A00, 0x3100},
		{0, 0x40, 0x1C00, 0},
		{0x3200, 0x20, 0x3200, 0x3200},
	}
	for i, e := range entries {
		at := dir + i*debugDirectoryEntrySize
		binary.LittleEndian.PutUint32(img[at+debugEntrySizeOffset:], e.size)
		binary.LittleEndian.PutUint32(img[at+debugEntryRVAOffset:], e.rva)
		binary.LittleEndian.PutUint32(img[at+debugEntryFileOffset:], e.pointer)
	}
	out := mustRebuild(t, img, 0x10000)
	for i, e := range entries {
		at := dir + i*debugDirectoryEntrySize
		if got := binary.LittleEndian.Uint32(out.File[at+debugEntryFileOffset:]); got != e.want {
			t.Errorf("entry %d: PointerToRawData 0x%x, want 0x%x", i, got, e.want)
		}
	}
	if out.DebugRepointed != 1 || out.DebugUnmapped != 1 {
		t.Errorf("repointed %d unmapped %d", out.DebugRepointed, out.DebugUnmapped)
	}
}

func TestRebuildRefusesBuffersItCannotDescribe(t *testing.T) {
	img := buildImage(true, 0x10000)
	if _, err := Rebuild(img[:0x3000], 0, limits.Limits{}); !errors.Is(err, ErrRebuildSize) {
		t.Errorf("short buffer: %v", err)
	}
	if _, err := Rebuild(img, 0, limits.Limits{MaxArtifactBytes: 0x1000}); !errors.Is(err, ErrRebuildTooLarge) {
		t.Errorf("over the cap: %v", err)
	}
	for _, sa := range []uint32{0, 0x1800} {
		bad := buildImage(true, 0x10000)
		binary.LittleEndian.PutUint32(bad[fxOptionalOffset+offOptSectionAlignment:], sa)
		if _, err := Rebuild(bad, 0, limits.Limits{}); !errors.Is(err, ErrBadAlignment) {
			t.Errorf("SectionAlignment 0x%x: %v", sa, err)
		}
	}
	short := buildImage(true, 0x10000)
	binary.LittleEndian.PutUint16(short[uint64(fxLfanew)+4+offFileSizeOfOptionalHeader:], 0x80)
	if _, err := Rebuild(short, 0, limits.Limits{}); !errors.Is(err, ErrRebuildHeaders) {
		t.Errorf("SizeOfOptionalHeader 0x80 with 16 directories: %v", err)
	}
	unaligned := append(buildImage(true, 0x10000), make([]byte, 0x200)...)
	binary.LittleEndian.PutUint32(unaligned[fxOptionalOffset+offOptSizeOfImage:], uint32(len(unaligned)))
	if out := mustRebuild(t, unaligned, 0); out.SizeOfImageAligned {
		t.Error("SizeOfImage 0x4200 reported as a multiple of 0x1000")
	}
}
