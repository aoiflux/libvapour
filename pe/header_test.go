package pe

import (
	"bytes"
	"debug/pe"
	"errors"
	"testing"
)

func TestHeadersMatchTheStandardLibraryReading(t *testing.T) {
	for _, plus := range []bool{false, true} {
		img := buildImage(plus, 0x140000000)
		h, err := ParseHeaders(img)
		if err != nil {
			t.Fatalf("plus %v: %v", plus, err)
		}
		f, err := pe.NewFile(bytes.NewReader(img))
		if err != nil {
			t.Fatalf("plus %v: debug/pe: %v", plus, err)
		}
		if h.File.Machine != f.Machine || h.File.NumberOfSections != f.NumberOfSections ||
			h.File.TimeDateStamp != f.TimeDateStamp || h.File.SizeOfOptionalHeader != f.SizeOfOptionalHeader ||
			h.File.Characteristics != f.Characteristics {
			t.Errorf("plus %v: file header %+v, debug/pe %+v", plus, h.File, f.FileHeader)
		}
		var want OptionalHeader
		switch o := f.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			want = OptionalHeader{Magic: o.Magic, AddressOfEntryPoint: o.AddressOfEntryPoint, ImageBase: uint64(o.ImageBase),
				SectionAlignment: o.SectionAlignment, FileAlignment: o.FileAlignment,
				MajorOperatingSystemVersion: o.MajorOperatingSystemVersion, MinorOperatingSystemVersion: o.MinorOperatingSystemVersion,
				SizeOfImage: o.SizeOfImage, SizeOfHeaders: o.SizeOfHeaders, CheckSum: o.CheckSum,
				ImageBaseOffset: uint64(fxLfanew) + 24 + offOptImageBase32, ImageBaseSize: 4}
		case *pe.OptionalHeader64:
			want = OptionalHeader{Magic: o.Magic, PE32Plus: true, AddressOfEntryPoint: o.AddressOfEntryPoint, ImageBase: o.ImageBase,
				SectionAlignment: o.SectionAlignment, FileAlignment: o.FileAlignment,
				MajorOperatingSystemVersion: o.MajorOperatingSystemVersion, MinorOperatingSystemVersion: o.MinorOperatingSystemVersion,
				SizeOfImage: o.SizeOfImage, SizeOfHeaders: o.SizeOfHeaders, CheckSum: o.CheckSum,
				ImageBaseOffset: uint64(fxLfanew) + 24 + offOptImageBase64, ImageBaseSize: 8}
		}
		if h.Optional != want {
			t.Errorf("plus %v: optional header\n got %+v\nwant %+v", plus, h.Optional, want)
		}
		if h.Optional.ImageBase != 0x140000000 && plus {
			t.Errorf("ImageBase 0x%x", h.Optional.ImageBase)
		}
		if len(h.Sections) != len(f.Sections) {
			t.Fatalf("plus %v: %d sections, debug/pe %d", plus, len(h.Sections), len(f.Sections))
		}
		for i, s := range f.Sections {
			got := h.Sections[i]
			if got.Name != s.Name || got.VirtualSize != s.VirtualSize || got.VirtualAddress != s.VirtualAddress ||
				got.SizeOfRawData != s.Size || got.PointerToRawData != s.Offset || got.Characteristics != s.Characteristics {
				t.Errorf("section %d: %+v, debug/pe %+v", i, got, s.SectionHeader)
			}
			if got.HeaderOffset != h.SectionTableOffset+uint64(i)*SectionHeaderSize {
				t.Errorf("section %d at 0x%x", i, got.HeaderOffset)
			}
		}
		if h.NTOffset != uint64(fxLfanew) || h.OptionalOffset != uint64(fxLfanew)+24 ||
			h.HeaderSpan() != h.SectionTableOffset+3*SectionHeaderSize {
			t.Errorf("offsets: NT 0x%x optional 0x%x span 0x%x", h.NTOffset, h.OptionalOffset, h.HeaderSpan())
		}
	}
}

func TestAShortBufferNamesTheLengthTheNextStageNeeds(t *testing.T) {
	img := buildImage(true, 0x10000)
	full, err := ParseHeaders(img)
	if err != nil {
		t.Fatal(err)
	}
	have, passes := uint64(2), 0
	for {
		h, err := ParseHeaders(img[:have])
		var short *TruncatedError
		if errors.As(err, &short) {
			if short.Need <= have || short.Have != have || short.Need > full.HeaderSpan() {
				t.Fatalf("buffer %d: need %d (%s)", have, short.Need, short.What)
			}
			have, passes = short.Need, passes+1
			continue
		}
		if err != nil {
			t.Fatalf("buffer %d: %v", have, err)
		}
		if have != full.HeaderSpan() || len(h.Sections) != 3 {
			t.Fatalf("finished at %d bytes, header span %d", have, full.HeaderSpan())
		}
		break
	}
	if passes < 4 {
		t.Errorf("%d passes", passes)
	}
}

func TestHeaderFailures(t *testing.T) {
	file := uint64(fxLfanew) + 4
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{"no MZ in a 2-byte buffer", func(b []byte) []byte { return []byte("ZM") }, ErrNotPE},
		{"no MZ", func(b []byte) []byte { b[0] = 'X'; return b }, ErrNotPE},
		{"no PE signature", func(b []byte) []byte { b[fxLfanew+1] = 'X'; return b }, ErrNoNTSignature},
		{"ROM magic", func(b []byte) []byte { put16(b, file+FileHeaderSize, 0x0107); return b }, ErrUnsupportedOptionalMagic},
		{"optional header shorter than its fields", func(b []byte) []byte {
			put16(b, file+offFileSizeOfOptionalHeader, uint16(offOptDataDirectory64-1))
			return b
		}, ErrShortOptionalHeader},
	} {
		if _, err := ParseHeaders(tc.edit(buildImage(true, 0x10000))); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestAnEightCharacterSectionNameHasNoNUL(t *testing.T) {
	img := buildImage(true, 0x10000)
	h, _ := ParseHeaders(img)
	copy(img[h.Sections[0].HeaderOffset:], "ABCDEFGH")
	h, err := ParseHeaders(img)
	if err != nil || h.Sections[0].Name != "ABCDEFGH" {
		t.Fatalf("%q %v", h.Sections[0].Name, err)
	}
}

func TestDataDirectoryEntriesCountOnlyWhenDeclared(t *testing.T) {
	for _, plus := range []bool{false, true} {
		img := buildImage(plus, 0x10000)
		fxDirectory(img, plus, DirectoryEntryDebug, 0x3000, 56)
		h, err := ParseHeaders(img)
		if err != nil {
			t.Fatal(err)
		}
		dir, err := h.DataDirectory(img, DirectoryEntryDebug)
		if err != nil || dir != (DataDirectory{0x3000, 56}) {
			t.Fatalf("plus %v: %+v %v", plus, dir, err)
		}
		if read, err := h.ReadDataDirectory(flat(img), DirectoryEntryDebug); err != nil || read != dir {
			t.Errorf("plus %v: ReadDataDirectory %+v %v", plus, read, err)
		}
		for _, index := range []int{-1, 16} {
			if _, err := h.DataDirectory(img, index); !errors.Is(err, ErrNoDataDirectory) {
				t.Errorf("index %d: %v", index, err)
			}
		}
		countAt, _ := h.directoryLayout()
		put32(img, countAt, 4)
		if _, err := h.DataDirectory(img, DirectoryEntryDebug); !errors.Is(err, ErrNoDataDirectory) {
			t.Errorf("past NumberOfRvaAndSizes: %v", err)
		}
		if _, err := h.ReadDataDirectory(flat(img), DirectoryEntryDebug); !errors.Is(err, ErrNoDataDirectory) {
			t.Errorf("ReadDataDirectory past NumberOfRvaAndSizes: %v", err)
		}
		put32(img, countAt, 16)
		_, arrayAt := h.directoryLayout()
		h.File.SizeOfOptionalHeader = uint16(arrayAt - h.OptionalOffset)
		if _, err := h.DataDirectory(img, DirectoryEntryExport); !errors.Is(err, ErrNoDataDirectory) {
			t.Errorf("past SizeOfOptionalHeader: %v", err)
		}
		if _, err := h.ReadDataDirectory(withHoles(img, 0), DirectoryEntryExport); !errors.Is(err, ErrUnreadable) {
			t.Errorf("unread header page: %v", err)
		}
	}
}
