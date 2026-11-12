package pe

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

func FuzzRebuild(f *testing.F) {
	f.Add(buildImage(true, 0x140000000), uint64(0x7FF600000000))
	f.Add(buildImage(false, 0x400000), uint64(0x10000))
	f.Add(buildImage(false, 0x400000), uint64(0x100000000))
	withDebug := buildImage(true, 0x10000)
	fxDirectory(withDebug, true, DirectoryEntryDebug, 0x3000, 2*debugDirectoryEntrySize)
	fxDirectory(withDebug, true, DirectoryEntryCertificate, 0x9000, 0x100)
	f.Add(withDebug, uint64(0x10000))

	f.Fuzz(func(t *testing.T, image []byte, base uint64) {
		out, err := Rebuild(image, base, limits.Limits{MaxArtifactBytes: 1 << 20})
		if err != nil {
			return
		}
		if len(out.File) != len(image) {
			t.Fatalf("rebuilt %d bytes of a %d-byte image", len(out.File), len(image))
		}
		h, err := ParseHeaders(out.File)
		if err != nil {
			t.Fatalf("the rebuilt headers no longer parse: %v", err)
		}
		align := uint64(h.Optional.SectionAlignment)
		allowed := make([]bool, len(image))
		allow := func(at, n uint64) {
			for i := at; i < at+n && i < uint64(len(allowed)); i++ {
				allowed[i] = true
			}
		}
		for _, s := range h.Sections {
			allow(s.HeaderOffset+offSectSizeOfRawData, 8)
			raw, ptr := uint64(s.SizeOfRawData), uint64(s.PointerToRawData)
			if raw == 0 {
				continue
			}
			if ptr != uint64(s.VirtualAddress) || ptr+raw > uint64(len(image)) {
				t.Fatalf("%q: raw 0x%x+0x%x, RVA 0x%x, image 0x%x", s.Name, ptr, raw, s.VirtualAddress, len(image))
			}
			if raw%align != 0 && ptr+raw != uint64(len(image)) {
				t.Fatalf("%q: raw size 0x%x is not a multiple of 0x%x and does not end the image", s.Name, raw, align)
			}
		}
		allow(h.OptionalOffset+offOptFileAlignment, 4)
		allow(h.OptionalOffset+offOptSizeOfHeaders, 4)
		allow(h.Optional.ImageBaseOffset, h.Optional.ImageBaseSize)
		allow(h.NTOffset+4+offFilePointerToSymbolTable, 8)
		allow(h.OptionalOffset+offOptCheckSum, 4)
		if h.Optional.CheckSum != 0 {
			t.Fatal("the CheckSum survived")
		}
		if at, ok := h.directoryEntryOffset(out.File, DirectoryEntryCertificate); ok {
			allow(at, 8)
			if binary.LittleEndian.Uint64(out.File[at:]) != 0 {
				t.Fatal("the certificate entry survived")
			}
		}
		if dir, err := h.DataDirectory(out.File, DirectoryEntryDebug); err == nil && uint64(dir.VirtualAddress) >= h.HeaderSpan() {
			entries := min(uint64(dir.Size), uint64(len(image))) / debugDirectoryEntrySize
			for i := range entries {
				allow(uint64(dir.VirtualAddress)+i*debugDirectoryEntrySize+debugEntryFileOffset, 4)
			}
		}
		fa := uint64(h.Optional.FileAlignment)
		if !powerOfTwo(fa) || fa > align {
			t.Fatalf("FileAlignment 0x%x with SectionAlignment 0x%x", fa, align)
		}
		for i := range image {
			if image[i] != out.File[i] && !allowed[i] {
				t.Fatalf("byte 0x%x changed outside the rewritten fields", i)
			}
		}
	})
}
