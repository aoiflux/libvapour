package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
)

type CodeViewRecord struct {
	PDBPath string
	GUID    [16]byte
	Age     uint32
}

// Offsets from Microsoft Learn, "PE Format": e_lfanew, the COFF header, the
// optional header's data directories (Debug is the seventh), the debug
// directory entry, and the RSDS record (S32 F20, S47 B6).
const (
	peLfanewAt        = 0x3c
	peCOFFBytes       = 20
	peOptionalSizeAt  = 16
	peMagic32         = 0x10b
	peMagic64         = 0x20b
	peDirectories32   = 96
	peDirectories64   = 112
	peDirCount32At    = 92
	peDirCount64At    = 108
	peDebugDirectory  = 6
	debugEntryBytes   = 28
	debugTypeAt       = 12
	debugDataSizeAt   = 16
	debugDataRVAAt    = 20
	debugTypeCodeView = 2
	rsdsPathAt        = 24
	rsdsMaxPath       = 260
)

// The headers come from the image's first page and the directory from one page
// at most.
func ImageCodeViews(reader memory.MemoryReader, imageBase uint64) ([]CodeViewRecord, error) {
	hdr, err := reader.ReadAt(imageBase, pageBytes)
	if err != nil {
		return nil, fmt.Errorf("layers: image at 0x%x: headers: %w", imageBase, err)
	}
	if uint64(len(hdr)) < pageBytes || hdr[0] != 'M' || hdr[1] != 'Z' {
		return nil, fmt.Errorf("layers: image at 0x%x: no MZ header", imageBase)
	}
	nt := uint64(binary.LittleEndian.Uint32(hdr[peLfanewAt:]))
	if nt+4+peCOFFBytes+2 > pageBytes || !bytes.Equal(hdr[nt:nt+4], []byte("PE\x00\x00")) {
		return nil, fmt.Errorf("layers: image at 0x%x: no PE signature in the first page", imageBase)
	}
	optional := nt + 4 + peCOFFBytes
	optionalSize := uint64(binary.LittleEndian.Uint16(hdr[nt+4+peOptionalSizeAt:]))
	var dirs, countAt uint64
	switch binary.LittleEndian.Uint16(hdr[optional:]) {
	case peMagic32:
		dirs, countAt = peDirectories32, peDirCount32At
	case peMagic64:
		dirs, countAt = peDirectories64, peDirCount64At
	default:
		return nil, fmt.Errorf("layers: image at 0x%x: unknown optional header magic", imageBase)
	}
	entry := dirs + peDebugDirectory*8
	if entry+8 > optionalSize || optional+entry+8 > pageBytes {
		return nil, fmt.Errorf("layers: image at 0x%x: no debug directory entry", imageBase)
	}
	if binary.LittleEndian.Uint32(hdr[optional+countAt:]) <= peDebugDirectory {
		return nil, fmt.Errorf("layers: image at 0x%x: NumberOfRvaAndSizes leaves out the debug directory", imageBase)
	}
	rva := uint64(binary.LittleEndian.Uint32(hdr[optional+entry:]))
	size := min(uint64(binary.LittleEndian.Uint32(hdr[optional+entry+4:])), pageBytes)
	if rva == 0 || size < debugEntryBytes {
		return nil, fmt.Errorf("layers: image at 0x%x: empty debug directory", imageBase)
	}
	dir, err := reader.ReadAt(imageBase+rva, size)
	if err != nil {
		return nil, fmt.Errorf("layers: image at 0x%x: debug directory: %w", imageBase, err)
	}
	var out []CodeViewRecord
	for at := uint64(0); at+debugEntryBytes <= uint64(len(dir)); at += debugEntryBytes {
		if binary.LittleEndian.Uint32(dir[at+debugTypeAt:]) != debugTypeCodeView {
			continue
		}
		if r, ok := readRSDS(reader, imageBase, dir[at:at+debugEntryBytes]); ok {
			out = append(out, r)
		}
	}
	return out, nil
}

func readRSDS(reader memory.MemoryReader, imageBase uint64, entry []byte) (CodeViewRecord, bool) {
	size := uint64(binary.LittleEndian.Uint32(entry[debugDataSizeAt:]))
	rva := uint64(binary.LittleEndian.Uint32(entry[debugDataRVAAt:]))
	if rva == 0 || size <= rsdsPathAt {
		return CodeViewRecord{}, false
	}
	raw, err := reader.ReadAt(imageBase+rva, min(size, rsdsPathAt+rsdsMaxPath))
	if err != nil || len(raw) <= rsdsPathAt || string(raw[:4]) != "RSDS" {
		return CodeViewRecord{}, false
	}
	end := bytes.IndexByte(raw[rsdsPathAt:], 0)
	if end <= 0 {
		return CodeViewRecord{}, false
	}
	r := CodeViewRecord{PDBPath: string(raw[rsdsPathAt : rsdsPathAt+end]), Age: binary.LittleEndian.Uint32(raw[20:])}
	copy(r.GUID[:], raw[4:20])
	return r, true
}
