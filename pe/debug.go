package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/limits"
)

const (
	DirectoryEntryDebug = 6
	DebugTypeCodeView   = uint32(2)
)

const (
	debugDirectoryEntrySize = 28
	debugEntryTypeOffset    = 12
	debugEntrySizeOffset    = 16
	debugEntryRVAOffset     = 20

	codeViewMagic      = "RSDS"
	codeViewFixedBytes = 24
)

var (
	ErrNoDebugDirectory  = errors.New("pe: no debug directory")
	ErrNoCodeView        = errors.New("pe: no RSDS CodeView record")
	ErrBadDebugDirectory = errors.New("pe: debug directory holds no whole entry")
)

type CodeView struct {
	GUID    [16]byte
	Age     uint32
	PDBPath string
	RVA     uint32
}

func (c CodeView) PDBName() string {
	return c.PDBPath[strings.LastIndexAny(c.PDBPath, `\/`)+1:]
}

// The first RSDS record in directory order wins. When none decodes, a read
// failure is reported over "absent": an unread page says nothing about what
// the record held.
func ReadCodeView(read ReadRVA, dir DataDirectory) (CodeView, error) {
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return CodeView{}, ErrNoDebugDirectory
	}
	count := uint64(dir.Size) / debugDirectoryEntrySize
	if count == 0 {
		return CodeView{}, fmt.Errorf("%w: Size %d", ErrBadDebugDirectory, dir.Size)
	}
	pathLimit := limits.Default().MaxNameBytes
	var unread, malformed error
	for i := range count {
		entry, err := readAt(read, uint64(dir.VirtualAddress)+i*debugDirectoryEntrySize, debugDirectoryEntrySize)
		if err != nil {
			if unread == nil {
				unread = err
			}
			break
		}
		if binary.LittleEndian.Uint32(entry[debugEntryTypeOffset:]) != DebugTypeCodeView {
			continue
		}
		rva := binary.LittleEndian.Uint32(entry[debugEntryRVAOffset:])
		size := binary.LittleEndian.Uint32(entry[debugEntrySizeOffset:])
		cv, err := readCodeViewRecord(read, rva, size, pathLimit)
		switch {
		case err == nil:
			return cv, nil
		case errors.Is(err, ErrUnreadable) || errors.Is(err, ErrOutsideImage):
			if unread == nil {
				unread = err
			}
		case malformed == nil:
			malformed = err
		}
	}
	switch {
	case unread != nil:
		return CodeView{}, unread
	case malformed != nil:
		return CodeView{}, malformed
	}
	return CodeView{}, ErrNoCodeView
}

func readCodeViewRecord(read ReadRVA, rva, size uint32, pathLimit int64) (CodeView, error) {
	if rva == 0 {
		return CodeView{}, fmt.Errorf("%w: CodeView entry is not mapped", ErrNoCodeView)
	}
	if size <= codeViewFixedBytes {
		return CodeView{}, fmt.Errorf("%w: CodeView data at rva 0x%x is %d bytes", ErrNoCodeView, rva, size)
	}
	head, err := readAt(read, uint64(rva), codeViewFixedBytes)
	if err != nil {
		return CodeView{}, err
	}
	if string(head[:4]) != codeViewMagic {
		return CodeView{}, fmt.Errorf("%w: CodeView data at rva 0x%x starts %q", ErrNoCodeView, rva, head[:4])
	}
	limit := min(int64(size)-codeViewFixedBytes-1, pathLimit)
	path, err := readString(read, uint64(rva)+codeViewFixedBytes, limit)
	if err != nil {
		return CodeView{}, err
	}
	if path == "" {
		return CodeView{}, fmt.Errorf("%w: CodeView record at rva 0x%x has an empty path", ErrNoCodeView, rva)
	}
	cv := CodeView{Age: binary.LittleEndian.Uint32(head[20:]), PDBPath: path, RVA: rva}
	copy(cv.GUID[:], head[4:20])
	return cv, nil
}
