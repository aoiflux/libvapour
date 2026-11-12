package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/limits"
)

const (
	FixedFileInfoSignature = uint32(0xFEEF04BD)
	FixedFileInfoSize      = 52
)

const (
	versionHeaderBytes = 6
	versionKey         = "VS_VERSION_INFO"
)

var (
	ErrBadVersionInfo            = errors.New("pe: bad VS_VERSIONINFO")
	ErrNoFixedFileInfo           = errors.New("pe: VS_VERSIONINFO has no VS_FIXEDFILEINFO")
	ErrBadFixedFileInfoSignature = errors.New("pe: VS_FIXEDFILEINFO signature is not 0xFEEF04BD")
)

type FixedFileInfo struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

func splitVersion(ms, ls uint32) [4]uint16 {
	return [4]uint16{uint16(ms >> 16), uint16(ms), uint16(ls >> 16), uint16(ls)}
}

func (f FixedFileInfo) FileVersion() [4]uint16 { return splitVersion(f.FileVersionMS, f.FileVersionLS) }

func (f FixedFileInfo) ProductVersion() [4]uint16 {
	return splitVersion(f.ProductVersionMS, f.ProductVersionLS)
}

var versionKeyBytes = func() []byte {
	units := utf16.Encode([]rune(versionKey + "\x00"))
	b := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	return b
}()

func valueOffset(rva uint32) int {
	keyEnd := uint32(versionHeaderBytes + len(versionKeyBytes))
	return int(keyEnd + (4-(keyEnd+rva)%4)%4)
}

// The padding before Value aligns it to 32 bits of the address the data is
// loaded at, so the caller passes that address's low bits as rva.
func ParseVersionInfo(data []byte, rva uint32) (FixedFileInfo, error) {
	if len(data) < versionHeaderBytes {
		return FixedFileInfo{}, fmt.Errorf("%w: %d bytes", ErrBadVersionInfo, len(data))
	}
	length := int(binary.LittleEndian.Uint16(data))
	valueLength := int(binary.LittleEndian.Uint16(data[2:]))
	keyEnd := len(versionKeyBytes) + versionHeaderBytes
	if length < keyEnd || len(data) < keyEnd {
		return FixedFileInfo{}, fmt.Errorf("%w: wLength %d, %d bytes", ErrBadVersionInfo, length, len(data))
	}
	if string(data[versionHeaderBytes:keyEnd]) != string(versionKeyBytes) {
		return FixedFileInfo{}, fmt.Errorf("%w: szKey is not %s", ErrBadVersionInfo, versionKey)
	}
	if valueLength == 0 {
		return FixedFileInfo{}, ErrNoFixedFileInfo
	}
	value := valueOffset(rva)
	if valueLength < FixedFileInfoSize || value+FixedFileInfoSize > length {
		return FixedFileInfo{}, fmt.Errorf("%w: wValueLength %d at offset %d, wLength %d", ErrBadVersionInfo, valueLength, value, length)
	}
	if value+FixedFileInfoSize > len(data) {
		return FixedFileInfo{}, fmt.Errorf("%w: VS_FIXEDFILEINFO ends at %d, %d bytes", ErrBadVersionInfo, value+FixedFileInfoSize, len(data))
	}
	v := data[value:]
	u := func(i int) uint32 { return binary.LittleEndian.Uint32(v[4*i:]) }
	info := FixedFileInfo{
		Signature: u(0), StrucVersion: u(1),
		FileVersionMS: u(2), FileVersionLS: u(3),
		ProductVersionMS: u(4), ProductVersionLS: u(5),
		FileFlagsMask: u(6), FileFlags: u(7), FileOS: u(8), FileType: u(9), FileSubtype: u(10),
		FileDateMS: u(11), FileDateLS: u(12),
	}
	if info.Signature != FixedFileInfoSignature {
		return FixedFileInfo{}, fmt.Errorf("%w: 0x%08x", ErrBadFixedFileInfoSignature, info.Signature)
	}
	return info, nil
}

// Only the bytes up to the end of Value are read: the string and variable
// children that follow may lie on pages that did not read. The first version
// leaf in tree order that decodes wins; if none does, the first leaf's error
// is returned.
func ReadVersion(read ReadRVA, dir DataDirectory, l limits.Limits) (FixedFileInfo, error) {
	leaves, err := FindResources(read, dir, RTVersion, l)
	if err != nil {
		return FixedFileInfo{}, err
	}
	var first error
	for _, leaf := range leaves {
		data, err := readAt(read, uint64(leaf.RVA), uint64(min(leaf.Size, uint32(valueOffset(leaf.RVA)+FixedFileInfoSize))))
		if err == nil {
			var info FixedFileInfo
			if info, err = ParseVersionInfo(data, leaf.RVA); err == nil {
				return info, nil
			}
		}
		first = firstErr(first, err)
	}
	return FixedFileInfo{}, first
}
