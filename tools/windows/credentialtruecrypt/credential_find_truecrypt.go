package credentialtruecrypt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const Name = "windows.credential.find_truecrypt"

const OptionMinLength = "truecrypt_min_length"

// Owner decisions (S66 TO1 to TO5): no allowed source documents the driver's
// cache, and no capture holds the driver.
const (
	DriverName       = "truecrypt.sys"
	DefaultMinLength = 4
	MaxLength        = 128
)

const (
	scnMemExecute = 0x20000000
	scnMemWrite   = 0x80000000
	lengthBytes   = 4
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find counted printable strings, candidate cached passphrases, in the writable sections of truecrypt.sys",
		},
		RunAny,
	)
}

var (
	ErrNotWindows = errors.New("credentialtruecrypt: profile is not windows")
	ErrMinLength  = errors.New("credentialtruecrypt: minimum length out of range")
)

// Offset is the virtual address of the 4-byte length that precedes the text.
type Passphrase struct {
	Offset   uint64
	Length   uint64
	Password string
	Section  string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Passphrase, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	minLength, err := readMinLength(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	mods, err := modulelist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: module list: %w", Name, err)
	}
	var rows []Passphrase
	unnamed := 0
	for _, m := range mods {
		if m.NameUnreadable {
			unnamed++
			continue
		}
		if !strings.EqualFold(m.Name, DriverName) {
			continue
		}
		if m.BaseUnreadable || m.Base == 0 {
			ctx.AddDiagnostic("%s: loader entry at 0x%x: %s has no readable base: not scanned", Name, m.Entry, m.Name)
			continue
		}
		found, err := scanDriver(ctx, m.Base, minLength)
		if err != nil {
			if ctx.StrictMode() {
				return nil, err
			}
			ctx.AddDiagnostic("%v", err)
		}
		rows = append(rows, found...)
	}
	if unnamed > 0 {
		ctx.AddDiagnostic("%s: %d loaded modules have no readable name: any of them could be %s", Name, unnamed, DriverName)
	}
	return rows, nil
}

func readMinLength(ctx tools.Context) (uint64, error) {
	v, set, err := ctx.UintOption(OptionMinLength)
	if err != nil {
		return 0, err
	}
	if !set {
		return DefaultMinLength, nil
	}
	if v < 1 || v > MaxLength {
		return 0, fmt.Errorf("%s %d: %w: want 1 to %d", OptionMinLength, v, ErrMinLength, MaxLength)
	}
	return v, nil
}

func scanDriver(ctx tools.Context, base, minLength uint64) ([]Passphrase, error) {
	headers, err := extract.ReadHeaders(ctx.Memory, base)
	if err != nil {
		return nil, fmt.Errorf("%s: %s at 0x%x: PE headers do not read: %w", Name, DriverName, base, err)
	}
	limit := uint64(ctx.Bounds().MaxRegionScanBytes)
	var rows []Passphrase
	for _, s := range headers.Sections {
		if s.Characteristics&scnMemWrite == 0 || s.Characteristics&scnMemExecute != 0 {
			continue
		}
		size := sectionSpan(s, headers.Optional.SizeOfImage)
		if size > limit {
			ctx.AddDiagnostic("%s: %s at 0x%x: section %q of %d bytes is scanned to MaxRegionScanBytes %d", Name, DriverName,
				base, s.Name, size, limit)
			size = limit
		}
		start := base + uint64(s.VirtualAddress)
		data, gaps := extract.ReadPadded(ctx.Memory, start, size)
		if missing := gaps.PaddedBytes(); missing > 0 {
			ctx.AddDiagnostic("%s: section %q at 0x%x: %d of %d bytes do not read and are scanned as zero", Name, s.Name,
				start, missing, size)
		}
		for _, h := range FindCounted(data, minLength, MaxLength) {
			rows = append(rows, Passphrase{Offset: start + h.Offset, Length: uint64(len(h.Text)), Password: h.Text, Section: s.Name})
		}
	}
	return rows, nil
}

// The loaded size is VirtualSize; a linker that leaves it 0 gives only the
// file size, so that is used instead. Neither may run past the image.
func sectionSpan(s pe.SectionHeader, sizeOfImage uint32) uint64 {
	size := uint64(s.VirtualSize)
	if size == 0 {
		size = uint64(s.SizeOfRawData)
	}
	if end := uint64(s.VirtualAddress) + size; end > uint64(sizeOfImage) {
		if uint64(s.VirtualAddress) >= uint64(sizeOfImage) {
			return 0
		}
		size = uint64(sizeOfImage) - uint64(s.VirtualAddress)
	}
	return size
}

type Counted struct {
	Offset uint64
	Text   string
}

// FindCounted gives each 4-byte aligned little-endian length n, minLength <= n
// <= maxLength, followed by n printable ASCII bytes and a NUL. The scan resumes
// after the NUL, so text inside a hit is not reported again.
func FindCounted(data []byte, minLength, maxLength uint64) []Counted {
	var out []Counted
	for off := uint64(0); off+lengthBytes <= uint64(len(data)); {
		n := uint64(binary.LittleEndian.Uint32(data[off:]))
		end := off + lengthBytes + n
		if n < minLength || n > maxLength || end >= uint64(len(data)) || data[end] != 0 || !printable(data[off+lengthBytes:end]) {
			off += lengthBytes
			continue
		}
		out = append(out, Counted{Offset: off, Text: string(data[off+lengthBytes : end])})
		off = (end + lengthBytes) &^ (lengthBytes - 1)
	}
	return out
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
