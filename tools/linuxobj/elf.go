package linuxobj

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
)

var (
	ErrELFClass = errors.New("linuxobj: elf class or data encoding not supported")
	ErrELFRead  = errors.New("linuxobj: elf structure unreadable")
)

const (
	elfClass32  = 1
	elfClass64  = 2
	elfDataLSB  = 1
	elfPTLoad   = 1
	elfPTDyn    = 2
	elfDTNull   = 0
	elfDTDebug  = 21
	elfPageSize = 4096
)

type ELF struct {
	r         memory.MemoryReader
	Base      uint64
	Class     int
	Type      uint16
	Machine   uint16
	PhOff     uint64
	PhEntSize uint16
	PhNum     uint16
}

type ProgramHeader struct {
	Type, Flags                         uint32
	Offset, Vaddr, Filesz, Memsz, Align uint64
}

type LinkMapEntry struct {
	Address, LoadBias, Name, Dynamic uint64
}

func (e ELF) width() uint64 {
	if e.Class == 64 {
		return 8
	}
	return 4
}

func (e ELF) bytes(at, n uint64) ([]byte, error) {
	b, err := e.r.ReadAt(at, n)
	if err != nil || uint64(len(b)) < n {
		return nil, fmt.Errorf("%w: %d bytes at %#x", ErrELFRead, n, at)
	}
	return b[:n], nil
}

func (e ELF) word(b []byte) uint64 {
	if e.Class == 64 {
		return binary.LittleEndian.Uint64(b)
	}
	return uint64(binary.LittleEndian.Uint32(b))
}

// ParseELF is false with no error when base holds no ELF identification.
func ParseELF(r memory.MemoryReader, base uint64) (ELF, bool, error) {
	id, err := r.ReadAt(base, 16)
	if err != nil || len(id) < 16 || !bytes.Equal(id[:4], []byte("\x7fELF")) {
		return ELF{}, false, nil
	}
	e := ELF{r: r, Base: base}
	switch id[4] {
	case elfClass64:
		e.Class = 64
	case elfClass32:
		e.Class = 32
	default:
		return ELF{}, false, fmt.Errorf("elf at %#x: class %d: %w", base, id[4], ErrELFClass)
	}
	if id[5] != elfDataLSB {
		return ELF{}, false, fmt.Errorf("elf at %#x: data encoding %d: %w", base, id[5], ErrELFClass)
	}
	size, phoff, phent, phnum := uint64(52), uint64(28), uint64(42), uint64(44)
	if e.Class == 64 {
		size, phoff, phent, phnum = 64, 32, 54, 56
	}
	h, err := e.bytes(base, size)
	if err != nil {
		return ELF{}, false, fmt.Errorf("elf at %#x: header: %w", base, err)
	}
	e.Type = binary.LittleEndian.Uint16(h[16:])
	e.Machine = binary.LittleEndian.Uint16(h[18:])
	e.PhOff = e.word(h[phoff:])
	e.PhEntSize = binary.LittleEndian.Uint16(h[phent:])
	e.PhNum = binary.LittleEndian.Uint16(h[phnum:])
	return e, true, nil
}

func (e ELF) ProgramHeaders(maxEntries int) ([]ProgramHeader, error) {
	entry := uint64(32)
	if e.Class == 64 {
		entry = 56
	}
	if uint64(e.PhEntSize) < entry {
		return nil, fmt.Errorf("elf at %#x: program header entry of %d bytes: %w", e.Base, e.PhEntSize, ErrELFRead)
	}
	n := min(int(e.PhNum), maxEntries)
	out := make([]ProgramHeader, 0, n)
	for i := range n {
		b, err := e.bytes(e.Base+e.PhOff+uint64(i)*uint64(e.PhEntSize), entry)
		if err != nil {
			return out, fmt.Errorf("elf at %#x: program header %d: %w", e.Base, i, err)
		}
		le := binary.LittleEndian
		var p ProgramHeader
		if e.Class == 64 {
			p = ProgramHeader{Type: le.Uint32(b), Flags: le.Uint32(b[4:]), Offset: le.Uint64(b[8:]), Vaddr: le.Uint64(b[16:]),
				Filesz: le.Uint64(b[32:]), Memsz: le.Uint64(b[40:]), Align: le.Uint64(b[48:])}
		} else {
			p = ProgramHeader{Type: le.Uint32(b), Offset: uint64(le.Uint32(b[4:])), Vaddr: uint64(le.Uint32(b[8:])),
				Filesz: uint64(le.Uint32(b[16:])), Memsz: uint64(le.Uint32(b[20:])), Flags: le.Uint32(b[24:]),
				Align: uint64(le.Uint32(b[28:]))}
		}
		out = append(out, p)
	}
	return out, nil
}

func (e ELF) LoadSegments() ([]ProgramHeader, error) {
	all, err := e.ProgramHeaders(int(e.PhNum))
	var out []ProgramHeader
	for _, p := range all {
		if p.Type == elfPTLoad {
			out = append(out, p)
		}
	}
	return out, err
}

// LoadBias is the gABI base address, taking Base as the memory address of
// file offset 0.
func (e ELF) LoadBias(headers []ProgramHeader) (uint64, bool) {
	var low ProgramHeader
	found := false
	for _, p := range headers {
		if p.Type == elfPTLoad && (!found || p.Vaddr < low.Vaddr) {
			low, found = p, true
		}
	}
	if !found {
		return 0, false
	}
	page := ^uint64(elfPageSize - 1)
	return e.Base&page - (low.Vaddr-low.Offset)&page, true
}

func (e ELF) DebugAddress(maxEntries int) (uint64, error) {
	headers, err := e.ProgramHeaders(maxEntries)
	if err != nil {
		return 0, err
	}
	bias, ok := e.LoadBias(headers)
	if !ok {
		return 0, nil
	}
	w := e.width()
	for _, p := range headers {
		if p.Type != elfPTDyn {
			continue
		}
		for i := uint64(0); (i+1)*2*w <= p.Memsz && i < uint64(maxEntries); i++ {
			b, err := e.bytes(bias+p.Vaddr+i*2*w, 2*w)
			if err != nil {
				return 0, fmt.Errorf("elf at %#x: dynamic entry %d: %w", e.Base, i, err)
			}
			switch e.word(b) {
			case elfDTNull:
				return 0, nil
			case elfDTDebug:
				return e.word(b[w:]), nil
			}
		}
	}
	return 0, nil
}

// LinkMap walks the dynamic linker's list from DT_DEBUG; entries read before
// a failed read come back with the error.
func (e ELF) LinkMap(maxEntries int) ([]LinkMapEntry, error) {
	debug, err := e.DebugAddress(maxEntries)
	if err != nil || debug == 0 {
		return nil, err
	}
	w := e.width()
	b, err := e.bytes(debug+w, w)
	if err != nil {
		return nil, fmt.Errorf("elf at %#x: debug structure at %#x: %w", e.Base, debug, err)
	}
	var out []LinkMapEntry
	seen := map[uint64]bool{}
	for at := e.word(b); at != 0 && !seen[at] && len(out) < maxEntries; {
		seen[at] = true
		f, err := e.bytes(at, 4*w)
		if err != nil {
			return out, fmt.Errorf("elf at %#x: library entry at %#x: %w", e.Base, at, err)
		}
		out = append(out, LinkMapEntry{Address: at, LoadBias: e.word(f), Name: e.word(f[w:]), Dynamic: e.word(f[2*w:])})
		at = e.word(f[3*w:])
	}
	return out, nil
}

// NameAt reads a NUL-terminated string; false when it does not read or has
// no NUL within maxBytes.
func (e ELF) NameAt(at uint64, maxBytes int64) (string, bool) {
	var out []byte
	for int64(len(out)) < maxBytes {
		n := min(uint64(maxBytes-int64(len(out))), elfPageSize-at%elfPageSize)
		b, err := e.bytes(at, n)
		if err != nil {
			return "", false
		}
		if i := bytes.IndexByte(b, 0); i >= 0 {
			return string(append(out, b[:i]...)), true
		}
		out = append(out, b...)
		at += n
	}
	return "", false
}
