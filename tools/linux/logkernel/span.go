package logkernel

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/memory"
)

const pageSize = 0x1000

// span keeps the pages of a large array that read and marks the rest, so one
// unreadable page costs only the records that touch it.
type span struct {
	b      []byte
	base   uint64
	unread []bool
}

func readSpan(mem memory.MemoryReader, addr, n uint64) span {
	s := span{b: make([]byte, n), base: addr}
	first := addr &^ (pageSize - 1)
	s.unread = make([]bool, (addr+n-first+pageSize-1)/pageSize)
	for at := uint64(0); at < n; {
		chunk := min(pageSize-(addr+at)%pageSize, n-at)
		b, err := mem.ReadAt(addr+at, chunk)
		if err != nil || uint64(len(b)) < chunk {
			s.unread[(addr+at-first)/pageSize] = true
		} else {
			copy(s.b[at:], b)
		}
		at += chunk
	}
	return s
}

func wholeSpan(b []byte) span { return span{b: b} }

func (s span) bytes(off, n uint64) ([]byte, bool) {
	if off > uint64(len(s.b)) || n > uint64(len(s.b))-off {
		return nil, false
	}
	if len(s.unread) > 0 && n > 0 {
		first := s.base &^ (pageSize - 1)
		for p := (s.base + off - first) / pageSize; p <= (s.base+off+n-1-first)/pageSize; p++ {
			if s.unread[p] {
				return nil, false
			}
		}
	}
	return s.b[off : off+n], true
}

func (s span) uint(off, width uint64) (uint64, bool) {
	b, ok := s.bytes(off, width)
	if !ok {
		return 0, false
	}
	return le(b), true
}

func le(b []byte) uint64 {
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(b))
	case 4:
		return uint64(binary.LittleEndian.Uint32(b))
	case 8:
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}
