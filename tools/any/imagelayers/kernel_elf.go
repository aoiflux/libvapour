package imagelayers

import (
	"encoding/binary"
	"os"

	"github.com/aoiflux/libvapour/layers"
)

// ELF64 layout (S47 F1 to F3).
const (
	elfHeaderSize     = 64
	programHeaderSize = 56
	sectionHeaderSize = 64
	elfPageAlign      = 4096

	elfClass64  = 2
	elfDataLSB  = 1
	elfVersion  = 1
	elfTypeCore = 4
	ptLoad      = 1
	pfRead      = 4
	pnXNum      = 0xffff
)

func alignPage(n uint64) uint64 { return (n + elfPageAlign - 1) &^ (elfPageAlign - 1) }

// With PN_XNUM or more entries one section header holds the count, so it
// sits after the program headers.
func headerBytes(runs int) (phoff, shoff, data uint64) {
	phoff = elfHeaderSize
	end := phoff + uint64(runs)*programHeaderSize
	if runs >= pnXNum {
		shoff = end
		end += sectionHeaderSize
	}
	return phoff, shoff, alignPage(end)
}

func elfSize(runs []layers.MappedRun) uint64 {
	_, _, at := headerBytes(len(runs))
	for _, r := range runs {
		at = alignPage(at) + r.Size
	}
	return at
}

func elfHeaders(runs []layers.MappedRun, machine uint16) ([]byte, []uint64) {
	phoff, shoff, data := headerBytes(len(runs))
	out := make([]byte, data)
	le := binary.LittleEndian
	copy(out, []byte{0x7f, 'E', 'L', 'F', elfClass64, elfDataLSB, elfVersion})
	le.PutUint16(out[16:], elfTypeCore)
	le.PutUint16(out[18:], machine)
	le.PutUint32(out[20:], elfVersion)
	le.PutUint64(out[32:], phoff)
	le.PutUint64(out[40:], shoff)
	le.PutUint16(out[52:], elfHeaderSize)
	le.PutUint16(out[54:], programHeaderSize)
	phnum := uint16(min(len(runs), pnXNum))
	le.PutUint16(out[56:], phnum)
	if shoff != 0 {
		le.PutUint16(out[58:], sectionHeaderSize)
		le.PutUint16(out[60:], 1)
		le.PutUint32(out[shoff+44:], uint32(len(runs)))
	}
	offsets := make([]uint64, len(runs))
	at := data
	for i, r := range runs {
		at = alignPage(at)
		offsets[i] = at
		ph := out[phoff+uint64(i)*programHeaderSize:]
		le.PutUint32(ph[0:], ptLoad)
		le.PutUint32(ph[4:], pfRead)
		le.PutUint64(ph[8:], at)
		le.PutUint64(ph[16:], r.Virtual)
		le.PutUint64(ph[24:], r.Physical)
		le.PutUint64(ph[32:], r.Size)
		le.PutUint64(ph[40:], r.Size)
		le.PutUint64(ph[48:], elfPageAlign)
		at += r.Size
	}
	return out, offsets
}

func (w *writer) kernel(f *os.File, s source) (uint64, error) {
	head, offsets := elfHeaders(s.runs, s.machine)
	if _, err := f.WriteAt(head, 0); err != nil {
		return 0, err
	}
	var read uint64
	for i, r := range s.runs {
		n, err := w.copy(f, s.physical, r.Physical, r.Size, offsets[i])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}
