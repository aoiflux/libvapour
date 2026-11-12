package autoload

import (
	"encoding/binary"
	"errors"

	"github.com/aoiflux/libvapour/memory"
)

type flatImage struct{ buf []byte }

func (m *flatImage) ReadAt(offset, size uint64) ([]byte, error) {
	if offset > uint64(len(m.buf)) || size > uint64(len(m.buf))-offset {
		return nil, memory.ErrOutOfBounds
	}
	return append([]byte(nil), m.buf[offset:offset+size]...), nil
}

func (m *flatImage) Size() uint64 { return uint64(len(m.buf)) }

var errCaptureGone = errors.New("the capture file went away")

type unreadableImage struct{ size uint64 }

func (unreadableImage) ReadAt(uint64, uint64) ([]byte, error) { return nil, errCaptureGone }
func (m unreadableImage) Size() uint64                        { return m.size }

// Page-table entry bits for the fixtures that build 4-level tables.
const (
	ptePresent   = uint64(1)
	pteFramemask = uint64(0x000ffffffffff000)
)

// A PE32+ image: e_lfanew 0x80, a debug directory of one CodeView entry at
// RVA 0x1000 that declares its record at declaredRVA, and the record itself
// at RVA 0x2000.
const (
	fixtureLfanew      = 0x80
	fixtureDebugDirRVA = 0x1000
	fixtureRecordRVA   = 0x2000
	fixtureImageSpan   = 0x3000
)

func putRSDSNamed(buf []byte, off int, pdb string, seed byte, age uint32) {
	copy(buf[off:], "RSDS")
	for i := range 16 {
		buf[off+4+i] = seed + byte(i)
	}
	binary.LittleEndian.PutUint32(buf[off+20:], age)
	copy(buf[off+24:], pdb+"\x00")
}

func putKernelImage(buf []byte, base int, pdb string, seed byte, age uint32, declaredRVA uint32) {
	copy(buf[base:], "MZ")
	binary.LittleEndian.PutUint32(buf[base+0x3c:], fixtureLfanew)
	nt := base + fixtureLfanew
	copy(buf[nt:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(buf[nt+4+16:], 0xf0)
	optional := nt + 4 + 20
	binary.LittleEndian.PutUint16(buf[optional:], 0x20b)
	binary.LittleEndian.PutUint32(buf[optional+108:], 16)
	debug := optional + 112 + 6*8
	binary.LittleEndian.PutUint32(buf[debug:], fixtureDebugDirRVA)
	binary.LittleEndian.PutUint32(buf[debug+4:], 28)
	dir := base + fixtureDebugDirRVA
	binary.LittleEndian.PutUint32(buf[dir+12:], 2)
	binary.LittleEndian.PutUint32(buf[dir+16:], uint32(24+len(pdb)+1))
	binary.LittleEndian.PutUint32(buf[dir+20:], declaredRVA)
	binary.LittleEndian.PutUint32(buf[dir+24:], declaredRVA)
	putRSDSNamed(buf, base+fixtureRecordRVA, pdb, seed, age)
}

func kernelBanner(release string) string {
	return "Linux version " + release + " (builder@host) (gcc 13.3.0, GNU ld 2.42) #1 SMP PREEMPT_DYNAMIC"
}

// putBanner writes a banner with its "\n\0" and, when template is set,
// linux_proc_banner gap bytes after it. It returns the offset past both.
func putBanner(buf []byte, off int, release string, template bool, gap int) int {
	off += copy(buf[off:], kernelBanner(release)+"\n\x00")
	if !template {
		return off
	}
	off += gap
	return off + copy(buf[off:], "%s version %s (builder@host) (gcc 13.3.0, GNU ld 2.42) %s\n\x00")
}
