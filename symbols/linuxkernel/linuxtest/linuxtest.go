// Package linuxtest builds a small x86-64 Linux capture for tests: page
// tables that map a 2 MiB arrays page, a kallsyms table in it, and VMCOREINFO
// notes placed where a test asks.
package linuxtest

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
)

type Memory struct{ Buf []byte }

func (m *Memory) ReadAt(offset, size uint64) ([]byte, error) {
	if offset > uint64(len(m.Buf)) || size > uint64(len(m.Buf))-offset {
		return nil, memory.ErrOutOfBounds
	}
	return append([]byte(nil), m.Buf[offset:offset+size]...), nil
}

func (m *Memory) Size() uint64 { return uint64(len(m.Buf)) }

const (
	Present    = 1
	PageSize   = 1 << 7
	PML4       = 0x1000
	PDPT       = 0x2000
	PD         = 0x3000
	PT         = 0x4000
	PML5       = 0x6000
	ArraysVA   = 0xffffffff82000000
	ArraysPA   = 0x200000
	ArraysSize = 2 << 20
	ProbeVA    = 0xffffffff82200000
	KernelBase = 0xffffffff81000000
	Size       = 4 << 20
)

// Where each kallsyms table lies in the arrays page.
const (
	numSymsAt    = 0x000
	relBaseAt    = 0x008
	tokenIndexAt = 0x100
	tokenTableAt = 0x400
	offsetsAt    = 0x1000
	namesAt      = 0x2000
)

func PutEntry(buf []byte, table, index, value uint64) {
	binary.LittleEndian.PutUint64(buf[table+8*index:], value)
}

// An ELF note: namesz 11 ("VMCOREINFO" and its NUL, padded to 12), descsz,
// type 0, the name, then the text.
func PutNote(buf []byte, off int, desc string) {
	binary.LittleEndian.PutUint32(buf[off:], 11)
	binary.LittleEndian.PutUint32(buf[off+4:], uint32(len(desc)))
	binary.LittleEndian.PutUint32(buf[off+8:], 0)
	copy(buf[off+12:], "VMCOREINFO\x00\x00")
	copy(buf[off+24:], desc)
}

// Each record is a type letter and a name; every printable byte is its own
// token, so a record is written as its own bytes.
func Capture(shift uint64, records []string, offsets []uint32) []byte {
	buf := make([]byte, Size)
	arrays, probe := ArraysVA+shift, ProbeVA+shift
	slot := func(va uint64, shift uint) uint64 { return va >> shift & 0x1ff }
	PutEntry(buf, PML5, slot(arrays, 48), PML4|Present)
	PutEntry(buf, PML4, slot(arrays, 39), PDPT|Present)
	PutEntry(buf, PDPT, slot(arrays, 30), PD|Present)
	PutEntry(buf, PD, slot(arrays, 21), ArraysPA|PageSize|Present)
	PutEntry(buf, PD, slot(probe, 21), PT|Present)

	page := buf[ArraysPA : ArraysPA+ArraysSize]
	binary.LittleEndian.PutUint32(page[numSymsAt:], uint32(len(records)))
	binary.LittleEndian.PutUint64(page[relBaseAt:], KernelBase+shift)
	at := tokenTableAt
	for c := range 256 {
		binary.LittleEndian.PutUint16(page[tokenIndexAt+2*c:], uint16(at-tokenTableAt))
		if c >= 0x20 && c < 0x7f {
			page[at] = byte(c)
			at++
		}
		at++
	}
	for i, off := range offsets {
		binary.LittleEndian.PutUint32(page[offsetsAt+4*i:], off)
	}
	at = namesAt
	for _, r := range records {
		page[at] = byte(len(r))
		at += 1 + copy(page[at+1:], r)
	}
	return buf
}

func KallsymsKeys(shift uint64) string {
	at := ArraysVA + shift
	return fmt.Sprintf("SYMBOL(kallsyms_num_syms)=%x\n"+
		"SYMBOL(kallsyms_relative_base)=%x\n"+
		"SYMBOL(kallsyms_token_index)=%x\n"+
		"SYMBOL(kallsyms_token_table)=%x\n"+
		"SYMBOL(kallsyms_offsets)=%x\n"+
		"SYMBOL(kallsyms_names)=%x\n"+
		"SYMBOL(_stext)=%x\n",
		at+numSymsAt, at+relBaseAt, at+tokenIndexAt, at+tokenTableAt, at+offsetsAt, at+namesAt, KernelBase+shift)
}

func LayoutKeys(shift uint64) string {
	return fmt.Sprintf("SYMBOL(swapper_pg_dir)=ffffffff80001000\nNUMBER(phys_base)=0\nKERNELOFFSET=%x\n", shift)
}

func Physical(va uint64) uint64 {
	return ArraysPA + (va - ArraysVA)
}
