package memory

import (
	"encoding/binary"
	"fmt"
)

type image []byte

func (m image) ReadAt(offset, size uint64) ([]byte, error) {
	if err := checkSpan(offset, size, uint64(len(m))); err != nil {
		return nil, err
	}
	return append([]byte(nil), m[offset:offset+size]...), nil
}

func (m image) Size() uint64 { return uint64(len(m)) }

func (m image) ImmutableSnapshot() bool { return true }

type countingReader struct {
	MemoryReader
	reads int
}

func (c *countingReader) ReadAt(offset, size uint64) ([]byte, error) {
	c.reads++
	return c.MemoryReader.ReadAt(offset, size)
}

type failingAt struct {
	MemoryReader
	bad Range
}

func (f failingAt) ReadAt(offset, size uint64) ([]byte, error) {
	if offset < f.bad.End && offset+size > f.bad.Start {
		return nil, fmt.Errorf("test: unreadable 0x%x", offset)
	}
	return f.MemoryReader.ReadAt(offset, size)
}

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7)
	}
	return b
}

type run struct{ base, count uint64 }

// crashFile lays out a 64-bit full dump: the measured header (S71 C2) and
// each run's pages in order, page p filled with the low byte of p.
func crashFile(runs []run, mutate func(h []byte)) image {
	h := make([]byte, crashHeaderBytes)
	for i := 0; i+4 <= len(h); i += 4 {
		copy(h[i:], crashSignature)
	}
	copy(h[4:], crashKind64)
	le := binary.LittleEndian
	le.PutUint32(h[crashMajorAt:], 15)
	le.PutUint32(h[crashMinorAt:], 26100)
	le.PutUint64(h[crashRootAt:], 0x1ad000)
	le.PutUint64(h[crashPfnAt:], 0xffffa00000000000)
	le.PutUint64(h[crashModulesAt:], 0xfffff80000100000)
	le.PutUint64(h[crashProcessesAt:], 0xfffff80000100010)
	le.PutUint32(h[crashMachineAt:], 0x8664)
	le.PutUint32(h[crashProcessorsAt:], 2)
	le.PutUint32(h[crashBugCheckAt:], 0xe2)
	le.PutUint64(h[crashDebuggerAt:], 0xfffff80000200000)
	le.PutUint32(h[crashDescriptorAt:], uint32(len(runs)))
	var total uint64
	for i, r := range runs {
		le.PutUint64(h[crashRunsAt+crashRunBytes*i:], r.base)
		le.PutUint64(h[crashRunsAt+crashRunBytes*i+8:], r.count)
		total += r.count
	}
	le.PutUint64(h[crashTotalAt:], total)
	if crashRunsAt+crashRunBytes*len(runs) <= crashDumpTypeAt {
		le.PutUint32(h[crashDumpTypeAt:], crashDumpTypeFull)
		le.PutUint64(h[crashRequiredAt:], crashHeaderBytes+total*crashPageBytes)
		le.PutUint64(h[crashSystemTimeAt:], 133000000000000000)
		le.PutUint64(h[crashUpTimeAt:], 36_000_000_000)
		copy(h[crashCommentAt:], "test dump\x00")
	}
	if mutate != nil {
		mutate(h)
	}
	out := append(image(nil), h...)
	for _, r := range runs {
		for p := r.base; p < r.base+r.count; p++ {
			page := make([]byte, crashPageBytes)
			for i := range page {
				page[i] = byte(p)
			}
			out = append(out, page...)
		}
	}
	return out
}

type limeRange struct {
	start uint64
	data  []byte
}

func limeFile(ranges []limeRange) image {
	var out image
	for _, r := range ranges {
		h := make([]byte, limeHeaderBytes)
		binary.LittleEndian.PutUint32(h, limeMagic)
		binary.LittleEndian.PutUint32(h[4:], limeVersion)
		binary.LittleEndian.PutUint64(h[limeStartAt:], r.start)
		binary.LittleEndian.PutUint64(h[limeEndAt:], r.start+uint64(len(r.data))-1)
		out = append(append(out, h...), r.data...)
	}
	return out
}

type elfNoteSpec struct {
	name string
	typ  uint32
	desc []byte
}

type elfLoadSpec struct {
	phys uint64
	data []byte
	mem  uint64
}

type elfSpec struct {
	wide, big  bool
	fileType   uint16
	notes      []elfNoteSpec
	noteAlign  uint64
	loads      []elfLoadSpec
	extendedPh bool
}

func (s elfSpec) build() image {
	shape := elf32
	if s.wide {
		shape = elf64
	}
	var order binary.ByteOrder = binary.LittleEndian
	if s.big {
		order = binary.BigEndian
	}
	put := func(b []byte, at int, v uint64) {
		if s.wide {
			order.PutUint64(b[at:], v)
		} else {
			order.PutUint32(b[at:], uint32(v))
		}
	}
	var noteBody []byte
	for _, n := range s.notes {
		h := make([]byte, noteHeader)
		order.PutUint32(h, uint32(len(n.name)+1))
		order.PutUint32(h[4:], uint32(len(n.desc)))
		order.PutUint32(h[8:], n.typ)
		noteBody = append(noteBody, h...)
		noteBody = append(noteBody, n.name...)
		noteBody = append(noteBody, 0)
		for len(noteBody)%4 != 0 {
			noteBody = append(noteBody, 0)
		}
		noteBody = append(noteBody, n.desc...)
		for len(noteBody)%4 != 0 {
			noteBody = append(noteBody, 0)
		}
	}
	count := len(s.loads)
	if len(s.notes) > 0 {
		count++
	}
	head := int(shape.headerBytes)
	phAt := head
	shAt := phAt + count*int(shape.phdrBytes)
	dataAt := shAt
	if s.extendedPh {
		dataAt += shape.sectionBytes
	}
	out := make([]byte, dataAt)
	copy(out, elfMagic)
	out[4] = elfClass32
	if s.wide {
		out[4] = elfClass64
	}
	out[5] = elfDataLSB
	if s.big {
		out[5] = elfDataMSB
	}
	out[6] = 1
	ft := s.fileType
	if ft == 0 {
		ft = elfTypeCore
	}
	order.PutUint16(out[16:], ft)
	put(out, shape.phoffAt, uint64(phAt))
	order.PutUint16(out[shape.phentAt:], uint16(shape.phdrBytes))
	if s.extendedPh {
		order.PutUint16(out[shape.phnumAt:], elfManyPhdrs)
		put(out, shape.shoffAt, uint64(shAt))
		order.PutUint16(out[shape.shentAt:], uint16(shape.sectionBytes))
		order.PutUint32(out[shAt+shape.shInfoAt:], uint32(count))
	} else {
		order.PutUint16(out[shape.phnumAt:], uint16(count))
	}
	ph := func(i int, kind uint32, off, phys, file, mem, align uint64) {
		p := out[phAt+i*int(shape.phdrBytes):]
		order.PutUint32(p, kind)
		put(p, shape.pOffsetAt, off)
		put(p, shape.pPhysAt, phys)
		put(p, shape.pFileAt, file)
		memAt := shape.pFileAt + 8
		if !s.wide {
			memAt = shape.pFileAt + 4
		}
		put(p, memAt, mem)
		put(p, shape.pAlignAt, align)
	}
	i := 0
	if len(s.notes) > 0 {
		ph(i, elfNote, uint64(len(out)), 0, uint64(len(noteBody)), uint64(len(noteBody)), s.noteAlign)
		out = append(out, noteBody...)
		i++
	}
	for _, l := range s.loads {
		mem := l.mem
		if mem == 0 {
			mem = uint64(len(l.data))
		}
		ph(i, elfLoad, uint64(len(out)), l.phys, uint64(len(l.data)), mem, 0x1000)
		out = append(out, l.data...)
		i++
	}
	return out
}
