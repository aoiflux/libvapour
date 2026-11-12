package autoload

import (
	"encoding/binary"
	"testing"
)

// writeMSF lays streams out in blocks of blockSize after the superblock and
// the two free block maps, with the directory last and its block map after it.
func writeMSF(blockSize uint32, streams [][]byte) []byte {
	bs := int(blockSize)
	var blocks [][]byte
	newBlock := func(b []byte) uint32 {
		blk := make([]byte, bs)
		copy(blk, b)
		blocks = append(blocks, blk)
		return uint32(len(blocks) - 1)
	}
	newBlock(nil)
	newBlock(nil)
	newBlock(nil)
	dir := binary.LittleEndian.AppendUint32(nil, uint32(len(streams)))
	var lists [][]uint32
	for _, s := range streams {
		dir = binary.LittleEndian.AppendUint32(dir, uint32(len(s)))
		var list []uint32
		for at := 0; at < len(s); at += bs {
			list = append(list, newBlock(s[at:min(at+bs, len(s))]))
		}
		lists = append(lists, list)
	}
	for _, list := range lists {
		for _, b := range list {
			dir = binary.LittleEndian.AppendUint32(dir, b)
		}
	}
	var dirBlocks []byte
	for at := 0; at < len(dir); at += bs {
		dirBlocks = binary.LittleEndian.AppendUint32(dirBlocks, newBlock(dir[at:min(at+bs, len(dir))]))
	}
	mapBlock := newBlock(dirBlocks)
	head := []byte(msfSignature)
	for _, v := range []uint32{blockSize, 1, uint32(len(blocks)), uint32(len(dir)), 0, mapBlock} {
		head = binary.LittleEndian.AppendUint32(head, v)
	}
	copy(blocks[0], head)
	var out []byte
	for _, b := range blocks {
		out = append(out, b...)
	}
	return out
}

type leafWriter []byte

func (w leafWriter) u8(v uint8) leafWriter   { return append(w, v) }
func (w leafWriter) u16(v uint16) leafWriter { return binary.LittleEndian.AppendUint16(w, v) }
func (w leafWriter) u32(v uint32) leafWriter { return binary.LittleEndian.AppendUint32(w, v) }
func (w leafWriter) str(s string) leafWriter { return append(append(w, s...), 0) }

func (w leafWriter) num(v uint64) leafWriter {
	switch {
	case v < leafNumeric:
		return w.u16(uint16(v))
	case v <= 0xffff:
		return w.u16(leafUShort).u16(uint16(v))
	case v <= 0xffffffff:
		return w.u16(leafULong).u32(uint32(v))
	}
	return binary.LittleEndian.AppendUint64(w.u16(leafUQuadword), v)
}

// pad aligns a member list entry to 4 bytes with LF_PAD bytes counting down.
func (w leafWriter) pad() leafWriter {
	for n := (4 - len(w)%4) % 4; n > 0; n-- {
		w = append(w, padLeafFirst|byte(n))
	}
	return w
}

func typeRecord(kind uint16, body leafWriter) []byte {
	rec := leafWriter(nil).u16(kind)
	rec = append(rec, body...)
	return append(leafWriter(nil).u16(uint16(len(rec))), rec...)
}

func structRecord(kind uint16, name string, size uint64, fields uint32, property uint16) []byte {
	w := leafWriter(nil).u16(0).u16(property).u32(fields)
	if kind != lfUnion {
		w = w.u32(0).u32(0)
	}
	return typeRecord(kind, w.num(size).str(name))
}

func enumRecord(name string, underlying, fields uint32, property uint16) []byte {
	return typeRecord(lfEnum, leafWriter(nil).u16(0).u16(property).u32(underlying).u32(fields).str(name))
}

type memberSpec struct {
	name   string
	typ    uint32
	offset uint64
}

func memberList(members ...memberSpec) []byte {
	var w leafWriter
	for _, m := range members {
		w = w.u16(lfMember).u16(3).u32(m.typ).num(m.offset).str(m.name).pad()
	}
	return typeRecord(lfFieldList, w)
}

func pointerRecord(referent uint32, size uint32) []byte {
	return typeRecord(lfPointer, leafWriter(nil).u32(referent).u32(0x0c|size<<13))
}

func arrayRecord(elem uint32, bytes uint64) []byte {
	return typeRecord(lfArray, leafWriter(nil).u32(elem).u32(0x23).num(bytes).str(""))
}

func typeStreamOf(records ...[]byte) []byte {
	var data []byte
	for _, r := range records {
		data = append(data, r...)
	}
	h := leafWriter(nil).u32(20040203).u32(typeHeaderMin).u32(0x1000).u32(0x1000 + uint32(len(records))).u32(uint32(len(data)))
	h = h.u16(noStreamIndex).u16(noStreamIndex)
	h = append(h, make([]byte, typeHeaderMin-len(h))...)
	return append(h, data...)
}

type procedureSpec struct {
	name    string
	segment uint16
	offset  uint32
}

func moduleStreamOf(procs ...procedureSpec) ([]byte, []uint32) {
	s := leafWriter(nil).u32(4)
	var at []uint32
	for _, p := range procs {
		at = append(at, uint32(len(s)))
		body := leafWriter(nil).u16(sLProc32).u32(0).u32(0).u32(0).u32(0x10).u32(0).u32(0).u32(0).u32(p.offset).u16(p.segment).u8(0).str(p.name)
		s = append(s.u16(uint16(len(body))), body...)
	}
	return s, at
}

type publicSpec struct {
	kind    uint16
	name    string
	segment uint16
	offset  uint32
	module  uint16
}

func symbolRecordsOf(publics ...publicSpec) []byte {
	var s leafWriter
	for _, p := range publics {
		var body leafWriter
		switch p.kind {
		case sLProcRef, sProcRef:
			body = leafWriter(nil).u16(p.kind).u32(0).u32(p.offset).u16(p.module).str(p.name)
		default:
			body = leafWriter(nil).u16(p.kind).u32(0).u32(p.offset).u16(p.segment).str(p.name)
		}
		s = append(s.u16(uint16(len(body))), body...)
	}
	return s
}

func sectionHeadersOf(vas ...uint32) []byte {
	var out []byte
	for _, va := range vas {
		h := make([]byte, sectionHeaderBytes)
		binary.LittleEndian.PutUint32(h[sectionVAAt:], va)
		out = append(out, h...)
	}
	return out
}

// pdbFixture names its streams by role; stream numbers are given when the
// fixture is written.
type pdbFixture struct {
	guid      [16]byte
	age       uint32
	machine   uint16
	types     [][]byte
	publics   []publicSpec
	modules   [][]procedureSpec
	sections  []uint32
	original  []uint32
	omap      [][2]uint32
	blockSize uint32
}

func newFixture() pdbFixture {
	return pdbFixture{
		guid:      [16]byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8},
		age:       3,
		machine:   machineAMD64,
		sections:  []uint32{0x1000, 0x5000},
		blockSize: 512,
	}
}

func (f pdbFixture) fingerprint() *Fingerprint {
	return &Fingerprint{PDBName: "fixture.pdb", GUID: formatGUID(f.guid[:]), Age: f.age}
}

func (f pdbFixture) streams() [][]byte {
	streams := make([][]byte, 5)
	info := leafWriter(nil).u32(20000404).u32(0).u32(f.age + 1)
	streams[pdbInfoStream] = append(append(info, f.guid[:]...), make([]byte, 8)...)
	streams[pdbTypeStream] = typeStreamOf(f.types...)
	streams[4] = typeStreamOf()
	add := func(s []byte) uint16 {
		streams = append(streams, s)
		return uint16(len(streams) - 1)
	}
	var moduleInfo leafWriter
	for _, procs := range f.modules {
		s, _ := moduleStreamOf(procs...)
		index := add(s)
		entry := make(leafWriter, moduleEntryFixed)
		binary.LittleEndian.PutUint16(entry[moduleSymStreamAt:], index)
		binary.LittleEndian.PutUint32(entry[moduleSymBytesAt:], uint32(len(s)))
		entry = entry.str("module.obj").str("module.obj")
		for len(entry)%4 != 0 {
			entry = append(entry, 0)
		}
		moduleInfo = append(moduleInfo, entry...)
	}
	slots := make([]uint16, 11)
	for i := range slots {
		slots[i] = noStreamIndex
	}
	slots[slotSectionHeaders] = add(sectionHeadersOf(f.sections...))
	if f.original != nil {
		slots[slotOriginalSections] = add(sectionHeadersOf(f.original...))
	}
	if f.omap != nil {
		var m leafWriter
		for _, e := range f.omap {
			m = m.u32(e[0]).u32(e[1])
		}
		slots[slotOMAPFromSource] = add(m)
	}
	records := add(symbolRecordsOf(f.publics...))
	var optional leafWriter
	for _, s := range slots {
		optional = optional.u16(s)
	}
	dbi := leafWriter(nil).u32(debugVersionSignature).u32(19990903).u32(f.age)
	dbi = dbi.u16(noStreamIndex).u16(0).u16(noStreamIndex).u16(0).u16(records).u16(0)
	dbi = dbi.u32(uint32(len(moduleInfo))).u32(0).u32(0).u32(0).u32(0).u32(0).u32(uint32(len(optional))).u32(0)
	dbi = dbi.u16(0).u16(f.machine).u32(0)
	dbi = append(dbi, moduleInfo...)
	streams[pdbDebugStream] = append(dbi, optional...)
	return streams
}

func (f pdbFixture) file() []byte { return writeMSF(f.blockSize, f.streams()) }

func (f pdbFixture) convert(t *testing.T) map[string]uint64 {
	t.Helper()
	d, err := pdbToDeclaration(f.file(), f.fingerprint(), 0)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	out := map[string]uint64{}
	for _, a := range d.Addresses {
		out[a.Name] = a.Address
	}
	return out
}
