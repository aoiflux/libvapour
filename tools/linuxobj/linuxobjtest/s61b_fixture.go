package linuxobjtest

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const MMExeFile = 0xa0

// AddExeFile needs AddFS first: it extends the mm_struct AddFS declares.
func AddExeFile(k *Kernel) {
	mm, err := k.Table.Struct("mm_struct")
	if err != nil {
		panic(err)
	}
	mm.Fields = append(mm.Fields, symbols.Field{Name: "exe_file", Offset: MMExeFile, Type: ptr("file")})
	k.Table.AddStruct(mm)
}

type Processes struct {
	k      *Kernel
	tables map[uint64]uint64
	spaces map[uint64]*Memory
	next   uint64
}

func (k *Kernel) NewProcesses() *Processes {
	return &Processes{k: k, tables: map[uint64]uint64{}, spaces: map[uint64]*Memory{}, next: 0x100000}
}

// Add gives the task an mm whose pgd translates to a root of its own and a
// user space of its own, returned for the caller to fill.
func (p *Processes) Add(spec Task, mm MM) (task, mmAddr uint64, space *Memory) {
	pgd := p.k.Alloc(0x1000)
	mm.PGD = pgd
	mmAddr = p.k.AddMM(mm)
	spec.MM = mmAddr
	task = p.k.AddTask(spec)
	root := p.next
	p.next += 0x1000
	p.tables[pgd] = root
	space = NewMemory()
	p.spaces[root] = space
	return task, mmAddr, space
}

func (p *Processes) Context(options map[string]any) (tools.Context, *[]string) {
	ctx, diags := p.k.Context(options)
	ctx.Memory = &Translating{Memory: p.k.Mem, Tables: p.tables}
	ctx.ProcessMemory = func(dtb uint64) (memory.MemoryReader, error) {
		if s, ok := p.spaces[dtb]; ok {
			return s, nil
		}
		return nil, fmt.Errorf("no process space at %#x", dtb)
	}
	return ctx, diags
}

type Segment struct {
	Type                         uint32
	Offset, Vaddr, Filesz, Memsz uint64
}

// ELF64 writes an ELF64 little-endian header and program headers at base;
// with dynamic set, a PT_DYNAMIC segment at that p_vaddr holding DT_DEBUG.
func ELF64(m *Memory, base uint64, segs []Segment, dynamic, debug uint64) {
	all := append([]Segment(nil), segs...)
	if dynamic != 0 {
		all = append(all, Segment{Type: 2, Vaddr: dynamic, Memsz: 32})
	}
	h := make([]byte, 64+56*len(all))
	copy(h, "\x7fELF\x02\x01\x01")
	le := binary.LittleEndian
	le.PutUint16(h[16:], 3)
	le.PutUint16(h[18:], 62)
	le.PutUint64(h[32:], 64)
	le.PutUint16(h[52:], 64)
	le.PutUint16(h[54:], 56)
	le.PutUint16(h[56:], uint16(len(all)))
	for i, s := range all {
		p := h[64+56*i:]
		le.PutUint32(p, s.Type)
		le.PutUint64(p[8:], s.Offset)
		le.PutUint64(p[16:], s.Vaddr)
		le.PutUint64(p[32:], s.Filesz)
		le.PutUint64(p[40:], s.Memsz)
	}
	m.Write(base, h)
	if dynamic != 0 {
		m.U64(base+dynamic, 21)
		m.U64(base+dynamic+8, debug)
		m.U64(base+dynamic+16, 0)
		m.U64(base+dynamic+24, 0)
	}
}

type LinkEntry struct {
	At, Base uint64
	Name     string
}

// LinkMap writes the debugger structure at debug and the entries in order,
// each name 0x100 bytes after its entry; an empty name has a NUL there.
func LinkMap(m *Memory, debug uint64, entries []LinkEntry) {
	m.U32(debug, 1)
	first := uint64(0)
	if len(entries) > 0 {
		first = entries[0].At
	}
	m.U64(debug+8, first)
	for i, e := range entries {
		next, prev := uint64(0), uint64(0)
		if i+1 < len(entries) {
			next = entries[i+1].At
		}
		if i > 0 {
			prev = entries[i-1].At
		}
		name := e.At + 0x100
		m.Write(name, append([]byte(e.Name), 0))
		m.U64(e.At, e.Base)
		m.U64(e.At+8, name)
		m.U64(e.At+16, 0)
		m.U64(e.At+24, next)
		m.U64(e.At+32, prev)
	}
}
