package minidump

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

type Audit struct {
	Size            uint64
	NumberOfStreams uint32
	Streams         []StreamRecord
	Problems        []string
}

func (a Audit) OK() bool { return len(a.Problems) == 0 }

func Validate(data []byte) Audit {
	return ValidateReaderAt(bytes.NewReader(data), int64(len(data)))
}

// The memory data is never read, so a dump far larger than memory can be
// checked from its file.
func ValidateReaderAt(r io.ReaderAt, size int64) Audit {
	c := &checker{r: r, size: uint64(max(size, 0)), first: map[string]string{}, count: map[string]int{}}
	c.run()
	for _, k := range c.order {
		msg := c.first[k]
		if n := c.count[k]; n > 1 {
			msg += fmt.Sprintf(" (and %d more)", n-1)
		}
		c.audit.Problems = append(c.audit.Problems, msg)
	}
	return c.audit
}

// Bounds what one read holds when a stream claims a long array.
const entryBlock = 0x10000

type extent struct {
	lo, hi uint64
	what   string
}

type infoRange struct {
	base, size uint64
	state      uint32
}

type checker struct {
	r     io.ReaderAt
	size  uint64
	audit Audit

	order []string
	first map[string]string
	count map[string]int

	extents  []extent
	streams  map[StreamType]StreamRecord
	arch     uint16
	haveArch bool
	mem      []span
	memEnd   uint64
	infos    []infoRange
	threads  map[uint32]bool
}

func (c *checker) fail(rule, format string, args ...any) {
	if c.count[rule] == 0 {
		c.order = append(c.order, rule)
		c.first[rule] = fmt.Sprintf(format, args...)
	}
	c.count[rule]++
}

func (c *checker) inside(off, n uint64) bool { return off <= c.size && n <= c.size-off }

func (c *checker) read(off, n uint64) ([]byte, bool) {
	if !c.inside(off, n) {
		return nil, false
	}
	b := make([]byte, n)
	if _, err := c.r.ReadAt(b, int64(off)); err != nil && err != io.EOF {
		return nil, false
	}
	return b, true
}

func (c *checker) entries(off, n, size uint64, fn func(i uint64, e []byte)) bool {
	per := max(entryBlock/size, 1)
	for i := uint64(0); i < n; i += per {
		k := min(per, n-i)
		b, ok := c.read(off+i*size, k*size)
		if !ok {
			return false
		}
		for j := uint64(0); j < k; j++ {
			fn(i+j, b[j*size:(j+1)*size])
		}
	}
	return true
}

func le16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func le64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }

func (c *checker) run() {
	c.audit.Size = c.size
	h, ok := c.read(0, headerSize)
	if !ok {
		c.fail("header", "header: file is %d bytes, under %d", c.size, headerSize)
		return
	}
	if s := le32(h, 0); s != Signature {
		c.fail("signature", "header: signature 0x%08x", s)
	}
	if v := le32(h, 4) & 0xFFFF; v != VersionLow {
		c.fail("version", "header: version low word 0x%04x", v)
	}
	n, dirRVA, flags := le32(h, 8), uint64(le32(h, 12)), le64(h, 24)
	c.audit.NumberOfStreams = n
	c.extents = append(c.extents, extent{0, headerSize, "header"})
	if !c.inside(dirRVA, uint64(n)*directoryEntry) {
		c.fail("directory", "directory at 0x%x: %d entries pass the end of the file", dirRVA, n)
		return
	}
	c.extents = append(c.extents, extent{dirRVA, dirRVA + uint64(n)*directoryEntry, "directory"})
	c.streams = map[StreamType]StreamRecord{}
	c.entries(dirRVA, uint64(n), directoryEntry, func(_ uint64, e []byte) {
		rec := StreamRecord{Type: StreamType(le32(e, 0)), Size: le32(e, 4), RVA: le32(e, 8)}
		c.audit.Streams = append(c.audit.Streams, rec)
		if rec.Type == StreamUnused && rec.Size == 0 {
			return
		}
		if !c.inside(uint64(rec.RVA), uint64(rec.Size)) {
			c.fail("location", "%s at 0x%x: 0x%x bytes pass the end of the file", rec.Type, rec.RVA, rec.Size)
			return
		}
		if rec.Size > 0 {
			c.extents = append(c.extents, extent{uint64(rec.RVA), uint64(rec.RVA) + uint64(rec.Size), rec.Type.String()})
		}
		if _, dup := c.streams[rec.Type]; dup && rec.Type != StreamUnused {
			c.fail("duplicate", "%s at 0x%x: second stream of this type", rec.Type, rec.RVA)
			return
		}
		c.streams[rec.Type] = rec
	})

	if rec, ok := c.streams[StreamSystemInfo]; ok {
		c.systemInfo(rec)
	} else {
		c.fail("systeminfo", "no SystemInfoStream")
	}
	for _, step := range []struct {
		t  StreamType
		fn func(StreamRecord)
	}{
		{StreamMemory64List, c.memory64},
		{StreamMemoryInfoList, c.memoryInfo},
		{StreamModuleList, c.modules},
		{StreamThreadList, c.threadList},
		{StreamThreadInfoList, c.threadInfo},
		{StreamHandleData, c.handles},
	} {
		if rec, ok := c.streams[step.t]; ok {
			step.fn(rec)
		}
	}
	for t := range c.streams {
		if f := flagFor(t); f != 0 && flags&f == 0 {
			c.fail("flags", "header: flags 0x%x lack 0x%x for %s", flags, f, t)
		}
	}
	c.overlaps()
	c.memoryCommitted()
}

func (c *checker) overlaps() {
	sort.Slice(c.extents, func(i, j int) bool { return c.extents[i].lo < c.extents[j].lo })
	for i := 1; i < len(c.extents); i++ {
		if c.extents[i].lo < c.extents[i-1].hi {
			c.fail("overlap", "%s at 0x%x: overlaps %s at 0x%x", c.extents[i].what, c.extents[i].lo, c.extents[i-1].what, c.extents[i-1].lo)
		}
	}
}

func (c *checker) str(what string, rva uint32) {
	h, ok := c.read(uint64(rva), 4)
	if !ok {
		c.fail("string", "%s string at 0x%x: length passes the end of the file", what, rva)
		return
	}
	n := uint64(le32(h, 0))
	if n%2 != 0 {
		c.fail("string", "%s string at 0x%x: odd length %d", what, rva, n)
		return
	}
	nul, ok := c.read(uint64(rva)+4+n, 2)
	if !ok {
		c.fail("string", "%s string at 0x%x: %d bytes and terminator pass the end of the file", what, rva, n)
		return
	}
	if le16(nul, 0) != 0 {
		c.fail("string", "%s string at 0x%x: no terminating NUL", what, rva)
	}
}

func (c *checker) location(what string, b []byte, off int) {
	size, rva := uint64(le32(b, off)), uint64(le32(b, off+4))
	if size > 0 && !c.inside(rva, size) {
		c.fail("location", "%s at 0x%x: 0x%x bytes pass the end of the file", what, rva, size)
	}
}

func (c *checker) systemInfo(rec StreamRecord) {
	if rec.Size < systemInfoSize {
		c.fail("size", "%s at 0x%x: %d bytes, under %d", rec.Type, rec.RVA, rec.Size, systemInfoSize)
		return
	}
	b, _ := c.read(uint64(rec.RVA), systemInfoSize)
	c.arch, c.haveArch = le16(b, 0), true
	c.str("CSDVersion", le32(b, 24))
}

func (c *checker) list(rec StreamRecord, entry uint64) (uint64, bool) {
	if rec.Size < listCountSize {
		c.fail("size", "%s at 0x%x: %d bytes, no count", rec.Type, rec.RVA, rec.Size)
		return 0, false
	}
	b, _ := c.read(uint64(rec.RVA), listCountSize)
	n := uint64(le32(b, 0))
	if n > (uint64(rec.Size)-listCountSize)/entry {
		c.fail("size", "%s at 0x%x: %d entries of %d bytes do not fit %d bytes", rec.Type, rec.RVA, n, entry, rec.Size)
		return 0, false
	}
	return n, true
}

// The three list headers that state their own sizes: the header and entry may
// grow in later versions, never shrink.
func (c *checker) sizedList(rec StreamRecord, headerMin, entryMin uint64, wide bool) (hdr, entry, n uint64, ok bool) {
	fixed := uint64(12)
	if wide {
		fixed = 16
	}
	if uint64(rec.Size) < fixed {
		c.fail("size", "%s at 0x%x: %d bytes, under its header", rec.Type, rec.RVA, rec.Size)
		return 0, 0, 0, false
	}
	b, _ := c.read(uint64(rec.RVA), fixed)
	hdr, entry = uint64(le32(b, 0)), uint64(le32(b, 4))
	if wide {
		n = le64(b, 8)
	} else {
		n = uint64(le32(b, 8))
	}
	switch {
	case hdr < headerMin || entry < entryMin:
		c.fail("size", "%s at 0x%x: header %d and entry %d bytes, under %d and %d", rec.Type, rec.RVA, hdr, entry, headerMin, entryMin)
		return 0, 0, 0, false
	case hdr > uint64(rec.Size) || n > (uint64(rec.Size)-hdr)/entry:
		c.fail("size", "%s at 0x%x: %d entries of %d bytes after %d do not fit %d bytes", rec.Type, rec.RVA, n, entry, hdr, rec.Size)
		return 0, 0, 0, false
	}
	return hdr, entry, n, true
}

func (c *checker) memory64(rec StreamRecord) {
	if rec.Size < memory64HeaderSize {
		c.fail("size", "%s at 0x%x: %d bytes, under its header", rec.Type, rec.RVA, rec.Size)
		return
	}
	b, _ := c.read(uint64(rec.RVA), memory64HeaderSize)
	n, base := le64(b, 0), le64(b, 8)
	if n > (uint64(rec.Size)-memory64HeaderSize)/memory64EntrySize {
		c.fail("size", "%s at 0x%x: %d ranges do not fit %d bytes", rec.Type, rec.RVA, n, rec.Size)
		return
	}
	cursor, prevEnd, broken := base, uint64(0), false
	c.entries(uint64(rec.RVA)+memory64HeaderSize, n, memory64EntrySize, func(i uint64, e []byte) {
		start, size := le64(e, 0), le64(e, 8)
		if broken {
			return
		}
		if size > ^uint64(0)-start {
			c.fail("range", "memory range %d at 0x%x: 0x%x bytes pass the end of the address space", i, start, size)
			broken = true
			return
		}
		if i > 0 && start < prevEnd {
			c.fail("range", "memory range %d at 0x%x: below the end 0x%x of the range before it", i, start, prevEnd)
		}
		if !c.inside(cursor, size) {
			c.fail("range", "memory range %d at 0x%x: data at 0x%x passes the end of the file", i, start, cursor)
			broken = true
			return
		}
		c.mem = append(c.mem, span{address: start, size: size, rva: cursor})
		prevEnd, cursor = start+size, cursor+size
	})
	if !broken && cursor > base {
		c.extents = append(c.extents, extent{base, cursor, "memory data"})
	}
	c.memEnd = cursor
}

func (c *checker) memoryInfo(rec StreamRecord) {
	hdr, entry, n, ok := c.sizedList(rec, memoryInfoHeaderSize, memoryInfoSize, true)
	if !ok {
		return
	}
	prevEnd := uint64(0)
	c.entries(uint64(rec.RVA)+hdr, n, entry, func(i uint64, e []byte) {
		base, size := le64(e, 0), le64(e, 24)
		state, typ := le32(e, 32), le32(e, 40)
		switch {
		case size == 0 || size > ^uint64(0)-base:
			c.fail("info", "memory info %d at 0x%x: size 0x%x is empty or passes the end of the address space", i, base, size)
			return
		case i > 0 && base < prevEnd:
			c.fail("info", "memory info %d at 0x%x: below the end 0x%x of the entry before it", i, base, prevEnd)
		}
		if !knownState(state) {
			c.fail("state", "memory info %d at 0x%x: state 0x%x", i, base, state)
		} else if state != MemFree && !knownType(typ) {
			c.fail("state", "memory info %d at 0x%x: type 0x%x", i, base, typ)
		}
		c.infos = append(c.infos, infoRange{base: base, size: size, state: state})
		prevEnd = base + size
	})
}

// A reserved or free page has no storage, so memory data for it has no
// source.
func (c *checker) memoryCommitted() {
	if _, ok := c.streams[StreamMemoryInfoList]; !ok || len(c.mem) == 0 {
		return
	}
	infos := c.infos
	sort.Slice(infos, func(i, j int) bool { return infos[i].base < infos[j].base })
	j := 0
	for i, m := range c.mem {
		at, end := m.address, m.address+m.size
		for at < end {
			for j < len(infos) && infos[j].base+infos[j].size <= at {
				j++
			}
			if j >= len(infos) || infos[j].base > at || infos[j].state != MemCommit {
				c.fail("committed", "memory range %d at 0x%x: 0x%x is not in a committed memory info entry", i, m.address, at)
				break
			}
			at = infos[j].base + infos[j].size
		}
	}
}

func (c *checker) modules(rec StreamRecord) {
	n, ok := c.list(rec, moduleSize)
	if !ok {
		return
	}
	c.entries(uint64(rec.RVA)+listCountSize, n, moduleSize, func(i uint64, e []byte) {
		c.str(fmt.Sprintf("module %d name", i), le32(e, 20))
		c.location(fmt.Sprintf("module %d CodeView record", i), e, 24+fixedFileInfoSize)
		c.location(fmt.Sprintf("module %d misc record", i), e, 24+fixedFileInfoSize+locationSize)
	})
}

func (c *checker) threadList(rec StreamRecord) {
	n, ok := c.list(rec, threadSize)
	if !ok {
		return
	}
	if n == 0 {
		c.fail("threads", "%s at 0x%x: no thread", rec.Type, rec.RVA)
	}
	c.threads = map[uint32]bool{}
	c.entries(uint64(rec.RVA)+listCountSize, n, threadSize, func(i uint64, e []byte) {
		id := le32(e, 0)
		c.threads[id] = true
		c.stack(id, e)
		c.context(id, e)
	})
}

func (c *checker) stack(id uint32, e []byte) {
	start := le64(e, 24)
	size, rva := uint64(le32(e, 32)), uint64(le32(e, 36))
	if size == 0 {
		return
	}
	if !c.inside(rva, size) {
		c.fail("stack", "thread %d stack at 0x%x: 0x%x bytes at 0x%x pass the end of the file", id, start, size, rva)
		return
	}
	if len(c.mem) == 0 || rva < c.mem[0].rva || rva >= c.memEnd {
		return
	}
	i := sort.Search(len(c.mem), func(i int) bool { return c.mem[i].rva+c.mem[i].size > rva })
	if i == len(c.mem) || c.mem[i].address+(rva-c.mem[i].rva) != start {
		c.fail("stack", "thread %d stack at 0x%x: rva 0x%x holds another address in the memory data", id, start, rva)
	}
}

func (c *checker) context(id uint32, e []byte) {
	size, rva := uint64(le32(e, 40)), uint64(le32(e, 44))
	if size == 0 {
		return
	}
	if !c.inside(rva, size) {
		c.fail("context", "thread %d context at 0x%x: 0x%x bytes pass the end of the file", id, rva, size)
		return
	}
	if !c.haveArch || c.arch != ProcessorArchitectureAMD64 {
		return
	}
	if size < ContextAMD64Size {
		c.fail("context", "thread %d context at 0x%x: %d bytes, under %d", id, rva, size, ContextAMD64Size)
		return
	}
	b, _ := c.read(rva+ctxFlags, 4)
	if f := le32(b, 0); f&ContextAMD64 == 0 {
		c.fail("context", "thread %d context at 0x%x: flags 0x%x lack 0x%x", id, rva, f, ContextAMD64)
	}
}

func (c *checker) threadInfo(rec StreamRecord) {
	hdr, entry, n, ok := c.sizedList(rec, threadInfoHeaderSize, threadInfoSize, false)
	if !ok {
		return
	}
	c.entries(uint64(rec.RVA)+hdr, n, entry, func(i uint64, e []byte) {
		if id := le32(e, 0); c.threads != nil && !c.threads[id] {
			c.fail("threadinfo", "thread info %d: thread %d is not in the thread list", i, id)
		}
	})
}

func (c *checker) handles(rec StreamRecord) {
	if rec.Size >= handleHeaderSize {
		b, _ := c.read(uint64(rec.RVA)+4, 4)
		if entry := le32(b, 0); entry != handleDescriptorSize && entry != handleDescriptor2 {
			c.fail("size", "%s at 0x%x: descriptor of %d bytes, not %d or %d", rec.Type, rec.RVA, entry, handleDescriptorSize, handleDescriptor2)
			return
		}
	}
	hdr, entry, n, ok := c.sizedList(rec, handleHeaderSize, handleDescriptorSize, false)
	if !ok {
		return
	}
	b, _ := c.read(uint64(rec.RVA)+12, 4)
	if r := le32(b, 0); r != 0 {
		c.fail("reserved", "%s at 0x%x: reserved 0x%x", rec.Type, rec.RVA, r)
	}
	c.entries(uint64(rec.RVA)+hdr, n, entry, func(i uint64, e []byte) {
		if rva := le32(e, 8); rva != 0 {
			c.str(fmt.Sprintf("handle %d type", i), rva)
		}
		if rva := le32(e, 12); rva != 0 {
			c.str(fmt.Sprintf("handle %d object", i), rva)
		}
		if entry == handleDescriptor2 {
			if rva := uint64(le32(e, 32)); rva != 0 && rva >= c.size {
				c.fail("location", "handle %d object information at 0x%x: past the end of the file", i, rva)
			}
		}
	})
}
