package minidump

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/extract"
)

var (
	ErrTooLarge         = errors.New("minidump: streams pass the 32-bit rva limit")
	ErrNoMemoryReader   = errors.New("minidump: dumpable region without a memory reader")
	ErrRegionRange      = errors.New("minidump: region is empty or passes the end of the address space")
	ErrRegionOverlap    = errors.New("minidump: regions overlap")
	ErrRegionAttributes = errors.New("minidump: region state or type is not a defined value")
	ErrModuleTooLarge   = errors.New("minidump: module size does not fit 32 bits")
)

const (
	maxRVA = uint64(1) << 32
	// Bounds the region bytes held at once; a page multiple, so the caller's
	// per-page gaps are not split.
	readChunk = 0x100000
)

type SystemInfo struct {
	ProcessorArchitecture uint16
	ProcessorLevel        uint16
	ProcessorRevision     uint16
	NumberOfProcessors    uint8
	ProductType           uint8
	MajorVersion          uint32
	MinorVersion          uint32
	BuildNumber           uint32
	PlatformID            uint32
	SuiteMask             uint16
	CSDVersion            string
}

type Module struct {
	Base          uint64
	Size          uint64
	Name          string
	TimeDateStamp uint32
	CheckSum      uint32
}

type Thread struct {
	ID            uint32
	SuspendCount  uint32
	PriorityClass uint32
	Priority      uint32
	Teb           uint64
	// StackBase is the low end, as StartOfMemoryRange requires. _NT_TIB.StackBase
	// is the high end, so do not copy it here.
	StackBase    uint64
	StackSize    uint64
	Context      []byte
	Affinity     uint64
	StartAddress uint64
	CreateTime   uint64
	ExitTime     uint64
	KernelTime   uint64
	UserTime     uint64
	ExitStatus   uint32
	DumpError    uint32
}

type Handle struct {
	Handle        uint64
	TypeName      string
	ObjectName    string
	Attributes    uint32
	GrantedAccess uint32
	HandleCount   uint32
	PointerCount  uint32
}

type Region struct {
	BaseAddress       uint64
	AllocationBase    uint64
	Size              uint64
	Protect           uint32
	AllocationProtect uint32
	State             uint32
	Type              uint32
	Dumpable          bool
}

// Gaps are absolute addresses, as extract.ReadPadded returns them.
type ReadFunc func(base, size uint64) ([]byte, extract.GapMap)

type Input struct {
	System        SystemInfo
	Modules       []Module
	Threads       []Thread
	Handles       []Handle
	Regions       []Region
	ReadMemory    ReadFunc
	TimeDateStamp uint32
}

type Result struct {
	Size        uint64
	Streams     []StreamRecord
	MemoryBytes uint64
	MemoryGaps  extract.GapMap
}

type StreamRecord struct {
	Type StreamType
	RVA  uint32
	Size uint32
}

type span struct{ address, size, rva uint64 }

// Every RVA points forward, so the streams are built in memory first. The
// memory bytes come last, behind the 64-bit BaseRva, and are copied a chunk
// at a time. After an error w holds a partial file: discard it.
func Write(w io.Writer, in Input) (Result, error) {
	regions, err := checkInput(in)
	if err != nil {
		return Result{}, err
	}
	b := &builder{buf: make([]byte, headerSize), strings: map[string]uint32{}}
	var dir []StreamRecord
	stream := func(t StreamType, size int) int {
		off := b.alloc(size, streamAlign)
		dir = append(dir, StreamRecord{Type: t, RVA: uint32(off), Size: uint32(size)})
		return off
	}

	// A dump without a thread does not open in the Windows debugging tools,
	// so a process with none gets the documented placeholder thread.
	list, placeholder := in.Threads, len(in.Threads) == 0
	if placeholder {
		list = []Thread{{}}
	}
	count := 4 + boolInt(len(in.Handles) > 0) + boolInt(len(regions) > 0) + 1
	b.alloc(count*directoryEntry, 4)

	sys := stream(StreamSystemInfo, systemInfoSize)
	mods := stream(StreamModuleList, listCountSize+len(in.Modules)*moduleSize)
	threads := stream(StreamThreadList, listCountSize+len(list)*threadSize)
	threadInfo := stream(StreamThreadInfoList, threadInfoHeaderSize+len(list)*threadInfoSize)
	handles, infos := -1, -1
	if len(in.Handles) > 0 {
		handles = stream(StreamHandleData, handleHeaderSize+len(in.Handles)*handleDescriptorSize)
	}
	if len(regions) > 0 {
		infos = stream(StreamMemoryInfoList, memoryInfoHeaderSize+len(regions)*memoryInfoSize)
	}

	b.systemInfo(sys, in.System)
	b.modules(mods, in.Modules)
	b.threads(threads, list)
	b.threadInfo(threadInfo, list, placeholder)
	if handles >= 0 {
		b.handles(handles, in.Handles)
	}
	if infos >= 0 {
		b.memoryInfo(infos, regions)
	}

	var written []span
	for _, r := range regions {
		if r.Dumpable && r.State == MemCommit {
			written = append(written, span{address: r.BaseAddress, size: r.Size})
		}
	}
	mem := stream(StreamMemory64List, memory64HeaderSize+len(written)*memory64EntrySize)
	if uint64(len(b.buf)) > maxRVA || b.overflow {
		return Result{}, fmt.Errorf("%w: 0x%x bytes before the memory data", ErrTooLarge, len(b.buf))
	}
	cursor := uint64(len(b.buf))
	b.put64(mem, uint64(len(written)))
	b.put64(mem+8, cursor)
	for i := range written {
		written[i].rva = cursor
		b.put64(mem+memory64HeaderSize+i*memory64EntrySize, written[i].address)
		b.put64(mem+memory64HeaderSize+i*memory64EntrySize+8, written[i].size)
		cursor += written[i].size
	}
	b.stacks(threads, list, written)
	b.header(dir, in.TimeDateStamp)

	res := Result{Streams: dir}
	if _, err := w.Write(b.buf); err != nil {
		return res, err
	}
	res.Size = uint64(len(b.buf))
	var gaps extract.Coverage
	for _, s := range written {
		for off := uint64(0); off < s.size; {
			n := min(readChunk, s.size-off)
			data := readRange(in.ReadMemory, s.address+off, n, &gaps)
			if _, err := w.Write(data); err != nil {
				return res, err
			}
			res.Size += n
			off += n
		}
	}
	res.MemoryGaps = gaps.Covered()
	res.MemoryBytes = cursor - uint64(len(b.buf)) - gaps.Bytes()
	return res, nil
}

func checkInput(in Input) ([]Region, error) {
	for _, m := range in.Modules {
		if m.Size > 0xFFFFFFFF {
			return nil, fmt.Errorf("%w: %s at 0x%x, 0x%x bytes", ErrModuleTooLarge, m.Name, m.Base, m.Size)
		}
	}
	regions := slices.Clone(in.Regions)
	slices.SortStableFunc(regions, func(a, b Region) int {
		switch {
		case a.BaseAddress < b.BaseAddress:
			return -1
		case a.BaseAddress > b.BaseAddress:
			return 1
		}
		return 0
	})
	for i, r := range regions {
		if r.Size == 0 || r.Size > ^uint64(0)-r.BaseAddress {
			return nil, fmt.Errorf("%w: 0x%x, 0x%x bytes", ErrRegionRange, r.BaseAddress, r.Size)
		}
		if i > 0 && r.BaseAddress < regions[i-1].BaseAddress+regions[i-1].Size {
			return nil, fmt.Errorf("%w: 0x%x starts inside 0x%x", ErrRegionOverlap, r.BaseAddress, regions[i-1].BaseAddress)
		}
		if !knownState(r.State) || (r.State != MemFree && !knownType(r.Type)) {
			return nil, fmt.Errorf("%w: 0x%x, state 0x%x, type 0x%x", ErrRegionAttributes, r.BaseAddress, r.State, r.Type)
		}
		if r.Dumpable && r.State == MemCommit && in.ReadMemory == nil {
			return nil, fmt.Errorf("%w: 0x%x", ErrNoMemoryReader, r.BaseAddress)
		}
	}
	return regions, nil
}

// A reader that returns fewer or more bytes than asked would shift every
// later range, so the result is cut or padded to n and the padding is a gap.
func readRange(read ReadFunc, base, n uint64, gaps *extract.Coverage) []byte {
	data, got := read(base, n)
	if uint64(len(data)) != n {
		fixed := make([]byte, n)
		copy(fixed, data)
		if uint64(len(data)) < n {
			gaps.Add(base+uint64(len(data)), n-uint64(len(data)))
		}
		data = fixed
	}
	for _, g := range got {
		lo, hi := max(g.Start, base), min(g.Start+g.Length, base+n)
		if g.Length > 0 && g.Start+g.Length > g.Start && lo < hi {
			gaps.Add(lo, hi-lo)
		}
	}
	return data
}

type builder struct {
	buf      []byte
	strings  map[string]uint32
	overflow bool
}

func (b *builder) alloc(n, align int) int {
	for len(b.buf)%align != 0 {
		b.buf = append(b.buf, 0)
	}
	off := len(b.buf)
	b.buf = append(b.buf, make([]byte, n)...)
	if uint64(len(b.buf)) > maxRVA {
		b.overflow = true
	}
	return off
}

func (b *builder) put16(off int, v uint16) { binary.LittleEndian.PutUint16(b.buf[off:], v) }
func (b *builder) put32(off int, v uint32) { binary.LittleEndian.PutUint32(b.buf[off:], v) }
func (b *builder) put64(off int, v uint64) { binary.LittleEndian.PutUint64(b.buf[off:], v) }

// Handle type names repeat for every handle, so equal strings share one copy.
func (b *builder) str(s string) uint32 {
	if rva, ok := b.strings[s]; ok {
		return rva
	}
	units := utf16.Encode([]rune(s))
	off := b.alloc(4+2*len(units)+2, 4)
	b.put32(off, uint32(2*len(units)))
	for i, u := range units {
		b.put16(off+4+2*i, u)
	}
	b.strings[s] = uint32(off)
	return uint32(off)
}

func (b *builder) blob(p []byte) (uint32, uint32) {
	if len(p) == 0 {
		return 0, 0
	}
	off := b.alloc(len(p), streamAlign)
	copy(b.buf[off:], p)
	return uint32(len(p)), uint32(off)
}

func (b *builder) header(dir []StreamRecord, stamp uint32) {
	b.put32(0, Signature)
	b.put32(4, VersionLow)
	b.put32(8, uint32(len(dir)))
	b.put32(12, headerSize)
	b.put32(20, stamp)
	flags := MiniDumpWithFullMemory
	for i, d := range dir {
		off := headerSize + i*directoryEntry
		b.put32(off, uint32(d.Type))
		b.put32(off+4, d.Size)
		b.put32(off+8, d.RVA)
		flags |= flagFor(d.Type)
	}
	b.put64(24, flags)
}

func flagFor(t StreamType) uint64 {
	switch t {
	case StreamMemory64List:
		return MiniDumpWithFullMemory
	case StreamHandleData:
		return MiniDumpWithHandleData
	case StreamMemoryInfoList:
		return MiniDumpWithFullMemoryInfo
	case StreamThreadInfoList:
		return MiniDumpWithThreadInfo
	}
	return 0
}

func (b *builder) systemInfo(off int, s SystemInfo) {
	b.put16(off, s.ProcessorArchitecture)
	b.put16(off+2, s.ProcessorLevel)
	b.put16(off+4, s.ProcessorRevision)
	b.buf[off+6] = s.NumberOfProcessors
	b.buf[off+7] = s.ProductType
	b.put32(off+8, s.MajorVersion)
	b.put32(off+12, s.MinorVersion)
	b.put32(off+16, s.BuildNumber)
	b.put32(off+20, s.PlatformID)
	b.put32(off+24, b.str(s.CSDVersion))
	b.put16(off+28, s.SuiteMask)
}

func (b *builder) modules(off int, mods []Module) {
	b.put32(off, uint32(len(mods)))
	for i, m := range mods {
		e := off + listCountSize + i*moduleSize
		b.put64(e, m.Base)
		b.put32(e+8, uint32(m.Size))
		b.put32(e+12, m.CheckSum)
		b.put32(e+16, m.TimeDateStamp)
		b.put32(e+20, b.str(m.Name))
	}
}

func (b *builder) threads(off int, threads []Thread) {
	b.put32(off, uint32(len(threads)))
	for i, t := range threads {
		e := off + listCountSize + i*threadSize
		b.put32(e, t.ID)
		b.put32(e+4, t.SuspendCount)
		b.put32(e+8, t.PriorityClass)
		b.put32(e+12, t.Priority)
		b.put64(e+16, t.Teb)
		b.put64(e+24, t.StackBase)
		size, rva := b.blob(t.Context)
		b.put32(e+40, size)
		b.put32(e+44, rva)
	}
}

// A stack's descriptor can point into the memory data only when the whole
// stack lies in address-contiguous written ranges below the 32-bit limit;
// otherwise it carries the address alone.
func (b *builder) stacks(off int, threads []Thread, written []span) {
	for i, t := range threads {
		e := off + listCountSize + i*threadSize
		if rva, ok := stackRVA(t.StackBase, t.StackSize, written); ok {
			b.put32(e+32, uint32(t.StackSize))
			b.put32(e+36, uint32(rva))
		}
	}
}

func stackRVA(base, size uint64, written []span) (uint64, bool) {
	if size == 0 || size > 0xFFFFFFFF || size > ^uint64(0)-base {
		return 0, false
	}
	i, _ := slices.BinarySearchFunc(written, base, func(s span, a uint64) int {
		switch {
		case s.address+s.size <= a:
			return -1
		case s.address > a:
			return 1
		}
		return 0
	})
	if i >= len(written) || written[i].address > base {
		return 0, false
	}
	rva := written[i].rva + (base - written[i].address)
	end := base + size
	for j := i; ; j++ {
		if written[j].address+written[j].size >= end {
			break
		}
		if j+1 >= len(written) || written[j+1].address != written[j].address+written[j].size {
			return 0, false
		}
	}
	if rva+size > maxRVA {
		return 0, false
	}
	return rva, true
}

func (b *builder) threadInfo(off int, threads []Thread, placeholder bool) {
	b.put32(off, threadInfoHeaderSize)
	b.put32(off+4, threadInfoSize)
	b.put32(off+8, uint32(len(threads)))
	for i, t := range threads {
		e := off + threadInfoHeaderSize + i*threadInfoSize
		var flags uint32
		if placeholder {
			flags |= threadInfoErrorThread
		}
		if t.ExitTime != 0 {
			flags |= threadInfoExited
		}
		if len(t.Context) == 0 {
			flags |= threadInfoInvalidContext
		}
		if t.Teb == 0 {
			flags |= threadInfoInvalidTEB
		}
		b.put32(e, t.ID)
		b.put32(e+4, flags)
		b.put32(e+8, t.DumpError)
		b.put32(e+12, t.ExitStatus)
		b.put64(e+16, t.CreateTime)
		b.put64(e+24, t.ExitTime)
		b.put64(e+32, t.KernelTime)
		b.put64(e+40, t.UserTime)
		b.put64(e+48, t.StartAddress)
		b.put64(e+56, t.Affinity)
	}
}

func (b *builder) handles(off int, handles []Handle) {
	b.put32(off, handleHeaderSize)
	b.put32(off+4, handleDescriptorSize)
	b.put32(off+8, uint32(len(handles)))
	for i, h := range handles {
		e := off + handleHeaderSize + i*handleDescriptorSize
		b.put64(e, h.Handle)
		if h.TypeName != "" {
			b.put32(e+8, b.str(h.TypeName))
		}
		if h.ObjectName != "" {
			b.put32(e+12, b.str(h.ObjectName))
		}
		b.put32(e+16, h.Attributes)
		b.put32(e+20, h.GrantedAccess)
		b.put32(e+24, h.HandleCount)
		b.put32(e+28, h.PointerCount)
	}
}

func (b *builder) memoryInfo(off int, regions []Region) {
	b.put32(off, memoryInfoHeaderSize)
	b.put32(off+4, memoryInfoSize)
	b.put64(off+8, uint64(len(regions)))
	for i, r := range regions {
		e := off + memoryInfoHeaderSize + i*memoryInfoSize
		b.put64(e, r.BaseAddress)
		b.put64(e+8, r.AllocationBase)
		b.put32(e+16, r.AllocationProtect)
		b.put64(e+24, r.Size)
		b.put32(e+32, r.State)
		b.put32(e+36, r.Protect)
		b.put32(e+40, r.Type)
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
