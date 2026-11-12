package testsupport

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// Member offsets are the 19045 kernel's (S79 T1 to T5, T7, T8); the 32-bit
// loader records follow S56 L1.
const (
	FixturePIDOffset         = uint64(0x440)
	FixtureActiveLinksOffset = uint64(0x448)
	FixtureImageNameOffset   = uint64(0x5a8)
	FixturePebOffset         = uint64(0x550)
	FixtureDTBOffset         = uint64(0x28)
	FixtureFlinkOffset       = uint64(0x00)
	FixtureBlinkOffset       = uint64(0x08)

	FixtureLdrOffset               = uint64(0x18)
	FixtureInLoadOrderOffset       = uint64(0x10)
	FixtureInLoadLinksOffset       = uint64(0x00)
	FixtureDllBaseOffset           = uint64(0x30)
	FixtureSizeOfImageOffset       = uint64(0x40)
	FixtureFullDllNameOffset       = uint64(0x48)
	FixtureBaseDllNameOffset       = uint64(0x58)
	FixtureObsoleteLoadCountOffset = uint64(0x6c)
	FixtureLoadTimeOffset          = uint64(0x100)
	FixtureUnicodeBufferOffset     = unicodeBufferAt

	FixtureWow64ProcessOffset = uint64(0x580)
	FixtureEwow64PebOffset    = uint64(0x00)
	FixtureParentPIDOffset    = uint64(0x540)

	FixtureObjectTableOffset       = uint64(0x570)
	FixtureNextHandleOffset        = uint64(0x00)
	FixtureTableCodeOffset         = uint64(0x08)
	FixtureObjectPointerBitsOffset = uint64(0x00)

	FixtureEntry32FullDllNameOffset = uint64(0x24)
	FixtureEntry32BaseDllNameOffset = uint64(0x2c)
	FixtureUnicode32BufferOffset    = unicodeBuffer32At

	FixtureSectionBaseOffset  = uint64(0x520)
	FixtureVadRootOffset      = uint64(0x7d8)
	FixtureVadCountOffset     = uint64(0x7e8)
	FixturePebImageBaseOffset = uint64(0x10)

	FixtureVadNodeOffset         = uint64(0x00)
	FixtureVadLeftOffset         = uint64(0x00)
	FixtureVadRightOffset        = uint64(0x08)
	FixtureVadParentOffset       = uint64(0x10)
	FixtureVadParentBalance      = uint64(0x3)
	FixtureVadStartingVpnOff     = uint64(0x18)
	FixtureVadEndingVpnOff       = uint64(0x1c)
	FixtureVadStartingVpnHighOff = uint64(0x20)
	FixtureVadEndingVpnHighOff   = uint64(0x21)
	FixtureVadFlagsOffset        = uint64(0x30)
	FixtureVadSubsectionOffset   = uint64(0x48)

	FixtureVadTypeBit          = uint8(4)
	FixtureVadTypeBits         = uint8(3)
	FixtureVadProtectionBit    = uint8(7)
	FixtureVadProtectionBits   = uint8(5)
	FixtureVadPrivateMemoryBit = uint8(20)
	// An image view (S24 M11).
	FixtureVadTypeImage = uint32(2)

	// Indexes into MmProtectToValue (M1).
	FixtureProtectionReadWrite        = uint32(4)
	FixtureProtectionExecuteReadWrite = uint32(6)
	FixtureProtectionExecuteWriteCopy = uint32(7)
)

// Sizes of the 19045 types the fixture declares (S79 T1 to T8).
const (
	fixtureEprocessSize    = uint64(0xa40)
	fixturePebSize         = uint64(0x7c8)
	fixtureLdrDataSize     = uint64(0x58)
	fixtureLdrEntrySize    = uint64(0x120)
	fixtureEwow64Size      = uint64(0x10)
	fixturePeb32Size       = uint64(0x480)
	fixtureHandleTableSize = uint64(0x80)
	fixtureHandleEntrySize = uint64(0x10)
	fixtureVadShortSize    = uint64(0x40)
	fixtureVadLongSize     = uint64(0x88)
	fixtureSubsectionSize  = uint64(0x38)
	fixtureControlAreaSize = uint64(0x80)
	fixtureFileObjectSize  = uint64(0xd8)
	fixtureObjectBody      = uint64(0x30)
	fixtureObjectHeaderLen = uint64(0x38)

	fixturePeb32LdrOffset     = uint64(0x0c)
	fixtureLdr32InLoadOrder   = uint64(0x0c)
	fixtureEntry32DllBase     = uint64(0x18)
	fixtureEntry32SizeOfImage = uint64(0x20)
	fixtureSubControlAreaOff  = uint64(0x00)
	fixtureCaFilePointerOff   = uint64(0x40)
	fixtureFoFileNameOff      = uint64(0x58)
	fixtureFileObjectType     = uint16(5)

	// _EX_FAST_REF keeps a count in the low four bits on x64 (T8); all four
	// are set so a reader that clears only three misses the object.
	fixtureFastRefBits = uint64(0xF)

	fixtureObjectPointerShift = 20
	fixtureHandleUnlocked     = uint64(1)
	// One leaf page of 256 entries spans 1,024 handle values (S66 HM3).
	fixtureHandlesPerPage = uint32(1024)
	fixtureHandleStep     = 4

	fixtureObjectHeaderOffset = uint64(PoolHeaderSize)
	fixturePooledBodyOffset   = fixtureObjectHeaderOffset + fixtureObjectBody

	// The default module size is the mapped PE fixture's.
	fixtureDefaultModuleSize = uint64(MappedPESize)
	fixturePaddingPattern    = uint32(0x5a5a5a5a)
)

// The address plan the tests across the tree place their own pages around.
const (
	FixtureProcessListHeadVA  = uint64(0xfffff80000001000)
	fixtureObHeaderCookieVA   = uint64(0xfffff80000002000)
	fixtureProtectToValueVA   = uint64(0xfffff80000003000)
	fixtureProcessBaseVA      = uint64(0xfffff80000010000)
	fixtureProcessStrideVA    = uint64(0x10000)
	fixtureVadBaseVA          = uint64(0xfffff80000200000)
	fixtureVadProcessStride   = uint64(0x00100000)
	fixtureEwow64BaseVA       = uint64(0xfffff80000900000)
	fixtureHandleTableBaseVA  = uint64(0xfffff80000a00000)
	fixtureHandleTableStride  = uint64(0x2000)
	fixturePebVA              = uint64(0x00007ff600010000)
	fixtureLdrVA              = uint64(0x00007ff600020000)
	fixtureLdrEntryBaseVA     = uint64(0x00007ff600030000)
	fixtureModuleNameBaseVA   = uint64(0x00007ff600100000)
	fixturePeb32VA            = uint64(0x60000000)
	fixtureLdr32VA            = uint64(0x61000000)
	fixtureLdr32EntryBaseVA   = uint64(0x62000000)
	fixtureModule32NameBaseVA = uint64(0x63000000)
	fixtureRecordStride       = uint64(0x2000)
)

// MmProtectToValue as all five captures hold it (M1).
var fixtureProtectToValue = [32]uint32{
	0x1, 0x2, 0x10, 0x20, 0x4, 0x8, 0x40, 0x80,
	0x1, 0x202, 0x210, 0x220, 0x204, 0x208, 0x240, 0x280,
	0x1, 0x102, 0x110, 0x120, 0x104, 0x108, 0x140, 0x180,
	0x1, 0x402, 0x410, 0x420, 0x404, 0x408, 0x440, 0x480,
}

type FixtureModule struct {
	Name      string
	FullPath  string
	Base      uint64
	Image     []byte
	Size      uint64
	LoadCount uint16
	LoadTime  uint64
}

type FixtureVAD struct {
	Start      uint64
	End        uint64
	Path       string
	Protection uint32
	Tag        string
	VadType    uint32
}

type FixtureProcess struct {
	PID                uint64
	Name               string
	Parent             uint64
	NoPeb              bool
	Modules            []FixtureModule
	Wow64Modules       []FixtureModule
	Wow64PebNull       bool
	SectionBaseAddress uint64
	ImageBaseAddress   uint64
	VADs               []FixtureVAD
	UncountedVADs      uint64
	Unlinked           bool
	Handles            int
}

type ProcessFixture struct {
	Memory *PagedMemory
	Kernel *AddressSpace
	Table  *symbols.Table

	spaces     map[uint64]*AddressSpace
	eprocesses map[uint64]eprocessPlace
	pooled     bool
}

type eprocessPlace struct{ virtual, physical uint64 }

func BuildProcessFixture(procs []FixtureProcess) *ProcessFixture {
	return buildProcessFixture(procs, false)
}

// Each _EPROCESS sits behind a pool header and an object header, as a pool
// scan finds it.
func BuildPooledProcessFixture(procs []FixtureProcess) *ProcessFixture {
	return buildProcessFixture(procs, true)
}

type fixtureFeatures struct{ memory, parents, handles bool }

func featuresOf(procs []FixtureProcess) fixtureFeatures {
	var f fixtureFeatures
	for _, p := range procs {
		f.memory = f.memory || len(p.VADs) > 0
		f.parents = f.parents || p.Parent != 0
		f.handles = f.handles || p.Handles > 0
	}
	return f
}

func buildProcessFixture(procs []FixtureProcess, pooled bool) *ProcessFixture {
	pm := NewPagedMemory(64 << 20)
	f := &ProcessFixture{Memory: pm, Kernel: pm.NewAddressSpace(), spaces: map[uint64]*AddressSpace{},
		eprocesses: map[uint64]eprocessPlace{}, pooled: pooled}
	list := newKernelList(f, FixtureProcessListHeadVA)
	for i, p := range procs {
		place := f.placeProcess(i, p.PID)
		if !p.Unlinked {
			list.append(place.virtual+FixtureActiveLinksOffset, place.physical+FixtureActiveLinksOffset)
		}
		f.writeProcess(i, p, place)
	}
	list.close()

	features := featuresOf(procs)
	if features.memory {
		f.writeProtectToValue()
	}
	f.Table = buildFixtureSymbolTable(features.memory, features.parents)
	if features.handles {
		addHandleTypes(f.Table)
	}
	if pooled {
		addPoolTypes(f.Table)
	}
	return f
}

func (f *ProcessFixture) placeProcess(i int, pid uint64) eprocessPlace {
	va := fixtureProcessBaseVA + uint64(i)*fixtureProcessStrideVA
	pa := f.Kernel.MapPage(va)
	if f.pooled {
		f.writeObjectHeaders(pa, scan.ProcessFilter.Tag, fixtureEprocessSize)
		va, pa = va+fixturePooledBodyOffset, pa+fixturePooledBodyOffset
	}
	place := eprocessPlace{virtual: va, physical: pa}
	f.eprocesses[pid] = place
	f.spaces[pid] = f.Memory.NewAddressSpace()
	return place
}

// The pool header's blocks cover both headers and the body; PointerCount 1
// is the reference a live object holds (T6, T9).
func (f *ProcessFixture) writeObjectHeaders(pa uint64, tag string, body uint64) {
	headers := make([]byte, fixturePooledBodyOffset)
	WritePoolHeader(headers, 0, tag, BlocksFor(fixturePooledBodyOffset+body), NonPagedPoolType)
	binary.LittleEndian.PutUint64(headers[fixtureObjectHeaderOffset:], 1)
	f.Memory.WriteAt(pa, headers)
}

func (f *ProcessFixture) writeProcess(i int, p FixtureProcess, place eprocessPlace) {
	pm, ep := f.Memory, place.physical
	space := f.spaces[p.PID]
	pm.WriteU64(ep+FixturePIDOffset, p.PID)
	pm.WriteU64(ep+FixtureParentPIDOffset, p.Parent)
	pm.WriteAt(ep+FixtureImageNameOffset, append([]byte(p.Name), 0))
	pm.WriteU64(ep+FixtureDTBOffset, space.DTB)
	pm.WriteU64(ep+FixtureSectionBaseOffset, p.SectionBaseAddress)
	pm.WriteU64(ep+FixtureVadCountOffset, uint64(len(p.VADs))+p.UncountedVADs)
	if len(p.VADs) > 0 {
		pm.WriteU64(ep+FixtureVadRootOffset, f.writeVadTree(i, p.VADs))
	}
	if p.Handles > 0 {
		f.writeHandleTable(i, place, p.Handles)
	}
	if p.NoPeb {
		return
	}
	pm.WriteU64(ep+FixturePebOffset, fixturePebVA)
	peb := space.MapPage(fixturePebVA)
	pm.WriteU64(peb+FixturePebImageBaseOffset, p.ImageBaseAddress)
	pm.WriteU64(peb+FixtureLdrOffset, fixtureLdrVA)
	f.writeLoader(space, native, p.Modules)
	if len(p.Wow64Modules) == 0 && !p.Wow64PebNull {
		return
	}
	ewow := fixtureEwow64BaseVA + uint64(i)*pageSize
	pm.WriteU64(ep+FixtureWow64ProcessOffset, ewow)
	ewowPA := f.Kernel.MapPage(ewow)
	if !p.Wow64PebNull {
		pm.WriteU64(ewowPA+FixtureEwow64PebOffset, fixturePeb32VA)
	}
	if len(p.Wow64Modules) > 0 {
		peb32 := space.MapPage(fixturePeb32VA)
		pm.WriteU32(peb32+fixturePeb32LdrOffset, uint32(fixtureLdr32VA))
		f.writeLoader(space, wow64, p.Wow64Modules)
	}
}

func (f *ProcessFixture) writeProtectToValue() {
	pa := f.Kernel.MapPage(fixtureProtectToValueVA)
	for i, v := range fixtureProtectToValue {
		f.Memory.WriteU32(pa+uint64(i)*4, v)
	}
}

type kernelList struct {
	pm               *PagedMemory
	head, headPA     uint64
	tail, tailPA     uint64
	write            func(pm *PagedMemory, at, v uint64)
	flinkAt, blinkAt uint64
}

func write64(pm *PagedMemory, at, v uint64) { pm.WriteU64(at, v) }
func write32(pm *PagedMemory, at, v uint64) { pm.WriteU32(at, uint32(v)) }

func newKernelList(f *ProcessFixture, head uint64) *kernelList {
	pa := f.Kernel.MapPage(head)
	return &kernelList{pm: f.Memory, head: head, headPA: pa, tail: head, tailPA: pa, write: write64,
		flinkAt: FixtureFlinkOffset, blinkAt: FixtureBlinkOffset}
}

func (l *kernelList) append(link, linkPA uint64) {
	l.write(l.pm, l.tailPA+l.flinkAt, link)
	l.write(l.pm, linkPA+l.blinkAt, l.tail)
	l.tail, l.tailPA = link, linkPA
}

func (l *kernelList) close() {
	l.write(l.pm, l.tailPA+l.flinkAt, l.head)
	l.write(l.pm, l.headPA+l.blinkAt, l.tail)
}

// One loader shape per pointer width: the native records of T4 and the
// 32-bit ones of S56 L1, each string a UNICODE_STRING of that width.
type loaderShape struct {
	ldr, entries, names, listHead uint64
	dllBase, sizeOfImage          uint64
	fullName, baseName            uint64
	blink                         uint64
	write                         func(pm *PagedMemory, at, v uint64)
	defaultDir                    string
	stringWriter                  func(f *ProcessFixture, as *AddressSpace, structPA, bufferVA uint64, s string)
	extras                        bool
}

var native = loaderShape{
	ldr: fixtureLdrVA, entries: fixtureLdrEntryBaseVA, names: fixtureModuleNameBaseVA, listHead: FixtureInLoadOrderOffset,
	dllBase: FixtureDllBaseOffset, sizeOfImage: FixtureSizeOfImageOffset,
	fullName: FixtureFullDllNameOffset, baseName: FixtureBaseDllNameOffset, blink: FixtureBlinkOffset,
	write: write64, defaultDir: `C:\Windows\System32\`, stringWriter: (*ProcessFixture).writeUnicodeString, extras: true,
}

var wow64 = loaderShape{
	ldr: fixtureLdr32VA, entries: fixtureLdr32EntryBaseVA, names: fixtureModule32NameBaseVA, listHead: fixtureLdr32InLoadOrder,
	dllBase: fixtureEntry32DllBase, sizeOfImage: fixtureEntry32SizeOfImage,
	fullName: FixtureEntry32FullDllNameOffset, baseName: FixtureEntry32BaseDllNameOffset, blink: 4,
	write: write32, defaultDir: `C:\Windows\SysWOW64\`, stringWriter: (*ProcessFixture).writeUnicodeString32,
}

// Every record gets its own page, mapped before any is written: a page
// mapped twice gets a fresh frame and loses what was written through the
// first.
func (f *ProcessFixture) writeLoader(as *AddressSpace, shape loaderShape, mods []FixtureModule) {
	ldrPA := as.MapPage(shape.ldr)
	head := shape.ldr + shape.listHead
	list := &kernelList{pm: f.Memory, head: head, headPA: ldrPA + shape.listHead, tail: head,
		tailPA: ldrPA + shape.listHead, write: shape.write, flinkAt: 0, blinkAt: shape.blink}
	records := make([]uint64, len(mods))
	for i := range mods {
		records[i] = as.MapPage(shape.entries + uint64(i)*fixtureRecordStride)
	}
	for i, m := range mods {
		va, pa := shape.entries+uint64(i)*fixtureRecordStride, records[i]
		list.append(va+FixtureInLoadLinksOffset, pa+FixtureInLoadLinksOffset)
		size := m.Size
		if size == 0 {
			size = uint64(len(m.Image))
		}
		if size == 0 {
			size = fixtureDefaultModuleSize
		}
		shape.write(f.Memory, pa+shape.dllBase, m.Base)
		f.Memory.WriteU32(pa+shape.sizeOfImage, uint32(size))
		if shape.extras {
			// The padding after SizeOfImage is not zero, so a reader that
			// takes eight bytes there gets a wrong size.
			f.Memory.WriteU32(pa+shape.sizeOfImage+4, fixturePaddingPattern)
			f.Memory.WriteU16(pa+FixtureObsoleteLoadCountOffset, m.LoadCount)
			f.Memory.WriteU64(pa+FixtureLoadTimeOffset, m.LoadTime)
		}
		full := m.FullPath
		if full == "" {
			full = shape.defaultDir + m.Name
		}
		names := shape.names + uint64(2*i)*fixtureRecordStride
		shape.stringWriter(f, as, pa+shape.baseName, names, m.Name)
		shape.stringWriter(f, as, pa+shape.fullName, names+fixtureRecordStride, full)
		if len(m.Image) > 0 {
			as.MapImage(m.Base, m.Image)
		}
	}
	list.close()
}

func (f *ProcessFixture) writeUnicodeString(as *AddressSpace, structPA, bufferVA uint64, s string) {
	raw := f.stringPage(as, bufferVA, s)
	f.Memory.WriteU64(structPA+unicodeBufferAt, bufferVA)
	f.writeCounts(structPA, raw)
}

func (f *ProcessFixture) writeUnicodeString32(as *AddressSpace, structPA, bufferVA uint64, s string) {
	raw := f.stringPage(as, bufferVA, s)
	f.Memory.WriteU32(structPA+unicodeBuffer32At, uint32(bufferVA))
	f.writeCounts(structPA, raw)
}

func (f *ProcessFixture) stringPage(as *AddressSpace, bufferVA uint64, s string) []byte {
	raw := utf16LE(s)
	f.Memory.WriteAt(as.MapPage(bufferVA), raw)
	return raw
}

func (f *ProcessFixture) writeCounts(structPA uint64, raw []byte) {
	f.Memory.WriteU16(structPA+unicodeLengthAt, uint16(len(raw)))
	f.Memory.WriteU16(structPA+unicodeMaximumAt, uint16(len(raw)))
}

// Each VAD has a kernel page of its own: its pool tag and node, then, for a
// file view, the subsection, control area, file object and name the view
// leads to, one after the other at 16-byte steps (T5 to T8).
type vadPage struct {
	node, subsection, controlArea, fileObject, name uint64
}

func align16(v uint64) uint64 { return (v + PoolAlignment - 1) &^ (PoolAlignment - 1) }

var vadInPage = func() vadPage {
	var p vadPage
	p.node = PoolHeaderSize
	p.subsection = align16(p.node + fixtureVadLongSize)
	p.controlArea = align16(p.subsection + fixtureSubsectionSize)
	p.fileObject = align16(p.controlArea + fixtureControlAreaSize)
	p.name = align16(p.fileObject + fixtureFileObjectSize)
	return p
}()

func vadTag(v FixtureVAD) string {
	switch {
	case v.Tag != "":
		return v.Tag
	case v.Path != "":
		return "Vad "
	default:
		return "VadS"
	}
}

func vadFlags(v FixtureVAD) uint32 {
	field := func(value uint32, bit, bits uint8) uint32 { return (value & (1<<bits - 1)) << bit }
	flags := field(v.Protection, FixtureVadProtectionBit, FixtureVadProtectionBits) |
		field(v.VadType, FixtureVadTypeBit, FixtureVadTypeBits)
	if v.Path == "" {
		flags |= 1 << FixtureVadPrivateMemoryBit
	}
	return flags
}

// Balance is the right subtree's height less the left's, kept as a 2-bit
// two's-complement value (S24 T2, M7).
func vadBalances(links S24Links) []uint64 {
	heights := make([]int, len(links.Left))
	var height func(i int) int
	height = func(i int) int {
		if i < 0 {
			return 0
		}
		heights[i] = 1 + max(height(links.Left[i]), height(links.Right[i]))
		return heights[i]
	}
	height(links.Root)
	balances := make([]uint64, len(heights))
	for i := range heights {
		h := func(j int) int {
			if j < 0 {
				return 0
			}
			return heights[j]
		}
		balances[i] = uint64(h(links.Right[i])-h(links.Left[i])) & FixtureVadParentBalance
	}
	return balances
}

func (f *ProcessFixture) writeVadTree(procIndex int, vads []FixtureVAD) uint64 {
	pm := f.Memory
	base := fixtureVadBaseVA + uint64(procIndex)*fixtureVadProcessStride
	pages := make([]uint64, len(vads))
	for i := range vads {
		pages[i] = f.Kernel.MapPage(base + uint64(i)*pageSize)
	}
	at := func(i int, offset uint64) uint64 { return base + uint64(i)*pageSize + offset }
	links := S24VadLinks(vads)
	balances := vadBalances(links)
	for i, v := range vads {
		node := pages[i] + vadInPage.node
		pm.WriteAt(node-PoolHeaderSize+PoolTagOffset, []byte(vadTag(v)))
		pm.WriteU32(node+FixtureVadStartingVpnOff, uint32(v.Start>>12))
		pm.WriteU32(node+FixtureVadEndingVpnOff, uint32(v.End>>12))
		pm.WriteAt(node+FixtureVadStartingVpnHighOff, []byte{byte(v.Start >> 44)})
		pm.WriteAt(node+FixtureVadEndingVpnHighOff, []byte{byte(v.End >> 44)})
		pm.WriteU32(node+FixtureVadFlagsOffset, vadFlags(v))
		if l := links.Left[i]; l >= 0 {
			pm.WriteU64(node+FixtureVadNodeOffset+FixtureVadLeftOffset, at(l, vadInPage.node))
		}
		if r := links.Right[i]; r >= 0 {
			pm.WriteU64(node+FixtureVadNodeOffset+FixtureVadRightOffset, at(r, vadInPage.node))
		}
		parent := uint64(0)
		if p := links.Parent[i]; p >= 0 {
			parent = at(p, vadInPage.node)
		}
		pm.WriteU64(node+FixtureVadNodeOffset+FixtureVadParentOffset, parent|balances[i])
		if v.Path != "" {
			f.writeFileView(pages[i], at(i, 0), v.Path)
		}
	}
	return at(links.Root, vadInPage.node)
}

func (f *ProcessFixture) writeFileView(pa, va uint64, path string) {
	pm, p := f.Memory, vadInPage
	raw := utf16LE(path)
	if p.name+uint64(len(raw)) > pageSize {
		panic("testsupport: VAD path does not fit its page")
	}
	pm.WriteU64(pa+p.node+FixtureVadSubsectionOffset, va+p.subsection)
	pm.WriteU64(pa+p.subsection+fixtureSubControlAreaOff, va+p.controlArea)
	pm.WriteU64(pa+p.controlArea+fixtureCaFilePointerOff, (va+p.fileObject)|fixtureFastRefBits)
	pm.WriteU16(pa+p.fileObject, fixtureFileObjectType)
	pm.WriteU16(pa+p.fileObject+2, uint16(fixtureFileObjectSize))
	pm.WriteAt(pa+p.name, raw)
	pm.WriteU64(pa+p.fileObject+fixtureFoFileNameOff+unicodeBufferAt, va+p.name)
	f.writeCounts(pa+p.fileObject+fixtureFoFileNameOff, raw)
}

// A one-level table: TableCode is the leaf page itself. Entry 0 of a page is
// never in use; entry k holds handle 4k, and every handle names the
// process's own object header (S66 HT2, HM3 to HM5).
func (f *ProcessFixture) writeHandleTable(i int, place eprocessPlace, count int) {
	table := fixtureHandleTableBaseVA + uint64(i)*fixtureHandleTableStride
	leaf := table + pageSize
	tablePA, leafPA := f.Kernel.MapPage(table), f.Kernel.MapPage(leaf)
	pm := f.Memory
	pm.WriteU64(place.physical+FixtureObjectTableOffset, table)
	pm.WriteU64(tablePA+FixtureTableCodeOffset, leaf)
	pages := (uint32(count+1)*fixtureHandleStep + fixtureHandlesPerPage - 1) / fixtureHandlesPerPage
	pm.WriteU32(tablePA+FixtureNextHandleOffset, pages*fixtureHandlesPerPage)
	header := (place.virtual - fixtureObjectBody) & (1<<48 - 1)
	entry := header>>4<<fixtureObjectPointerShift | fixtureHandleUnlocked
	for k := 1; k <= count; k++ {
		pm.WriteU64(leafPA+uint64(k)*fixtureHandleEntrySize+FixtureObjectPointerBitsOffset, entry)
	}
}

func (f *ProcessFixture) Context() tools.Context {
	options := map[string]any{}
	if f.pooled {
		options[tools.OptionPhysicalMemory] = memory.MemoryReader(f.Memory)
		options[tools.OptionKernelDTB] = f.Kernel.DTB
		options[tools.OptionPagingMode] = "x64"
	}
	return tools.Context{
		Memory:        layers.NewProcessLayer(f.Memory, f.Kernel.DTB, 0),
		Symbols:       f.Table,
		Profile:       profiles.WindowsX64Profile{},
		Options:       options,
		ProcessMemory: f.processMemory,
	}
}

func (f *ProcessFixture) ContextWithoutProcessLayer() tools.Context {
	ctx := f.Context()
	ctx.ProcessMemory = nil
	return ctx
}

func (f *ProcessFixture) EPROCESS(pid uint64) (virtual, physical uint64) {
	p := f.eprocesses[pid]
	return p.virtual, p.physical
}

func (f *ProcessFixture) DirectoryTableBase(pid uint64) uint64 {
	if as, ok := f.spaces[pid]; ok {
		return as.DTB
	}
	return 0
}

func (f *ProcessFixture) Space(pid uint64) *AddressSpace { return f.spaces[pid] }

func (f *ProcessFixture) processMemory(dtb uint64) (memory.MemoryReader, error) {
	if dtb == 0 {
		return nil, memory.ErrOutOfBounds
	}
	return layers.NewProcessLayer(f.Memory, dtb, 0), nil
}

func member(name string, offset uint64, typ string) symbols.Field {
	return symbols.Field{Name: name, Offset: offset, Type: symbols.TypeRef{Name: typ}}
}

func pointerMember(name string, offset uint64, to string) symbols.Field {
	return symbols.Field{Name: name, Offset: offset, Type: symbols.TypeRef{Name: to, IsPointer: true}}
}

func bitMember(name string, offset uint64, typ string, bit, bits uint8) symbols.Field {
	return symbols.Field{Name: name, Offset: offset, Type: symbols.TypeRef{Name: typ, BitOffset: bit, BitLength: bits}}
}

// The table declares only members the fixture fills: a member present but
// left zero would read as a real zero. DirectoryTableBase is named on
// _EPROCESS at Pcb (offset 0) plus its _KPROCESS offset, without Pcb itself.
func buildFixtureSymbolTable(withProcessMemory, withParents bool) *symbols.Table {
	t := symbols.NewTable("fixture", 8)
	add := func(name string, size uint64, fields ...symbols.Field) {
		t.AddStruct(symbols.StructType{Name: name, Size: size, Fields: fields})
	}
	add("_LIST_ENTRY", 0x10, pointerMember("Flink", FixtureFlinkOffset, "_LIST_ENTRY"),
		pointerMember("Blink", FixtureBlinkOffset, "_LIST_ENTRY"))
	add("LIST_ENTRY32", 8, member("Flink", 0, "unsigned int"), member("Blink", 4, "unsigned int"))
	t.AddStruct(unicodeStringType())
	add("_STRING32", 8, member("Length", unicodeLengthAt, "unsigned short"),
		member("MaximumLength", unicodeMaximumAt, "unsigned short"), member("Buffer", unicodeBuffer32At, "unsigned int"))

	eprocess := []symbols.Field{
		member("DirectoryTableBase", FixtureDTBOffset, "unsigned long long"),
		pointerMember("UniqueProcessId", FixturePIDOffset, "void"),
		member("ActiveProcessLinks", FixtureActiveLinksOffset, "_LIST_ENTRY"),
		pointerMember("Peb", FixturePebOffset, "_PEB"),
		pointerMember("WoW64Process", FixtureWow64ProcessOffset, "_EWOW64PROCESS"),
		{Name: "ImageFileName", Offset: FixtureImageNameOffset,
			Type: symbols.TypeRef{Name: "unsigned char", IsArray: true, ArrayLength: 15}},
	}
	peb := []symbols.Field{pointerMember("Ldr", FixtureLdrOffset, "_PEB_LDR_DATA")}
	if withParents {
		eprocess = append(eprocess, pointerMember("InheritedFromUniqueProcessId", FixtureParentPIDOffset, "void"))
	}
	if withProcessMemory {
		eprocess = append(eprocess,
			pointerMember("SectionBaseAddress", FixtureSectionBaseOffset, "void"),
			member("VadRoot", FixtureVadRootOffset, "_RTL_AVL_TREE"),
			member("VadCount", FixtureVadCountOffset, "unsigned long long"))
		peb = append(peb, pointerMember("ImageBaseAddress", FixturePebImageBaseOffset, "void"))
	}
	add("_EPROCESS", fixtureEprocessSize, eprocess...)
	add("_PEB", fixturePebSize, peb...)
	add("_PEB_LDR_DATA", fixtureLdrDataSize, member("InLoadOrderModuleList", FixtureInLoadOrderOffset, "_LIST_ENTRY"))
	add("_LDR_DATA_TABLE_ENTRY", fixtureLdrEntrySize,
		member("InLoadOrderLinks", FixtureInLoadLinksOffset, "_LIST_ENTRY"),
		pointerMember("DllBase", FixtureDllBaseOffset, "void"),
		member("SizeOfImage", FixtureSizeOfImageOffset, "unsigned int"),
		member("FullDllName", FixtureFullDllNameOffset, "_UNICODE_STRING"),
		member("BaseDllName", FixtureBaseDllNameOffset, "_UNICODE_STRING"),
		member("ObsoleteLoadCount", FixtureObsoleteLoadCountOffset, "unsigned short"),
		member("LoadTime", FixtureLoadTimeOffset, "_LARGE_INTEGER"))
	add("_EWOW64PROCESS", fixtureEwow64Size, pointerMember("Peb", FixtureEwow64PebOffset, "void"))
	add("_PEB32", fixturePeb32Size, member("Ldr", fixturePeb32LdrOffset, "unsigned int"))
	if withProcessMemory {
		addProcessMemoryTypes(t)
	}
	t.AddSymbol(symbols.Symbol{Name: "PsActiveProcessHead", Address: FixtureProcessListHeadVA})
	return t
}

func addProcessMemoryTypes(t *symbols.Table) {
	add := func(name string, size uint64, fields ...symbols.Field) {
		t.AddStruct(symbols.StructType{Name: name, Size: size, Fields: fields})
	}
	t.AddSymbol(symbols.Symbol{Name: "MmProtectToValue", Address: fixtureProtectToValueVA})
	add("_RTL_AVL_TREE", 8, pointerMember("Root", 0, "_RTL_BALANCED_NODE"))
	add("_RTL_BALANCED_NODE", 0x18,
		pointerMember("Left", FixtureVadLeftOffset, "_RTL_BALANCED_NODE"),
		pointerMember("Right", FixtureVadRightOffset, "_RTL_BALANCED_NODE"),
		member("ParentValue", FixtureVadParentOffset, "unsigned long long"),
		bitMember("Balance", FixtureVadParentOffset, "unsigned char", 0, 2))
	add("_MMVAD_SHORT", fixtureVadShortSize,
		member("VadNode", FixtureVadNodeOffset, "_RTL_BALANCED_NODE"),
		member("StartingVpn", FixtureVadStartingVpnOff, "unsigned int"),
		member("EndingVpn", FixtureVadEndingVpnOff, "unsigned int"),
		member("StartingVpnHigh", FixtureVadStartingVpnHighOff, "unsigned char"),
		member("EndingVpnHigh", FixtureVadEndingVpnHighOff, "unsigned char"),
		symbols.Field{Name: "u", Offset: FixtureVadFlagsOffset})
	add("_MMVAD", fixtureVadLongSize, member("Core", 0, "_MMVAD_SHORT"),
		pointerMember("Subsection", FixtureVadSubsectionOffset, "_SUBSECTION"))
	add("_MMVAD_FLAGS", 4,
		bitMember("VadType", 0, "unsigned int", FixtureVadTypeBit, FixtureVadTypeBits),
		bitMember("Protection", 0, "unsigned int", FixtureVadProtectionBit, FixtureVadProtectionBits),
		bitMember("PrivateMemory", 0, "unsigned int", FixtureVadPrivateMemoryBit, 1))
	add("_SUBSECTION", fixtureSubsectionSize, pointerMember("ControlArea", fixtureSubControlAreaOff, "_CONTROL_AREA"))
	add("_CONTROL_AREA", fixtureControlAreaSize, member("FilePointer", fixtureCaFilePointerOff, "_EX_FAST_REF"))
	add("_EX_FAST_REF", 8, pointerMember("Object", 0, "void"),
		bitMember("RefCnt", 0, "unsigned long long", 0, 4), member("Value", 0, "unsigned long long"))
	add("_FILE_OBJECT", fixtureFileObjectSize, member("Type", 0, "short"), member("Size", 2, "short"),
		member("FileName", fixtureFoFileNameOff, "_UNICODE_STRING"))
}

func addHandleTypes(t *symbols.Table) {
	eprocess, err := t.Struct("_EPROCESS")
	if err != nil {
		panic("testsupport: fixture table lacks _EPROCESS: " + err.Error())
	}
	eprocess.Fields = append(append([]symbols.Field(nil), eprocess.Fields...),
		pointerMember("ObjectTable", FixtureObjectTableOffset, "_HANDLE_TABLE"))
	t.AddStruct(eprocess)
	t.AddStruct(symbols.StructType{Name: "_HANDLE_TABLE", Size: fixtureHandleTableSize, Fields: []symbols.Field{
		member("NextHandleNeedingPool", FixtureNextHandleOffset, "unsigned int"),
		member("TableCode", FixtureTableCodeOffset, "unsigned long long"),
	}})
	t.AddStruct(symbols.StructType{Name: "_HANDLE_TABLE_ENTRY", Size: fixtureHandleEntrySize, Fields: []symbols.Field{
		bitMember("Unlocked", FixtureObjectPointerBitsOffset, "unsigned long long", 0, 1),
		bitMember("ObjectPointerBits", FixtureObjectPointerBitsOffset, "unsigned long long", fixtureObjectPointerShift, 44),
		bitMember("GrantedAccessBits", 8, "unsigned int", 0, 25),
	}})
}

func addPoolTypes(t *symbols.Table) {
	t.AddStruct(symbols.StructType{Name: "_POOL_HEADER", Size: PoolHeaderSize, Fields: poolHeaderFields()})
	t.AddStruct(symbols.StructType{Name: "_POOL_TRACKER_BIG_PAGES", Size: bigPageEntrySize,
		Fields: []symbols.Field{bigPageTypeField()}})
	t.AddStruct(symbols.StructType{Name: "_OBJECT_HEADER", Size: fixtureObjectHeaderLen, Fields: []symbols.Field{
		member("PointerCount", 0, "long long"),
		member("Body", fixtureObjectBody, "_QUAD"),
	}})
	t.AddSymbol(symbols.Symbol{Name: "ObHeaderCookie", Address: fixtureObHeaderCookieVA})
}
