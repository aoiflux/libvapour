package testsupport

import (
	"encoding/binary"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
)

func readU64(t *testing.T, r memory.MemoryReader, va uint64) uint64 {
	t.Helper()
	raw, err := r.ReadAt(va, 8)
	if err != nil {
		t.Fatalf("read 0x%x: %v", va, err)
	}
	return binary.LittleEndian.Uint64(raw)
}

func TestTableOffsetsAreThe19045Layout(t *testing.T) {
	f := BuildProcessFixture([]FixtureProcess{{PID: 4, Parent: 1, VADs: []FixtureVAD{{Start: 0x10000, End: 0x1ffff}}}})
	for _, c := range []struct {
		typ, name string
		want      uint64
	}{
		{"_EPROCESS", "UniqueProcessId", 0x440}, {"_EPROCESS", "ActiveProcessLinks", 0x448},
		{"_EPROCESS", "InheritedFromUniqueProcessId", 0x540}, {"_EPROCESS", "SectionBaseAddress", 0x520},
		{"_EPROCESS", "Peb", 0x550}, {"_EPROCESS", "WoW64Process", 0x580}, {"_EPROCESS", "ImageFileName", 0x5a8},
		{"_EPROCESS", "VadRoot", 0x7d8}, {"_EPROCESS", "VadCount", 0x7e8}, {"_EPROCESS", "DirectoryTableBase", 0x28},
		{"_PEB", "Ldr", 0x18}, {"_PEB", "ImageBaseAddress", 0x10}, {"_PEB_LDR_DATA", "InLoadOrderModuleList", 0x10},
		{"_LDR_DATA_TABLE_ENTRY", "LoadTime", 0x100}, {"_MMVAD_SHORT", "u", 0x30}, {"_MMVAD", "Subsection", 0x48},
		{"_CONTROL_AREA", "FilePointer", 0x40}, {"_FILE_OBJECT", "FileName", 0x58}, {"_PEB32", "Ldr", 0xc},
	} {
		got, err := f.Table.Field(c.typ, c.name)
		if err != nil || got.Offset != c.want {
			t.Errorf("%s.%s at 0x%x (%v), want 0x%x", c.typ, c.name, got.Offset, err, c.want)
		}
	}
	if st, _ := f.Table.Struct("_EPROCESS"); st.Size != 0xa40 {
		t.Errorf("_EPROCESS is 0x%x bytes, want 0xa40", st.Size)
	}
}

func TestProcessListIsCircularAndSkipsUnlinked(t *testing.T) {
	f := BuildProcessFixture([]FixtureProcess{{PID: 4, Name: "System"}, {PID: 8, Unlinked: true}, {PID: 12}})
	mem := f.Context().Memory
	var pids []uint64
	prev := FixtureProcessListHeadVA
	for link := readU64(t, mem, FixtureProcessListHeadVA); link != FixtureProcessListHeadVA; link = readU64(t, mem, link) {
		if back := readU64(t, mem, link+FixtureBlinkOffset); back != prev {
			t.Fatalf("Blink of 0x%x is 0x%x, want 0x%x", link, back, prev)
		}
		pids = append(pids, readU64(t, mem, link-FixtureActiveLinksOffset+FixturePIDOffset))
		prev = link
		if len(pids) > 3 {
			t.Fatal("list does not return to its head")
		}
	}
	if !slices.Equal(pids, []uint64{4, 12}) {
		t.Fatalf("list holds %v, want [4 12]", pids)
	}
	if readU64(t, mem, FixtureProcessListHeadVA+FixtureBlinkOffset) != prev {
		t.Fatal("head Blink does not name the last entry")
	}
	ep, _ := f.EPROCESS(4)
	name, _ := mem.ReadAt(ep+FixtureImageNameOffset, 7)
	if string(name) != "System\x00" {
		t.Fatalf("ImageFileName %q", name)
	}
	if readU64(t, mem, ep+FixtureDTBOffset) != f.DirectoryTableBase(4) {
		t.Fatal("DirectoryTableBase does not name the process's page tables")
	}
}

func TestPooledProcessHasPoolAndObjectHeaders(t *testing.T) {
	f := BuildPooledProcessFixture([]FixtureProcess{{PID: 4, NoPeb: true}})
	va, pa := f.EPROCESS(4)
	if va&0xfff != fixturePooledBodyOffset || pa&0xfff != fixturePooledBodyOffset {
		t.Fatalf("body at 0x%x / 0x%x, want page offset 0x%x", va, pa, fixturePooledBodyOffset)
	}
	h, err := ReadPoolHeader(f.Memory, "_POOL_HEADER", pa-fixturePooledBodyOffset)
	if err != nil {
		t.Fatal(err)
	}
	tag := make([]byte, 4)
	binary.LittleEndian.PutUint32(tag, uint32(h.Fields["PoolTag"]))
	if string(tag) != scan.ProcessFilter.Tag || h.Fields["PoolType"] != NonPagedPoolType ||
		h.Fields["BlockSize"]*PoolAlignment < fixturePooledBodyOffset+fixtureEprocessSize {
		t.Fatalf("pool header %v", h.Fields)
	}
	if end := pa&0xfff + fixtureEprocessSize; end > pageSize {
		t.Fatalf("allocation ends at page offset 0x%x, past its page", end)
	}
	if readU64(t, f.Memory, pa-fixtureObjectBody) != 1 {
		t.Fatal("PointerCount is not 1")
	}
}

func TestVadTreeIsOrderedWithBalanceAndParents(t *testing.T) {
	var vads []FixtureVAD
	for i := range 6 {
		vads = append(vads, FixtureVAD{Start: uint64(0x10000 * (i + 1)), End: uint64(0x10000*(i+1) + 0xfff)})
	}
	f := BuildProcessFixture([]FixtureProcess{{PID: 4, NoPeb: true, VADs: vads}})
	mem := f.Context().Memory
	ep, _ := f.EPROCESS(4)
	var starts []uint64
	var walk func(node, parent uint64) int
	walk = func(node, parent uint64) int {
		if node == 0 {
			return 0
		}
		pv := readU64(t, mem, node+FixtureVadParentOffset)
		if pv&^FixtureVadParentBalance != parent {
			t.Errorf("node 0x%x parent 0x%x, want 0x%x", node, pv&^FixtureVadParentBalance, parent)
		}
		left := walk(readU64(t, mem, node+FixtureVadLeftOffset), node)
		raw, _ := mem.ReadAt(node+FixtureVadStartingVpnOff, 4)
		starts = append(starts, uint64(binary.LittleEndian.Uint32(raw))<<12)
		right := walk(readU64(t, mem, node+FixtureVadRightOffset), node)
		if got, want := pv&FixtureVadParentBalance, uint64(right-left)&FixtureVadParentBalance; got != want {
			t.Errorf("node 0x%x balance %d, want %d", node, got, want)
		}
		tag, _ := mem.ReadAt(node-PoolHeaderSize+PoolTagOffset, 4)
		if string(tag) != "VadS" {
			t.Errorf("node 0x%x tag %q", node, tag)
		}
		return 1 + max(left, right)
	}
	walk(readU64(t, mem, ep+FixtureVadRootOffset), 0)
	if len(starts) != len(vads) || !slices.IsSorted(starts) || starts[0] != 0x10000 {
		t.Fatalf("in-order starts %x", starts)
	}
}

func TestFileViewLeadsToItsFileName(t *testing.T) {
	const path = `\Windows\System32\ntdll.dll`
	f := BuildProcessFixture([]FixtureProcess{{PID: 4, NoPeb: true, VADs: []FixtureVAD{{Start: 0x10000, End: 0x1ffff,
		Path: path, Protection: FixtureProtectionExecuteWriteCopy, VadType: FixtureVadTypeImage}}}})
	mem := f.Context().Memory
	ep, _ := f.EPROCESS(4)
	vad := readU64(t, mem, ep+FixtureVadRootOffset)
	flags, _ := mem.ReadAt(vad+FixtureVadFlagsOffset, 4)
	word := binary.LittleEndian.Uint32(flags)
	if word>>FixtureVadProtectionBit&0x1f != FixtureProtectionExecuteWriteCopy || word>>FixtureVadTypeBit&7 != 2 ||
		word>>FixtureVadPrivateMemoryBit&1 != 0 {
		t.Fatalf("flags 0x%x", word)
	}
	subsection := readU64(t, mem, vad+FixtureVadSubsectionOffset)
	controlArea := readU64(t, mem, subsection+fixtureSubControlAreaOff)
	filePointer := readU64(t, mem, controlArea+fixtureCaFilePointerOff)
	file := filePointer &^ fixtureFastRefBits
	if filePointer&^0x7 == file {
		t.Fatal("clearing three count bits also gives the file object")
	}
	if kind, _ := mem.ReadAt(file, 2); binary.LittleEndian.Uint16(kind) != 5 {
		t.Fatalf("file object Type %d", binary.LittleEndian.Uint16(kind))
	}
	length, _ := mem.ReadAt(file+fixtureFoFileNameOff, 2)
	text, err := mem.ReadAt(readU64(t, mem, file+fixtureFoFileNameOff+unicodeBufferAt), uint64(binary.LittleEndian.Uint16(length)))
	if err != nil || string(text) != string(utf16LE(path)) {
		t.Fatalf("file name %q (%v)", text, err)
	}
}

func TestLoaderListsInBothWidths(t *testing.T) {
	f := BuildProcessFixture([]FixtureProcess{{PID: 8,
		Modules:      []FixtureModule{{Name: "a.exe", Base: 0x400000}, {Name: "ntdll.dll", Base: 0x7ffb00000000, Size: 0x1000}},
		Wow64Modules: []FixtureModule{{Name: "wow.dll", Base: 0x77000000}}}})
	user, err := f.Context().ProcessMemory(f.DirectoryTableBase(8))
	if err != nil {
		t.Fatal(err)
	}
	head := fixtureLdrVA + FixtureInLoadOrderOffset
	var bases, sizes []uint64
	for e := readU64(t, user, head); e != head; e = readU64(t, user, e) {
		bases = append(bases, readU64(t, user, e+FixtureDllBaseOffset))
		raw, _ := user.ReadAt(e+FixtureSizeOfImageOffset, 4)
		sizes = append(sizes, uint64(binary.LittleEndian.Uint32(raw)))
	}
	if !slices.Equal(bases, []uint64{0x400000, 0x7ffb00000000}) || !slices.Equal(sizes, []uint64{uint64(MappedPESize), 0x1000}) {
		t.Fatalf("bases %x sizes %x", bases, sizes)
	}
	u32 := func(va uint64) uint64 {
		raw, err := user.ReadAt(va, 4)
		if err != nil {
			t.Fatal(err)
		}
		return uint64(binary.LittleEndian.Uint32(raw))
	}
	ldr32 := u32(fixturePeb32VA + fixturePeb32LdrOffset)
	first := u32(ldr32 + fixtureLdr32InLoadOrder)
	if u32(first+fixtureEntry32DllBase) != 0x77000000 || u32(first) != ldr32+fixtureLdr32InLoadOrder {
		t.Fatal("32-bit list does not hold its one record")
	}
	name := u32(first + FixtureEntry32BaseDllNameOffset + FixtureUnicode32BufferOffset)
	if text, _ := user.ReadAt(name, 14); string(text) != string(utf16LE("wow.dll")) {
		t.Fatalf("32-bit base name %q", text)
	}
}

func TestHandleEntriesNameTheProcessHeader(t *testing.T) {
	f := BuildProcessFixture([]FixtureProcess{{PID: 4, NoPeb: true, Handles: 3}})
	mem := f.Context().Memory
	ep, _ := f.EPROCESS(4)
	table := readU64(t, mem, ep+FixtureObjectTableOffset)
	leaf := readU64(t, mem, table+FixtureTableCodeOffset)
	if readU64(t, mem, leaf) != 0 {
		t.Fatal("entry 0 is in use")
	}
	for k := uint64(1); k <= 3; k++ {
		v := readU64(t, mem, leaf+k*fixtureHandleEntrySize)
		header := v>>fixtureObjectPointerShift<<4 | 0xffff000000000000
		if header != ep-fixtureObjectBody || v&fixtureHandleUnlocked == 0 {
			t.Fatalf("entry %d 0x%x names 0x%x, want 0x%x", k, v, header, ep-fixtureObjectBody)
		}
	}
	raw, _ := mem.ReadAt(table+FixtureNextHandleOffset, 4)
	if binary.LittleEndian.Uint32(raw) != 1024 {
		t.Fatalf("NextHandleNeedingPool %d", binary.LittleEndian.Uint32(raw))
	}
}

func TestProtectToValueHoldsTheMeasuredTable(t *testing.T) {
	f := BuildProcessFixture([]FixtureProcess{{PID: 4, NoPeb: true, VADs: []FixtureVAD{{Start: 0x10000, End: 0x1ffff}}}})
	mem := f.Context().Memory
	for index, want := range map[uint32]uint32{FixtureProtectionReadWrite: 0x04, FixtureProtectionExecuteReadWrite: 0x40,
		FixtureProtectionExecuteWriteCopy: 0x80, 0: 0x01, 24: 0x01} {
		raw, err := mem.ReadAt(fixtureProtectToValueVA+uint64(index)*4, 4)
		if err != nil || binary.LittleEndian.Uint32(raw) != want {
			t.Errorf("MmProtectToValue[%d] = %x (%v), want 0x%x", index, raw, err, want)
		}
	}
}
