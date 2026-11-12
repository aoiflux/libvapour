package registryhive

import (
	"encoding/binary"
	"fmt"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// Offsets are those of the 26100 kernel table (S49 section 3).
const (
	fxHiveList     = 0x648
	fxFullPath     = 0x720
	fxUserName     = 0x730
	fxRootPath     = 0x740
	fxRootKcb      = 0xb78
	fxBaseBlock    = 0x40
	fxStorageAt    = 0x118
	fxDualSize     = 0x278
	fxDualMap      = 0x8
	fxEntrySize    = 0x18
	fxEntryBin     = 0x8
	fxKcbKeyCell   = 0x28
	fxCMHiveSize   = 0x12d8
	fxListHead     = uint64(0xfffff80000001000)
	fxHeap         = uint64(0xffff900000000000)
	fxBlock        = 0x1000
	fxNoCell       = 0xffffffff
	fxBinFlags     = 0x9
	fxVolatileBit  = 0x80000000
	fxRootCellSize = 0x20
)

type fxMemory struct{ pages map[uint64][]byte }

func newFxMemory() *fxMemory { return &fxMemory{pages: map[uint64][]byte{}} }

func (m *fxMemory) ReadAt(at, n uint64) ([]byte, error) {
	out := make([]byte, 0, n)
	for n > 0 {
		p, ok := m.pages[at&^0xfff]
		if !ok {
			return nil, fmt.Errorf("fixture: 0x%x: %w", at, memory.ErrOutOfBounds)
		}
		k := min(n, 0x1000-at&0xfff)
		out = append(out, p[at&0xfff:at&0xfff+k]...)
		at, n = at+k, n-k
	}
	return out, nil
}

func (m *fxMemory) Size() uint64 { return 1 << 63 }

func (m *fxMemory) write(at uint64, b []byte) {
	for len(b) > 0 {
		p, ok := m.pages[at&^0xfff]
		if !ok {
			p = make([]byte, 0x1000)
			m.pages[at&^0xfff] = p
		}
		k := copy(p[at&0xfff:], b)
		at, b = at+uint64(k), b[k:]
	}
}

func (m *fxMemory) u16(at uint64, v uint16) { m.write(at, binary.LittleEndian.AppendUint16(nil, v)) }
func (m *fxMemory) u32(at uint64, v uint32) { m.write(at, binary.LittleEndian.AppendUint32(nil, v)) }
func (m *fxMemory) u64(at uint64, v uint64) { m.write(at, binary.LittleEndian.AppendUint64(nil, v)) }
func (m *fxMemory) drop(at uint64)          { delete(m.pages, at&^0xfff) }

func fxField(name string, off uint64, typ string) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: typ}}
}

func fxArray(name string, off, n uint64, typ string) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: typ, IsArray: true, ArrayLength: n,
		Element: &symbols.TypeRef{Name: typ}}}
}

func fxTable() *symbols.Table {
	t := symbols.NewTable("s49", 8)
	add := func(name string, size uint64, fields ...symbols.Field) {
		t.AddStruct(symbols.StructType{Name: name, Size: size, Fields: fields})
	}
	add("_LIST_ENTRY", 16, fxField("Flink", 0, "*_LIST_ENTRY"), fxField("Blink", 8, "*_LIST_ENTRY"))
	add("_UNICODE_STRING", 16, fxField("Length", 0, "unsigned short"), fxField("MaximumLength", 2, "unsigned short"),
		fxField("Buffer", 8, "*wchar_t"))
	add("_CMHIVE", fxCMHiveSize, fxField("Hive", 0, "_HHIVE"), fxField("HiveList", fxHiveList, "_LIST_ENTRY"),
		fxField("FileFullPath", fxFullPath, "_UNICODE_STRING"), fxField("FileUserName", fxUserName, "_UNICODE_STRING"),
		fxField("HiveRootPath", fxRootPath, "_UNICODE_STRING"), fxField("RootKcb", fxRootKcb, "*_CM_KEY_CONTROL_BLOCK"))
	add("_CM_KEY_CONTROL_BLOCK", 0x138, fxField("KeyCell", fxKcbKeyCell, "unsigned int"))
	add("_HHIVE", 0x608, fxField("Signature", 0, "unsigned int"), fxField("BaseBlock", fxBaseBlock, "*_HBASE_BLOCK"),
		fxArray("Storage", fxStorageAt, 2, "_DUAL"))
	add("_DUAL", fxDualSize, fxField("Length", 0, "unsigned int"), fxField("Map", fxDualMap, "*_HMAP_DIRECTORY"),
		fxField("SmallDir", 0x10, "*_HMAP_TABLE"))
	add("_HMAP_DIRECTORY", 0x2000, fxArray("Directory", 0, 1024, "*_HMAP_TABLE"))
	add("_HMAP_TABLE", 0x3000, fxArray("Table", 0, 512, "_HMAP_ENTRY"))
	add("_HMAP_ENTRY", fxEntrySize, fxField("BlockOffset", 0, "unsigned long long"),
		fxField("PermanentBinAddress", fxEntryBin, "unsigned long long"), fxField("MemAlloc", 0x10, "unsigned int"))
	add("_HBASE_BLOCK", fxBlock, fxField("Signature", 0, "unsigned int"), fxField("RootCell", 0x24, "unsigned int"),
		fxField("Length", 0x28, "unsigned int"))
	add("_CHILD_LIST", 8, fxField("Count", 0, "unsigned int"), fxField("List", 4, "unsigned int"))
	add("_CM_KEY_NODE", 0x50, fxField("Signature", 0, "unsigned short"), fxField("Flags", 2, "unsigned short"),
		fxField("LastWriteTime", 4, "_LARGE_INTEGER"), fxField("Parent", 0x10, "unsigned int"),
		fxArray("SubKeyCounts", 0x14, 2, "unsigned int"), fxArray("SubKeyLists", 0x1c, 2, "unsigned int"),
		fxField("ValueList", 0x24, "_CHILD_LIST"), fxField("Security", 0x2c, "unsigned int"),
		fxField("Class", 0x30, "unsigned int"), fxField("NameLength", 0x48, "unsigned short"),
		fxField("ClassLength", 0x4a, "unsigned short"), fxArray("Name", 0x4c, 1, "wchar_t"))
	add("_CM_KEY_VALUE", 0x18, fxField("Signature", 0, "unsigned short"), fxField("NameLength", 2, "unsigned short"),
		fxField("DataLength", 4, "unsigned int"), fxField("Data", 8, "unsigned int"), fxField("Type", 0xc, "unsigned int"),
		fxField("Flags", 0x10, "unsigned short"), fxArray("Name", 0x14, 1, "wchar_t"))
	add("_CM_KEY_INDEX", 8, fxField("Signature", 0, "unsigned short"), fxField("Count", 2, "unsigned short"),
		fxArray("List", 4, 1, "unsigned int"))
	add("_CM_INDEX", 8, fxField("Cell", 0, "unsigned int"), fxField("HashKey", 4, "unsigned int"))
	add("_CM_BIG_DATA", 8, fxField("Signature", 0, "unsigned short"), fxField("Count", 2, "unsigned short"),
		fxField("List", 4, "unsigned int"))
	t.AddSymbol(symbols.Symbol{Name: "CmpHiveListHead", Address: fxListHead})
	return t
}

type fxImage struct {
	mem   *fxMemory
	table *symbols.Table
	next  uint64
	hives []*fxHive
	diags *[]string
}

func newFxImage() *fxImage {
	img := &fxImage{mem: newFxMemory(), table: fxTable(), next: fxHeap, diags: &[]string{}}
	img.mem.u64(fxListHead, fxListHead)
	img.mem.u64(fxListHead+8, fxListHead)
	return img
}

func (img *fxImage) alloc(n uint64) uint64 {
	at := img.next
	img.next += (n + 0xfff) &^ 0xfff
	img.mem.write(at, make([]byte, n))
	return at
}

func (img *fxImage) context(opts map[string]any) tools.Context {
	o := map[string]any{"diagnostics": img.diags}
	for k, v := range opts {
		o[k] = v
	}
	return tools.Context{Memory: img.mem, Symbols: img.table, Profile: profiles.WindowsX64Profile{}, Options: o}
}

type fxStorage struct {
	data []byte
	bin  uint64
	mapD uint64
}

type fxHive struct {
	img     *fxImage
	cmhive  uint64
	base    uint64
	storage [2]*fxStorage
	root    uint32
}

// One bin per storage covers every block; cells follow the bin header.
func (img *fxImage) newHive(paths [3]string) *fxHive {
	h := &fxHive{img: img, cmhive: img.alloc(fxCMHiveSize), base: img.alloc(fxBlock)}
	for s := range h.storage {
		h.storage[s] = &fxStorage{data: make([]byte, fxRootCellSize)}
		copy(h.storage[s].data, "hbin")
	}
	img.mem.u32(h.cmhive, hiveSignature)
	img.mem.u64(h.cmhive+fxBaseBlock, h.base)
	img.mem.u32(h.base, baseSignature)
	for i, off := range []uint64{fxFullPath, fxUserName, fxRootPath} {
		img.writeString(h.cmhive+off, paths[i])
	}
	last, _ := img.mem.ReadAt(fxListHead+8, 8)
	prev := binary.LittleEndian.Uint64(last)
	entry := h.cmhive + fxHiveList
	img.mem.u64(prev, entry)
	img.mem.u64(entry+8, prev)
	img.mem.u64(entry, fxListHead)
	img.mem.u64(fxListHead+8, entry)
	img.hives = append(img.hives, h)
	return h
}

func (img *fxImage) writeString(at uint64, s string) {
	if s == "" {
		return
	}
	raw := utf16le(s)
	buf := img.alloc(uint64(len(raw)))
	img.mem.write(buf, raw)
	img.mem.u16(at, uint16(len(raw)))
	img.mem.u16(at+2, uint16(len(raw)))
	img.mem.u64(at+8, buf)
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}

func (h *fxHive) cell(storage int, payload []byte) uint32 {
	st := h.storage[storage]
	size := (uint64(len(payload)) + 4 + 7) &^ 7
	off := uint64(len(st.data))
	st.data = append(st.data, make([]byte, size)...)
	binary.LittleEndian.PutUint32(st.data[off:], uint32(-int32(size)))
	copy(st.data[off+4:], payload)
	return uint32(off) | uint32(storage)<<31
}

func (h *fxHive) payload(index uint32) []byte {
	st := h.storage[index>>31]
	return st.data[index&0x7fffffff+4:]
}

type fxKey struct {
	name       string
	utf16Name  bool
	flags      uint16
	parent     uint32
	lastWrite  uint64
	counts     [2]uint32
	lists      [2]uint32
	values     uint32
	valueList  uint32
	class      uint32
	classBytes uint16
}

func (h *fxHive) key(storage int, k fxKey) uint32 {
	name := []byte(k.name)
	flags := k.flags
	if k.utf16Name {
		name = utf16le(k.name)
	} else {
		flags |= keyNameCompressed
	}
	b := make([]byte, 0x4c+len(name))
	copy(b, sigKeyNode)
	binary.LittleEndian.PutUint16(b[2:], flags)
	binary.LittleEndian.PutUint64(b[4:], k.lastWrite)
	binary.LittleEndian.PutUint32(b[0x10:], k.parent)
	for s := 0; s < 2; s++ {
		binary.LittleEndian.PutUint32(b[0x14+4*s:], k.counts[s])
		list := k.lists[s]
		if k.counts[s] == 0 && list == 0 {
			list = fxNoCell
		}
		binary.LittleEndian.PutUint32(b[0x1c+4*s:], list)
	}
	binary.LittleEndian.PutUint32(b[0x24:], k.values)
	binary.LittleEndian.PutUint32(b[0x28:], k.valueList)
	binary.LittleEndian.PutUint32(b[0x2c:], fxNoCell)
	binary.LittleEndian.PutUint32(b[0x30:], k.class)
	binary.LittleEndian.PutUint16(b[0x48:], uint16(len(name)))
	binary.LittleEndian.PutUint16(b[0x4a:], k.classBytes)
	copy(b[0x4c:], name)
	return h.cell(storage, b)
}

func (h *fxHive) setU32(index uint32, off int, v uint32) {
	binary.LittleEndian.PutUint32(h.payload(index)[off:], v)
}

func (h *fxHive) index(storage int, sig string, cells ...uint32) uint32 {
	stride := 4
	if sig == sigFastLeaf || sig == sigHashLeaf {
		stride = 8
	}
	b := make([]byte, 4+stride*len(cells))
	copy(b, sig)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(cells)))
	for i, c := range cells {
		binary.LittleEndian.PutUint32(b[4+stride*i:], c)
	}
	return h.cell(storage, b)
}

type fxValue struct {
	name      string
	utf16Name bool
	typ       uint32
	length    uint32
	data      uint32
}

func (h *fxHive) valueCell(storage int, v fxValue) uint32 {
	name := []byte(v.name)
	var flags uint16
	if v.utf16Name {
		name = utf16le(v.name)
	} else if v.name != "" {
		flags = valueNameCompressed
	}
	b := make([]byte, 0x14+len(name))
	copy(b, sigValue)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(name)))
	binary.LittleEndian.PutUint32(b[4:], v.length)
	binary.LittleEndian.PutUint32(b[8:], v.data)
	binary.LittleEndian.PutUint32(b[0xc:], v.typ)
	binary.LittleEndian.PutUint16(b[0x10:], flags)
	copy(b[0x14:], name)
	return h.cell(storage, b)
}

func (h *fxHive) value(storage int, name string, typ uint32, data []byte) uint32 {
	if len(data) <= residentBytes {
		var field [4]byte
		copy(field[:], data)
		return h.valueCell(storage, fxValue{name: name, typ: typ, length: uint32(len(data)) | dataResident,
			data: binary.LittleEndian.Uint32(field[:])})
	}
	return h.valueCell(storage, fxValue{name: name, typ: typ, length: uint32(len(data)), data: h.cell(storage, data)})
}

func (h *fxHive) valueList(storage int, cells ...uint32) uint32 {
	b := make([]byte, 4*len(cells))
	for i, c := range cells {
		binary.LittleEndian.PutUint32(b[4*i:], c)
	}
	return h.cell(storage, b)
}

// commit lays each storage out in memory behind a map directory and table.
func (h *fxHive) commit() {
	img := h.img
	img.mem.u32(h.base+0x24, h.root)
	for s, st := range h.storage {
		dual := h.cmhive + fxStorageAt + uint64(s)*fxDualSize
		used := uint64(len(st.data))
		if used <= fxRootCellSize {
			img.mem.u32(dual, 0)
			continue
		}
		length := (used + fxBlock - 1) &^ (fxBlock - 1)
		st.data = append(st.data, make([]byte, length-used)...)
		binary.LittleEndian.PutUint32(st.data[8:], uint32(length))
		img.mem.u32(dual, uint32(length))
		st.bin = img.alloc(length)
		img.mem.write(st.bin, st.data[:length])
		table := img.alloc(0x3000)
		st.mapD = img.alloc(0x2000)
		img.mem.u64(st.mapD, table)
		img.mem.u64(dual+fxDualMap, st.mapD)
		for blk := uint64(0); blk < length/fxBlock; blk++ {
			e := table + blk*fxEntrySize
			img.mem.u64(e, blk*fxBlock)
			img.mem.u64(e+fxEntryBin, st.bin|fxBinFlags)
		}
	}
}

func (h *fxHive) address(index uint32) uint64 {
	return h.storage[index>>31].bin + uint64(index&0x7fffffff)
}

func (h *fxHive) layer(t *testing.T, ctx tools.Context) *HiveLayer {
	t.Helper()
	l, err := NewHiveLayer(ctx, h.cmhive)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// standardHive builds ROOT with subkeys Alpha (with values) and Beta, and a
// volatile subkey Gamma.
func standardHive(img *fxImage) (*fxHive, map[string]uint32) {
	h := img.newHive([3]string{"", `\SystemRoot\System32\Config\SOFTWARE`, `\REGISTRY\MACHINE\SOFTWARE`})
	cells := map[string]uint32{}
	h.root = h.key(0, fxKey{name: "ROOT", flags: keyHiveRoot, parent: fxNoCell})
	vals := h.valueList(0,
		h.value(0, "Path", regSZ, utf16le("C:\\x\x00")),
		h.value(0, "Count", regDWORD, []byte{7, 0, 0, 0}),
		h.value(0, "", regBinary, []byte{1, 2, 3, 4, 5, 6}))
	cells["Alpha"] = h.key(0, fxKey{name: "Alpha", parent: h.root, lastWrite: 133000000000000000, values: 3, valueList: vals})
	cells["Beta"] = h.key(0, fxKey{name: "Beta", utf16Name: true, parent: h.root})
	cells["Gamma"] = h.key(1, fxKey{name: "Gamma", parent: h.root})
	stable := h.index(0, sigHashLeaf, cells["Alpha"], cells["Beta"])
	volatile := h.index(1, sigFastLeaf, cells["Gamma"])
	h.setU32(h.root, 0x14, 2)
	h.setU32(h.root, 0x18, 1)
	h.setU32(h.root, 0x1c, stable)
	h.setU32(h.root, 0x20, volatile)
	cells["stable list"], cells["volatile list"] = stable, volatile
	h.commit()
	return h, cells
}
