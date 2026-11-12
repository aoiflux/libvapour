package executioncompatcachememory

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

type sparse map[uint64][]byte

func (m sparse) page(at uint64) []byte {
	p := m[at&^0xFFF]
	if p == nil {
		p = make([]byte, 0x1000)
		m[at&^0xFFF] = p
	}
	return p
}

func (m sparse) write(at uint64, b []byte) {
	for i, v := range b {
		m.page(at + uint64(i))[(at+uint64(i))&0xFFF] = v
	}
}

func (m sparse) u64(at, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	m.write(at, b[:])
}

func (m sparse) u32(at uint64, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	m.write(at, b[:])
}

func (m sparse) u16(at uint64, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	m.write(at, b[:])
}

func (m sparse) ReadAt(at, size uint64) ([]byte, error) {
	out := make([]byte, 0, size)
	for uint64(len(out)) < size {
		cur := at + uint64(len(out))
		p, ok := m[cur&^0xFFF]
		if !ok {
			if len(out) == 0 {
				return nil, fmt.Errorf("unmapped 0x%x", cur)
			}
			return out, nil
		}
		n := min(0x1000-cur&0xFFF, size-uint64(len(out)))
		out = append(out, p[cur&0xFFF:cur&0xFFF+n]...)
	}
	return out, nil
}

func (m sparse) Size() uint64 { return 0 }

func (m sparse) drop(at uint64) { delete(m, at&^0xFFF) }

func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	return b
}

func field(name string, off uint64) symbols.Field { return symbols.Field{Name: name, Offset: off} }

// The kernel types as T1 to T3 record them.
func s41Table(pointerSize uint8) *symbols.Table {
	t := symbols.NewTable("s41", pointerSize)
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 16, Fields: []symbols.Field{field("Flink", 0), field("Blink", 8)}})
	t.AddStruct(symbols.StructType{Name: "_UNICODE_STRING", Size: 16, Fields: []symbols.Field{
		field("Length", 0), field("MaximumLength", 2), field("Buffer", 8)}})
	t.AddStruct(symbols.StructType{Name: "_RTL_BALANCED_LINKS", Size: 0x20, Fields: []symbols.Field{
		field("Parent", 0), field("LeftChild", 8), field("RightChild", 0x10), field("Balance", 0x18)}})
	t.AddStruct(symbols.StructType{Name: "_RTL_AVL_TABLE", Size: 0x68, Fields: []symbols.Field{
		field("BalancedRoot", 0), field("NumberGenericTableElements", 0x2c), field("CompareRoutine", 0x48)}})
	return t
}

const (
	pool       = uint64(0xFFFF900000000000)
	handleAddr = uint64(0xFFFFF80010020000)
	cacheAddr  = pool + 0x100
	storeAddr  = pool + 0x1000
	linksSize  = uint64(0x20)
)

type s41Entry struct {
	key  string
	time uint64
	data []byte
}

type s41Cache struct {
	mem     sparse
	table   *symbols.Table
	nodes   []uint64
	limits  limits.Limits
	diags   []string
	counted uint32
}

func (f *s41Cache) element(i int) uint64 { return f.nodes[i] + linksSize }

func (f *s41Cache) dataAt(i int) uint64 { return f.nodes[i] + 0x200 }

func (f *s41Cache) keyAt(i int) uint64 { return pool + 0x200000 + uint64(i)*0x1000 }

func (f *s41Cache) blobAt(i int) uint64 { return pool + 0x400000 + uint64(i)*0x1000 }

func (f *s41Cache) ctx(strict bool) tools.Context {
	options := map[string]any{"diagnostics": &f.diags}
	if strict {
		options["strict"] = true
	}
	return tools.Context{Memory: f.mem, Symbols: f.table, Profile: profiles.WindowsX64Profile{}, Options: options,
		Limits: f.limits}
}

// Entries are in list order, most recent first, laid out as L1 to L11; the
// tree is balanced over the keys, case folded, as C5 orders it.
func newS41Cache(entries []s41Entry) *s41Cache {
	f := &s41Cache{mem: sparse{}, table: s41Table(8)}
	f.mem.u64(handleAddr, cacheAddr)
	f.mem.u64(cacheAddr, pool+0x80)
	f.mem.u64(cacheAddr+cacheStoreOffset, storeAddr)
	for i, e := range entries {
		node := pool + 0x10000 + uint64(i)*0x1000
		f.nodes = append(f.nodes, node)
		el := node + linksSize
		data := f.dataAt(i)
		keyBuf := f.keyAt(i)
		blob := f.blobAt(i)
		kb := utf16le(e.key)
		f.mem.u16(el+elementKeyOffset, uint16(len(kb)))
		f.mem.u16(el+elementKeyOffset+2, uint16(len(kb)+2))
		f.mem.u64(el+elementKeyOffset+8, keyBuf)
		f.mem.write(keyBuf, kb)
		f.mem.u64(el+elementDataOffset, data)
		f.mem.u64(data, pool+0x90)
		f.mem.u64(data+dataTimeOffset, e.time)
		f.mem.u32(data+dataSizeOffset, uint32(len(e.data)))
		f.mem.u64(data+dataBufferOffset, blob)
		f.mem.write(blob, e.data)
	}
	f.linkList(f.allElements()...)
	order := make([]int, len(entries))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool {
		return strings.ToUpper(entries[order[a]].key) < strings.ToUpper(entries[order[b]].key)
	})
	sentinel := storeAddr
	f.mem.u64(sentinel+0x10, f.build(order, sentinel))
	f.counted = uint32(len(entries))
	f.mem.u32(storeAddr+0x2c, f.counted)
	return f
}

func (f *s41Cache) allElements() []uint64 {
	out := make([]uint64, len(f.nodes))
	for i := range f.nodes {
		out[i] = f.element(i)
	}
	return out
}

func (f *s41Cache) linkList(entries ...uint64) {
	head := storeAddr + storeListOffset
	all := append([]uint64{head}, entries...)
	for i, at := range all {
		f.mem.u64(at, all[(i+1)%len(all)])
		f.mem.u64(at+8, all[(i+len(all)-1)%len(all)])
	}
}

func (f *s41Cache) build(order []int, parent uint64) uint64 {
	if len(order) == 0 {
		return 0
	}
	mid := len(order) / 2
	node := f.nodes[order[mid]]
	f.mem.u64(node, parent)
	f.mem.u64(node+8, f.build(order[:mid], node))
	f.mem.u64(node+0x10, f.build(order[mid+1:], node))
	return node
}
