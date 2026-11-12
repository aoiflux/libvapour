package network

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"testing"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	fxKernel      = uint64(0xffffa00000000000)
	fxSharedData  = uint64(0xFFFFF78000000000)
	fxPage        = uint64(0x1000)
	fxPIDAt       = uint64(0x440)
	fxImageAt     = uint64(0x5a8)
	fxProcessSize = uint64(0x800)
	fxLayout      = "tcpip-26100"
	fxBuckets     = 128
	fxBoot        = uint64(133_000_000_000_000_000)
	fxNow         = fxBoot + 36_000_000_000
	fxCreated     = fxBoot + 1_000_000_000
)

var errUnmapped = errors.New("fixture: address not mapped")

type sparse map[uint64][]byte

func (m sparse) ReadAt(off, size uint64) ([]byte, error) {
	out := make([]byte, 0, size)
	for size > 0 {
		page, ok := m[off&^(fxPage-1)]
		if !ok {
			return nil, errUnmapped
		}
		in := off & (fxPage - 1)
		n := min(size, fxPage-in)
		out = append(out, page[in:in+n]...)
		off, size = off+n, size-n
	}
	return out, nil
}

func (m sparse) Size() uint64 { return math.MaxUint64 }

func (m sparse) write(at uint64, b []byte) {
	for len(b) > 0 {
		base := at &^ (fxPage - 1)
		page, ok := m[base]
		if !ok {
			page = make([]byte, fxPage)
			m[base] = page
		}
		n := copy(page[at-base:], b)
		at, b = at+uint64(n), b[n:]
	}
}

func (m sparse) u16(at uint64, v uint16) { m.write(at, binary.LittleEndian.AppendUint16(nil, v)) }
func (m sparse) u32(at uint64, v uint32) { m.write(at, binary.LittleEndian.AppendUint32(nil, v)) }
func (m sparse) u64(at uint64, v uint64) { m.write(at, binary.LittleEndian.AppendUint64(nil, v)) }

type world struct {
	tb    testing.TB
	t     *symbols.Table
	k     sparse
	next  uint64
	diags []string
}

func u(name string) symbols.TypeRef { return symbols.TypeRef{Name: name} }

func ptr(name string) symbols.TypeRef {
	return symbols.TypeRef{Name: name, IsPointer: true, Element: &symbols.TypeRef{Name: name}}
}

func bits(name string, at, n uint8) symbols.TypeRef {
	return symbols.TypeRef{Name: name, BitOffset: at, BitLength: n}
}

func newWorld(tb testing.TB) *world {
	tb.Helper()
	st, err := LayoutForBuild(26100)
	if err != nil {
		tb.Fatal(err)
	}
	t := st.(*symbols.Table)
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 16, Fields: []symbols.Field{
		{Name: "Flink", Offset: 0, Type: ptr("_LIST_ENTRY")}, {Name: "Blink", Offset: 8, Type: ptr("_LIST_ENTRY")}}})
	t.AddStruct(symbols.StructType{Name: "_RTL_DYNAMIC_HASH_TABLE", Size: 40, Fields: []symbols.Field{
		{Name: "TableSize", Offset: 8, Type: u("unsigned int")}, {Name: "NumEntries", Offset: 0x14, Type: u("unsigned int")},
		{Name: "Directory", Offset: 0x20, Type: ptr("void")}}})
	t.AddStruct(symbols.StructType{Name: "_RTL_BITMAP", Size: 16, Fields: []symbols.Field{
		{Name: "SizeOfBitMap", Offset: 0, Type: u("unsigned int")}, {Name: "Buffer", Offset: 8, Type: ptr("unsigned int")}}})
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: fxProcessSize, Fields: []symbols.Field{
		{Name: "UniqueProcessId", Offset: fxPIDAt, Type: ptr("void")},
		{Name: "ImageFileName", Offset: fxImageAt, Type: symbols.TypeRef{Name: "unsigned char", IsArray: true, ArrayLength: 15,
			Element: &symbols.TypeRef{Name: "unsigned char"}}}}})
	t.AddStruct(symbols.StructType{Name: "_KUSER_SHARED_DATA", Size: 0x720, Fields: []symbols.Field{
		{Name: "SystemTime", Offset: 0x14, Type: u("_KSYSTEM_TIME")}}})
	t.AddStruct(symbols.StructType{Name: "_POOL_HEADER", Size: 16, Fields: []symbols.Field{
		{Name: "PreviousSize", Offset: 0, Type: bits("unsigned short", 0, 8)},
		{Name: "PoolIndex", Offset: 0, Type: bits("unsigned short", 8, 8)},
		{Name: "BlockSize", Offset: 2, Type: bits("unsigned short", 0, 8)},
		{Name: "PoolType", Offset: 2, Type: bits("unsigned short", 8, 8)},
		{Name: "PoolTag", Offset: 4, Type: u("unsigned int")}}})
	w := &world{tb: tb, t: t, k: sparse{}, next: fxKernel + 0x10000}
	boot, bias := w.alloc(8), w.alloc(8)
	w.k.u64(boot, fxBoot)
	t.AddSymbol(symbols.Symbol{Name: "KeBootTime", Address: boot})
	t.AddSymbol(symbols.Symbol{Name: "KeBootTimeBias", Address: bias})
	w.k.u64(fxSharedData+0x14, fxNow)
	return w
}

func (w *world) off(typ, member string) uint64 {
	f, err := w.t.Field(typ, member)
	if err != nil {
		w.tb.Fatal(err)
	}
	return f.Offset
}

func (w *world) size(typ string) uint64 {
	st, err := w.t.Struct(typ)
	if err != nil {
		w.tb.Fatal(err)
	}
	return st.Size
}

func (w *world) alloc(n uint64) uint64 {
	at := w.next
	w.next += (n+0xf)&^0xf + 0x10
	w.k.write(at, make([]byte, n))
	return at
}

func (w *world) process(pid uint64, name string) uint64 {
	at := w.alloc(fxProcessSize)
	w.k.u64(at+fxPIDAt, pid)
	w.k.write(at+fxImageAt, []byte(name))
	return at
}

func (w *world) family(v uint16) uint64 {
	at := w.alloc(w.size(typeInetAF))
	w.k.u16(at+w.off(typeInetAF, memberFamily), v)
	return at
}

func (w *world) ipBytes(a netip.Addr) uint64 {
	b := a.AsSlice()
	at := w.alloc(uint64(len(b)))
	w.k.write(at, b)
	return at
}

func (w *world) localAddressObject(a netip.Addr) uint64 {
	cell := w.alloc(8)
	w.k.u64(cell, w.ipBytes(a))
	obj := w.alloc(w.size(typeLocalAddress))
	w.k.u64(obj+w.off(typeLocalAddress, memberAddress), cell)
	return obj
}

func familyValue(a netip.Addr) uint16 {
	if a.Is4() {
		return addressFamilyInet
	}
	return addressFamilyInet6
}

type connSpec struct {
	family       uint64
	info         uint64
	local        netip.Addr
	remote       netip.Addr
	lport, rport uint16
	state        uint32
	owner        uint64
	ownerSlot    int
	created      uint64
}

func (w *world) defaultConn() connSpec {
	return connSpec{
		local: netip.MustParseAddr("10.0.0.5"), remote: netip.MustParseAddr("93.184.216.34"),
		lport: 49700, rport: 443, state: 4, owner: w.process(1236, "chrome.exe"), created: fxCreated,
	}
}

func be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

func (w *world) connectionBody(c connSpec) []byte {
	b := make([]byte, w.size(typeTCPEndpoint))
	fam := c.family
	if fam == 0 {
		fam = w.family(familyValue(c.local))
	}
	info := c.info
	if info == 0 {
		info = w.alloc(w.size(typeAddressInfo))
		w.k.u64(info+w.off(typeAddressInfo, memberLocal), w.localAddressObject(c.local))
		w.k.u64(info+w.off(typeAddressInfo, memberRemote), w.ipBytes(c.remote))
	}
	put := func(at uint64, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }
	put(w.off(typeTCPEndpoint, memberInetAF), fam)
	put(w.off(typeTCPEndpoint, memberAddressInfo), info)
	binary.LittleEndian.PutUint32(b[w.off(typeTCPEndpoint, memberState):], c.state)
	copy(b[w.off(typeTCPEndpoint, memberLocalPort):], be16(c.lport))
	copy(b[w.off(typeTCPEndpoint, memberRemotePort):], be16(c.rport))
	owners := ownerOffsets(fxLayout, w.off(typeTCPEndpoint, memberOwner))
	put(owners[c.ownerSlot], c.owner)
	put(w.off(typeTCPEndpoint, memberCreateTime), c.created)
	return b
}

func (w *world) connection(c connSpec) uint64 {
	b := w.connectionBody(c)
	at := w.alloc(uint64(len(b)))
	w.k.write(at, b)
	return at
}

type boundSpec struct {
	kind    EndpointKind
	family  uint16
	local   netip.Addr
	port    uint16
	owner   uint64
	created uint64
}

func (w *world) typeOf(k EndpointKind) string {
	if k == KindListener {
		return typeTCPListener
	}
	return typeUDPEndpoint
}

func (w *world) boundBody(s boundSpec) []byte {
	typ := w.typeOf(s.kind)
	b := make([]byte, w.size(typ))
	put := func(at uint64, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }
	put(w.off(typ, memberInetAF), w.family(s.family))
	if s.local.IsValid() && !s.local.IsUnspecified() {
		put(w.off(typ, memberLocalAddress), w.localAddressObject(s.local))
	}
	copy(b[w.off(typ, memberLocalPort):], be16(s.port))
	put(w.off(typ, memberOwner), s.owner)
	put(w.off(typ, memberCreateTime), s.created)
	return b
}

func (w *world) bound(s boundSpec) uint64 {
	b := w.boundBody(s)
	at := w.alloc(uint64(len(b)))
	w.k.write(at, b)
	return at
}

// buckets[p][b] lists the connections chained on bucket b of partition p.
func (w *world) partitions(buckets []map[int][]uint64) (table, count uint64) {
	psize := w.size(typePartition)
	parts := w.alloc(psize * uint64(len(buckets)))
	link := w.off(typeTCPEndpoint, memberListEntry)
	for p, chains := range buckets {
		hash := w.alloc(40)
		dir := w.alloc(16 * fxBuckets)
		w.k.u32(hash+8, fxBuckets)
		w.k.u64(hash+0x20, dir)
		entries := 0
		for b := range fxBuckets {
			head := dir + uint64(b)*16
			nodes := []uint64{head}
			for _, obj := range chains[b] {
				nodes = append(nodes, obj+link)
			}
			entries += len(chains[b])
			for i, n := range nodes {
				w.k.u64(n, nodes[(i+1)%len(nodes)])
				w.k.u64(n+8, nodes[(i+len(nodes)-1)%len(nodes)])
			}
		}
		w.k.u32(hash+0x14, uint32(entries))
		w.k.u64(parts+uint64(p)*psize+w.off(typePartition, memberEndpoints), hash)
	}
	table, count = w.alloc(8), w.alloc(4)
	w.k.u64(table, parts)
	w.k.u32(count, uint32(len(buckets)))
	return table, count
}

type portChain struct {
	flags   uint64
	objects []uint64
}

func (w *world) portPool(kind EndpointKind, ports map[uint16]portChain) uint64 {
	pool := w.alloc(w.size(typePortPool))
	bitmap := pool + w.off(typePortPool, memberBitmap)
	buffer := w.alloc(portSpace / 8)
	w.k.u32(bitmap, portSpace)
	w.k.u64(bitmap+8, buffer)
	next := w.off(w.typeOf(kind), memberNext)
	entrySize := w.size(typePortAssignmentEntry)
	blocks := map[uint64]uint64{}
	for port, c := range ports {
		byteAt := buffer + uint64(port/8)
		old, _ := w.k.ReadAt(byteAt, 1)
		w.k.write(byteAt, []byte{old[0] | 1<<(port%8)})
		block := uint64(port) >> portBlockShift
		list, ok := blocks[block]
		if !ok {
			assignment := w.alloc(w.size(typePortAssignment))
			list = w.alloc(w.off(typePortAssignmentList, memberObject) + portBlock*entrySize)
			w.k.u64(assignment+w.off(typePortAssignment, memberList), list)
			w.k.u64(pool+w.off(typePortPool, memberAssignments)+block*8, assignment)
			blocks[block] = list
		}
		entry := list + w.off(typePortAssignmentList, memberObject) + uint64(port%portBlock)*entrySize
		value := uint64(0)
		for i := len(c.objects) - 1; i >= 0; i-- {
			w.k.u64(c.objects[i]+next, value)
			value = (c.objects[i] + next) | c.flags
		}
		w.k.u64(entry, value)
	}
	protocol := w.alloc(w.size(typeProtocolCompartment))
	w.k.u64(protocol+w.off(typeProtocolCompartment, memberPortPool), pool)
	compartment := w.alloc(w.size(typeCompartment))
	w.k.u64(compartment+w.off(typeCompartment, memberProtocol), protocol)
	set := w.alloc(w.size(typeCompartmentSet))
	w.k.u64(set+w.off(typeCompartmentSet, memberCompartment), compartment)
	global := w.alloc(8)
	w.k.u64(global, set)
	return global
}

func (w *world) ctx(options map[string]any) tools.Context {
	w.diags = nil
	opts := map[string]any{tools.OptionNetworkScanLayout: fxLayout, "diagnostics": &w.diags}
	for k, v := range options {
		opts[k] = v
	}
	return tools.Context{Memory: w.k, Symbols: w.t, Profile: profiles.WindowsX64Profile{}, Options: opts}
}

func (w *world) decoder(ctx tools.Context) decoder {
	w.tb.Helper()
	l, err := resolveLayout(ctx)
	if err != nil {
		w.tb.Fatal(err)
	}
	return newDecoder(ctx, l)
}
