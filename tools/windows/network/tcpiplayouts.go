package network

import (
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
)

// tcpip.pdb carries publics only, so the session merges these measured
// private types into the kernel table (S67). The names are the project's
// labels for what each measured member holds.
const (
	typeTCPEndpoint = "tcpEndpoint"
	typeTCPListener = "tcpListener"
	typeUDPEndpoint = "udpEndpoint"

	memberInetAF       = "inetAF"
	memberAddressInfo  = "addressInfo"
	memberListEntry    = "listEntry"
	memberState        = "state"
	memberLocalPort    = "localPort"
	memberRemotePort   = "remotePort"
	memberOwner        = "owner"
	memberCreateTime   = "createTime"
	memberLocalAddress = "localAddress"
	memberNext         = "next"

	typeInetAF   = "inetAF"
	memberFamily = "family"

	typeAddressInfo = "addressInfo"
	memberLocal     = "local"
	memberRemote    = "remote"

	typeLocalAddress = "localAddress"
	memberAddress    = "address"

	typeAddressBytes = "inAddr"

	typePartition   = "partition"
	memberEndpoints = "endpoints"

	typeCompartmentSet      = "compartmentSet"
	memberCompartment       = "compartment"
	typeCompartment         = "compartment"
	memberProtocol          = "protocol"
	typeProtocolCompartment = "protocolCompartment"
	memberPortPool          = "portPool"
	typePortPool            = "portPool"
	memberBitmap            = "bitmap"
	memberAssignments       = "assignments"
	typePortAssignment      = "portAssignment"
	memberList              = "list"
	typePortAssignmentList  = "portAssignmentList"
	memberObject            = "object"
	typePortAssignmentEntry = "portAssignmentEntry"
)

// One port-assignment block covers the low byte of a port (S28 D5, M5), so a
// pool holds 65,536 / 256 of them.
const assignmentBlocks = 256

const pointerBytes64 = 8

// The captures whose data and code agreed on an offset (S67 section 3).
type measuredOffset struct {
	off      uint64
	captures []string
}

func (m measuredOffset) present() bool { return len(m.captures) > 0 }

func seen(off uint64, captures ...string) measuredOffset {
	return measuredOffset{off: off, captures: captures}
}

type connectionOffsets struct {
	inetAF, addressInfo, listEntry, state measuredOffset
	localPort, remotePort, createTime     measuredOffset
	owners                                []measuredOffset
}

type boundOffsets struct {
	inetAF, owner, createTime, localAddress, localPort, next measuredOffset
}

type tableOffsets struct {
	partitionSize, partitionEndpoints   measuredOffset
	compartment, protocol, portPool     measuredOffset
	bitmap, assignments, assignmentList measuredOffset
	entryObject, entrySize              measuredOffset
}

type tcpipBuildLayout struct {
	name        string
	first, last uint32

	connection         connectionOffsets
	listener, datagram boundOffsets
	family             measuredOffset
	local, remote      measuredOffset
	addressOfLocal     measuredOffset
	tables             *tableOffsets
}

// Builds outside these ranges are refused: another build's offsets would
// decode plausible rows from the wrong places. 14393's walk members were
// measured (S67 M9) but are not merged, so only the scan runs there (O3).
var tcpipBuildLayouts = []tcpipBuildLayout{
	{
		name: "tcpip-14393", first: 14393, last: 14393,
		connection: connectionOffsets{
			inetAF: seen(0x10, "mem5"), addressInfo: seen(0x18, "mem5"), state: seen(0x6c, "mem5"),
			localPort: seen(0x70, "mem5"), remotePort: seen(0x72, "mem5"), createTime: seen(0x268, "mem5"),
			owners: []measuredOffset{seen(0x258, "mem5")},
		},
		listener: boundOffsets{
			owner: seen(0x30, "mem5"), createTime: seen(0x40, "mem5"), localAddress: seen(0x60, "mem5"),
			inetAF: seen(0x68, "mem5"), localPort: seen(0x72, "mem5"),
		},
		datagram: boundOffsets{
			inetAF: seen(0x20, "mem5"), owner: seen(0x28, "mem5"), createTime: seen(0x58, "mem5"),
			localAddress: seen(0x60, "mem5"), localPort: seen(0x78, "mem5"),
		},
		family: seen(0x18, "mem5"), local: seen(0x0, "mem5"), remote: seen(0x10, "mem5"),
		addressOfLocal: seen(0x10, "mem5"),
	},
	{
		name: "tcpip-19041-19045", first: 19041, last: 19045,
		connection: connectionOffsets{
			inetAF: seen(0x10, "mem2"), addressInfo: seen(0x18, "mem2"), listEntry: seen(0x28, "mem2"),
			state: seen(0x6c, "mem2"), localPort: seen(0x70, "mem2"), remotePort: seen(0x72, "mem2"),
			createTime: seen(0x2e8, "mem2"), owners: []measuredOffset{seen(0x2d8, "mem2")},
		},
		listener: boundOffsets{
			owner: seen(0x30, "mem2"), createTime: seen(0x40, "mem2"), localAddress: seen(0x60, "mem2"),
			inetAF: seen(0x68, "mem2"), localPort: seen(0x72, "mem2"), next: seen(0x78, "mem2"),
		},
		datagram: boundOffsets{
			inetAF: seen(0x20, "mem2"), owner: seen(0x28, "mem2"), createTime: seen(0x58, "mem2"),
			localAddress: seen(0x60, "mem2"), next: seen(0x70, "mem2"), localPort: seen(0xa0, "mem2"),
		},
		family: seen(0x18, "mem2"), local: seen(0x0, "mem2"), remote: seen(0x10, "mem2"),
		addressOfLocal: seen(0x10, "mem2"),
		tables: &tableOffsets{
			partitionSize: seen(0xc0, "mem2"), partitionEndpoints: seen(0x8, "mem2"),
			compartment: seen(0x148, "mem2"), protocol: seen(0x20, "mem2"), portPool: seen(0x0, "mem2"),
			bitmap: seen(0xd0, "mem2"), assignments: seen(0xe0, "mem2"), assignmentList: seen(0x18, "mem2"),
			entryObject: seen(0x10, "mem2"), entrySize: seen(0x20, "mem2"),
		},
	},
	{
		// Two tcpip.sys versions share build 26100 and move the owner
		// (S67 M6); the createTime both hold is the one mem1's code reads.
		name: "tcpip-26100", first: 26100, last: 26100,
		connection: connectionOffsets{
			inetAF: seen(0x18, "mem1", "mem6", "mem7"), addressInfo: seen(0x20, "mem1", "mem6", "mem7"),
			listEntry: seen(0x30, "mem1", "mem6", "mem7"), state: seen(0x70, "mem1", "mem6", "mem7"),
			localPort: seen(0x74, "mem1", "mem6", "mem7"), remotePort: seen(0x76, "mem1", "mem6", "mem7"),
			createTime: seen(0x360, "mem1", "mem6", "mem7"),
			owners:     []measuredOffset{seen(0x348, "mem6", "mem7"), seen(0x350, "mem1")},
		},
		listener: boundOffsets{
			owner: seen(0x38, "mem1", "mem6", "mem7"), createTime: seen(0x48, "mem1", "mem6", "mem7"),
			localAddress: seen(0x68, "mem1", "mem6", "mem7"), inetAF: seen(0x70, "mem1", "mem6", "mem7"),
			localPort: seen(0x7a, "mem1", "mem6", "mem7"), next: seen(0x80, "mem1", "mem6", "mem7"),
		},
		datagram: boundOffsets{
			inetAF: seen(0x28, "mem1", "mem6", "mem7"), owner: seen(0x30, "mem1", "mem6", "mem7"),
			createTime: seen(0x60, "mem1", "mem6", "mem7"), localAddress: seen(0x68, "mem1", "mem6", "mem7"),
			next: seen(0x78, "mem1", "mem6", "mem7"), localPort: seen(0xa8, "mem1", "mem6", "mem7"),
		},
		family: seen(0x18, "mem1", "mem6", "mem7"), local: seen(0x0, "mem1", "mem6", "mem7"),
		remote: seen(0x10, "mem1", "mem6", "mem7"), addressOfLocal: seen(0x10, "mem1", "mem6", "mem7"),
		tables: &tableOffsets{
			partitionSize: seen(0xc0, "mem1", "mem6", "mem7"), partitionEndpoints: seen(0x8, "mem1", "mem6", "mem7"),
			compartment: seen(0x148, "mem1", "mem6", "mem7"), protocol: seen(0x20, "mem1", "mem6", "mem7"),
			portPool: seen(0x0, "mem1", "mem6", "mem7"), bitmap: seen(0xd0, "mem1", "mem6", "mem7"),
			assignments: seen(0xe0, "mem1", "mem6", "mem7"), assignmentList: seen(0x18, "mem1", "mem6", "mem7"),
			entryObject: seen(0x10, "mem1", "mem6", "mem7"), entrySize: seen(0x20, "mem1", "mem6", "mem7"),
		},
	},
}

func LayoutForBuild(build uint32) (symbols.SymbolTable, error) {
	for i := range tcpipBuildLayouts {
		if l := &tcpipBuildLayouts[i]; build >= l.first && build <= l.last {
			return l.symbolTable(), nil
		}
	}
	return nil, fmt.Errorf("no measured tcpip.sys layout for Windows build %d", build)
}

func LayoutBuilds(name string) (first, last uint32, ok bool) {
	if l := layoutNamed(name); l != nil {
		return l.first, l.last, true
	}
	return 0, 0, false
}

func layoutNamed(name string) *tcpipBuildLayout {
	for i := range tcpipBuildLayouts {
		if tcpipBuildLayouts[i].name == name {
			return &tcpipBuildLayouts[i]
		}
	}
	return nil
}

func pointerRef(to string) symbols.TypeRef {
	return symbols.TypeRef{Name: to, IsPointer: true, Element: &symbols.TypeRef{Name: to}}
}

var (
	ref16 = symbols.TypeRef{Name: "unsigned short"}
	ref32 = symbols.TypeRef{Name: "unsigned long"}
	ref64 = symbols.TypeRef{Name: "unsigned long long"}
)

type structBuilder struct {
	name   string
	size   uint64
	fields []symbols.Field
}

func (b *structBuilder) member(name string, m measuredOffset, ref symbols.TypeRef, width uint64) {
	if !m.present() {
		return
	}
	b.fields = append(b.fields, symbols.Field{Name: name, Offset: m.off, Type: ref})
	b.size = max(b.size, m.off+width)
}

func (b *structBuilder) addTo(t *symbols.Table) {
	if len(b.fields) > 0 || b.size > 0 {
		t.AddStruct(symbols.StructType{Name: b.name, Size: b.size, Fields: b.fields})
	}
}

// A struct's size is the end of its last measured member; the decoder reads
// no further. Partition and port-assignment-entry sizes are array strides.
func (l *tcpipBuildLayout) symbolTable() *symbols.Table {
	t := symbols.NewTable(l.name, pointerBytes64)
	t.SetPlatform(symbols.PlatformWindows)
	const p = pointerBytes64

	c := l.connection
	conn := &structBuilder{name: typeTCPEndpoint}
	conn.member(memberInetAF, c.inetAF, pointerRef(typeInetAF), p)
	conn.member(memberAddressInfo, c.addressInfo, pointerRef(typeAddressInfo), p)
	conn.member(memberListEntry, c.listEntry, symbols.TypeRef{Name: "_LIST_ENTRY"}, 2*p)
	conn.member(memberState, c.state, ref32, 4)
	conn.member(memberLocalPort, c.localPort, ref16, 2)
	conn.member(memberRemotePort, c.remotePort, ref16, 2)
	conn.member(memberCreateTime, c.createTime, ref64, 8)
	for i, o := range c.owners {
		if i == 0 {
			conn.member(memberOwner, o, pointerRef("_EPROCESS"), p)
		} else if o.present() {
			conn.size = max(conn.size, o.off+p)
		}
	}
	conn.addTo(t)

	for _, k := range []struct {
		name string
		b    boundOffsets
	}{{typeTCPListener, l.listener}, {typeUDPEndpoint, l.datagram}} {
		sb := &structBuilder{name: k.name}
		sb.member(memberInetAF, k.b.inetAF, pointerRef(typeInetAF), p)
		sb.member(memberOwner, k.b.owner, pointerRef("_EPROCESS"), p)
		sb.member(memberCreateTime, k.b.createTime, ref64, 8)
		sb.member(memberLocalAddress, k.b.localAddress, pointerRef(typeLocalAddress), p)
		sb.member(memberLocalPort, k.b.localPort, ref16, 2)
		sb.member(memberNext, k.b.next, pointerRef(k.name), p)
		sb.addTo(t)
	}

	af := &structBuilder{name: typeInetAF}
	af.member(memberFamily, l.family, ref16, 2)
	af.addTo(t)
	info := &structBuilder{name: typeAddressInfo}
	info.member(memberLocal, l.local, pointerRef(typeLocalAddress), p)
	info.member(memberRemote, l.remote, pointerRef(typeAddressBytes), p)
	info.addTo(t)
	holder := symbols.TypeRef{Name: typeAddressBytes, IsPointer: true, Element: &symbols.TypeRef{
		Name: typeAddressBytes, IsPointer: true, Element: &symbols.TypeRef{Name: typeAddressBytes}}}
	la := &structBuilder{name: typeLocalAddress}
	la.member(memberAddress, l.addressOfLocal, holder, p)
	la.addTo(t)

	tb := l.tables
	if tb == nil {
		return t
	}
	part := &structBuilder{name: typePartition}
	part.member(memberEndpoints, tb.partitionEndpoints, pointerRef("_RTL_DYNAMIC_HASH_TABLE"), p)
	part.size = tb.partitionSize.off
	part.addTo(t)
	set := &structBuilder{name: typeCompartmentSet}
	set.member(memberCompartment, tb.compartment, pointerRef(typeCompartment), p)
	set.addTo(t)
	comp := &structBuilder{name: typeCompartment}
	comp.member(memberProtocol, tb.protocol, pointerRef(typeProtocolCompartment), p)
	comp.addTo(t)
	proto := &structBuilder{name: typeProtocolCompartment}
	proto.member(memberPortPool, tb.portPool, pointerRef(typePortPool), p)
	proto.addTo(t)
	pool := &structBuilder{name: typePortPool}
	pool.member(memberBitmap, tb.bitmap, symbols.TypeRef{Name: "_RTL_BITMAP"}, 2*p)
	pool.member(memberAssignments, tb.assignments, symbols.TypeRef{
		Name: typePortAssignment, IsArray: true, ArrayLength: assignmentBlocks,
		Element: &symbols.TypeRef{Name: typePortAssignment, IsPointer: true, Element: &symbols.TypeRef{Name: typePortAssignment}},
	}, assignmentBlocks*p)
	pool.addTo(t)
	assign := &structBuilder{name: typePortAssignment}
	assign.member(memberList, tb.assignmentList, pointerRef(typePortAssignmentList), p)
	assign.addTo(t)
	list := &structBuilder{name: typePortAssignmentList}
	list.member(memberObject, tb.entryObject, pointerRef("void"), p)
	list.addTo(t)
	entry := &structBuilder{name: typePortAssignmentEntry, size: tb.entrySize.off}
	entry.addTo(t)
	return t
}
