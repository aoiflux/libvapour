package network

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

const pointerBytes = 8

type connectionMembers struct {
	size                                                          uint64
	inetAF, addressInfo, state, localPort, remotePort, createTime uint64
	owners                                                        []uint64
	link                                                          uint64
	hasLink                                                       bool
}

type boundMembers struct {
	size                                               uint64
	inetAF, owner, createTime, localAddress, localPort uint64
	next                                               uint64
	hasNext                                            bool
}

type tableMembers struct {
	partitionSize, endpoints                             uint64
	compartment, protocol, portPool, bitmap, assignments uint64
	assignmentList, entryObject, entrySize               uint64
	hashTableSize, hashEntries, hashDirectory            symbols.Field
	bitmapBits, bitmapBuffer                             symbols.Field
	listEntrySize                                        uint64
}

type objectLayout struct {
	name                string
	connection          connectionMembers
	listener, datagram  boundMembers
	family              uint64
	localInfo, remoteIP uint64
	addressOfLocal      uint64
	tables              *tableMembers
}

func (l *objectLayout) bound(k EndpointKind) boundMembers {
	if k == KindListener {
		return l.listener
	}
	return l.datagram
}

type memberReader struct {
	t   symbols.SymbolTable
	err error
}

func (m *memberReader) at(typ, member string) uint64 {
	f, err := m.t.Field(typ, member)
	if err != nil {
		if m.err == nil {
			m.err = fmt.Errorf("%s.%s: %w: %w", typ, member, ErrLayout, err)
		}
		return 0
	}
	return f.Offset
}

func (m *memberReader) optional(typ, member string) (uint64, bool) {
	f, err := m.t.Field(typ, member)
	return f.Offset, err == nil
}

func (m *memberReader) size(typ string) uint64 {
	st, err := m.t.Struct(typ)
	if err != nil || st.Size == 0 {
		if m.err == nil {
			m.err = fmt.Errorf("%s: %w: %v", typ, ErrLayout, err)
		}
		return 0
	}
	return st.Size
}

func (m *memberReader) field(typ, member string) symbols.Field {
	f, err := m.t.Field(typ, member)
	if err != nil && m.err == nil {
		m.err = fmt.Errorf("%s.%s: %w: %w", typ, member, ErrLayout, err)
	}
	return f
}

// The session merges the measured layout into the kernel table; a layout for
// another build would decode plausible rows from the wrong places, so a
// missing member stops the tool.
func resolveLayout(ctx tools.Context) (*objectLayout, error) {
	m := &memberReader{t: ctx.Symbols}
	l := &objectLayout{name: ctx.NetworkScanLayout()}
	c := &l.connection
	c.size = m.size(typeTCPEndpoint)
	c.inetAF = m.at(typeTCPEndpoint, memberInetAF)
	c.addressInfo = m.at(typeTCPEndpoint, memberAddressInfo)
	c.state = m.at(typeTCPEndpoint, memberState)
	c.localPort = m.at(typeTCPEndpoint, memberLocalPort)
	c.remotePort = m.at(typeTCPEndpoint, memberRemotePort)
	c.createTime = m.at(typeTCPEndpoint, memberCreateTime)
	c.owners = ownerOffsets(l.name, m.at(typeTCPEndpoint, memberOwner))
	c.link, c.hasLink = m.optional(typeTCPEndpoint, memberListEntry)
	for _, b := range []struct {
		typ string
		out *boundMembers
	}{{typeTCPListener, &l.listener}, {typeUDPEndpoint, &l.datagram}} {
		b.out.size = m.size(b.typ)
		b.out.inetAF = m.at(b.typ, memberInetAF)
		b.out.owner = m.at(b.typ, memberOwner)
		b.out.createTime = m.at(b.typ, memberCreateTime)
		b.out.localAddress = m.at(b.typ, memberLocalAddress)
		b.out.localPort = m.at(b.typ, memberLocalPort)
		b.out.next, b.out.hasNext = m.optional(b.typ, memberNext)
	}
	l.family = m.at(typeInetAF, memberFamily)
	l.localInfo = m.at(typeAddressInfo, memberLocal)
	l.remoteIP = m.at(typeAddressInfo, memberRemote)
	l.addressOfLocal = m.at(typeLocalAddress, memberAddress)
	if m.err != nil {
		return nil, m.err
	}
	if t, ok := resolveTables(ctx.Symbols, c.hasLink && l.listener.hasNext && l.datagram.hasNext); ok {
		l.tables = t
	}
	return l, nil
}

// One build's measured layout can hold more than one owner offset (M10); the
// table carries the first, the layout record the rest.
func ownerOffsets(layoutName string, fromTable uint64) []uint64 {
	out := []uint64{fromTable}
	if rec := layoutNamed(layoutName); rec != nil {
		for _, o := range rec.connection.owners {
			if o.present() && o.off != fromTable {
				out = append(out, o.off)
			}
		}
	}
	return out
}

func resolveTables(t symbols.SymbolTable, linked bool) (*tableMembers, bool) {
	if !linked {
		return nil, false
	}
	m := &memberReader{t: t}
	tb := &tableMembers{
		partitionSize:  m.size(typePartition),
		endpoints:      m.at(typePartition, memberEndpoints),
		compartment:    m.at(typeCompartmentSet, memberCompartment),
		protocol:       m.at(typeCompartment, memberProtocol),
		portPool:       m.at(typeProtocolCompartment, memberPortPool),
		bitmap:         m.at(typePortPool, memberBitmap),
		assignments:    m.at(typePortPool, memberAssignments),
		assignmentList: m.at(typePortAssignment, memberList),
		entryObject:    m.at(typePortAssignmentList, memberObject),
		entrySize:      m.size(typePortAssignmentEntry),
		hashTableSize:  m.field("_RTL_DYNAMIC_HASH_TABLE", "TableSize"),
		hashEntries:    m.field("_RTL_DYNAMIC_HASH_TABLE", "NumEntries"),
		hashDirectory:  m.field("_RTL_DYNAMIC_HASH_TABLE", "Directory"),
		bitmapBits:     m.field("_RTL_BITMAP", "SizeOfBitMap"),
		bitmapBuffer:   m.field("_RTL_BITMAP", "Buffer"),
		listEntrySize:  m.size("_LIST_ENTRY"),
	}
	return tb, m.err == nil
}

// S17 F5: on 64-bit Windows user space ends at 0x7FFF'FFFFFFFF, so a
// canonical system-space address has bit 63 set.
func systemSpace(p uint64) bool { return p>>63 == 1 }

func readU16(r memory.MemoryReader, at uint64) (uint16, bool) {
	b, err := r.ReadAt(at, 2)
	if err != nil || len(b) < 2 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b), true
}

func readU32(r memory.MemoryReader, at uint64) (uint32, bool) {
	b, err := r.ReadAt(at, 4)
	if err != nil || len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

func readPointer(r memory.MemoryReader, at uint64) (uint64, bool) {
	b, err := r.ReadAt(at, pointerBytes)
	if err != nil || len(b) < pointerBytes {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

type body []byte

func (b body) u32(at uint64) uint32 { return binary.LittleEndian.Uint32(b[at:]) }
func (b body) u64(at uint64) uint64 { return binary.LittleEndian.Uint64(b[at:]) }

// Learn, MIB_TCPROW2: ports are in network byte order (S28 D3, M7).
func (b body) port(at uint64) uint16 { return binary.BigEndian.Uint16(b[at:]) }

type decoder struct {
	kernel memory.MemoryReader
	l      *objectLayout
	owner  processlist.ProcessCheck
	window processlist.TimeWindow
}

func newDecoder(ctx tools.Context, l *objectLayout) decoder {
	check := processlist.NewProcessCheck(ctx)
	return decoder{kernel: ctx.Memory, l: l, owner: check, window: check.Window()}
}

func (d decoder) read(r memory.MemoryReader, at, size uint64) (body, error) {
	if at+size < at {
		return nil, ErrObjectUnread
	}
	b, err := r.ReadAt(at, size)
	if err != nil || uint64(len(b)) < size {
		return nil, ErrObjectUnread
	}
	return b, nil
}

func (d decoder) family(inetAF uint64) (Family, error) {
	if !systemSpace(inetAF) {
		return "", ErrFamily
	}
	v, ok := readU16(d.kernel, inetAF+d.l.family)
	if !ok {
		return "", ErrFamily
	}
	f, ok := familyOf(v)
	if !ok {
		return "", ErrFamily
	}
	return f, nil
}

func (d decoder) ipAt(at uint64, f Family) (netip.Addr, error) {
	if !systemSpace(at) {
		return netip.Addr{}, ErrPointer
	}
	b, err := d.kernel.ReadAt(at, f.addressBytes())
	if err != nil || uint64(len(b)) < f.addressBytes() {
		return netip.Addr{}, ErrIPUnread
	}
	if f == FamilyIPv6 {
		return netip.AddrFrom16([16]byte(b)), nil
	}
	return netip.AddrFrom4([4]byte(b)), nil
}

// The local address object holds a pointer to a pointer to the address
// bytes (the layout's address member, M12).
func (d decoder) localIP(object uint64, f Family) (netip.Addr, error) {
	if !systemSpace(object) {
		return netip.Addr{}, ErrPointer
	}
	p, ok := readPointer(d.kernel, object+d.l.addressOfLocal)
	if !ok {
		return netip.Addr{}, ErrIPUnread
	}
	if !systemSpace(p) {
		return netip.Addr{}, ErrPointer
	}
	q, ok := readPointer(d.kernel, p)
	if !ok {
		return netip.Addr{}, ErrIPUnread
	}
	return d.ipAt(q, f)
}

func (d decoder) setOwner(e *Endpoint, b body, offsets []uint64) {
	var last error = ErrOwner
	for _, off := range offsets {
		p := b.u64(off)
		if !systemSpace(p) {
			continue
		}
		id, err := d.owner.Check(d.kernel, p)
		if err != nil {
			last = fmt.Errorf("%w: _EPROCESS at 0x%x: %w", ErrOwner, p, err)
			continue
		}
		e.OwningPID, e.OwnerImage, e.OwnerAddress = id.PID, id.Name, p
		return
	}
	e.OwnerProblem = last.Error()
}

func (d decoder) setTime(e *Endpoint, ft uint64) {
	if ft == 0 {
		e.TimeProblem = ErrTimeAbsent.Error()
		return
	}
	t, ok := util.FiletimeToTime(ft)
	if !ok || !d.window.Holds(ft) {
		e.TimeProblem = ErrTimeWindow.Error()
		return
	}
	e.CreateTime = t
}

func (d decoder) setIP(e *Endpoint, which string, err error) {
	if err != nil && e.IPProblem == "" {
		e.IPProblem = which + ": " + err.Error()
	}
}

// A returned error is the validity rule that failed (S28 5); the row it comes
// with holds what decoded before the failure.
func (d decoder) connection(r memory.MemoryReader, at uint64) (Endpoint, error) {
	e := Endpoint{Kind: KindConnection}
	c := d.l.connection
	b, err := d.read(r, at, c.size)
	if err != nil {
		return e, err
	}
	e.StateValue = b.u32(c.state)
	e.State, _ = stateOf(e.StateValue)
	e.LocalPort, e.RemotePort = b.port(c.localPort), b.port(c.remotePort)
	if e.Family, err = d.family(b.u64(c.inetAF)); err != nil {
		return e, err
	}
	if _, ok := stateOf(e.StateValue); !ok {
		return e, ErrState
	}
	if e.LocalPort == 0 || e.RemotePort == 0 {
		return e, ErrPort
	}
	info := b.u64(c.addressInfo)
	if !systemSpace(info) {
		d.setIP(&e, "address info", ErrPointer)
	} else {
		local, okLocal := readPointer(d.kernel, info+d.l.localInfo)
		remote, okRemote := readPointer(d.kernel, info+d.l.remoteIP)
		if !okLocal || !okRemote {
			d.setIP(&e, "address info", ErrIPUnread)
		} else {
			e.LocalIP, err = d.localIP(local, e.Family)
			d.setIP(&e, "local", err)
			e.RemoteIP, err = d.ipAt(remote, e.Family)
			d.setIP(&e, "remote", err)
		}
	}
	d.setOwner(&e, b, c.owners)
	d.setTime(&e, b.u64(c.createTime))
	return e, nil
}

func (d decoder) bound(r memory.MemoryReader, kind EndpointKind, at uint64) (Endpoint, error) {
	e := Endpoint{Kind: kind}
	m := d.l.bound(kind)
	b, err := d.read(r, at, m.size)
	if err != nil {
		return e, err
	}
	if kind == KindListener {
		e.State, e.StateValue = TCPStateListen, stateListen
	}
	e.LocalPort = b.port(m.localPort)
	if e.Family, err = d.family(b.u64(m.inetAF)); err != nil {
		return e, err
	}
	if e.LocalPort == 0 {
		return e, ErrPort
	}
	// Learn, MIB_TCPROW2: a local address of zero accepts on any interface (D3, M12).
	if local := b.u64(m.localAddress); local == 0 {
		e.LocalIP = e.Family.unspecified()
	} else {
		e.LocalIP, err = d.localIP(local, e.Family)
		d.setIP(&e, "local", err)
	}
	d.setOwner(&e, b, []uint64{m.owner})
	d.setTime(&e, b.u64(m.createTime))
	return e, nil
}
