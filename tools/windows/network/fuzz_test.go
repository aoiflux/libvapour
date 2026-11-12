package network

import (
	"encoding/binary"
	"errors"
	"testing"
)

func FuzzDecodeEndpoint(f *testing.F) {
	seed := newWorld(f)
	f.Add(byte(0), seed.connectionBody(seed.defaultConn()))
	f.Add(byte(1), seed.boundBody(boundSpec{kind: KindListener, family: addressFamilyInet, port: 80}))
	f.Add(byte(2), []byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, which byte, data []byte) {
		w := newWorld(t)
		pointers := []uint64{w.family(addressFamilyInet), w.family(addressFamilyInet6), w.family(9),
			w.process(8, "x.exe"), w.localAddressObject(seed.defaultConn().local), 0, 0x7fff0000}
		kind := []EndpointKind{KindConnection, KindListener, KindDatagram}[int(which)%3]
		size := w.size(typeTCPEndpoint)
		if kind != KindConnection {
			size = w.size(w.typeOf(kind))
		}
		body := make([]byte, size)
		copy(body, data)
		for i := 0; i+8 <= len(body); i += 8 {
			if v := binary.LittleEndian.Uint64(body[i:]); v>>56 == 0xa5 {
				binary.LittleEndian.PutUint64(body[i:], pointers[v%uint64(len(pointers))])
			}
		}
		at := w.alloc(size)
		w.k.write(at, body)
		d := w.decoder(w.ctx(nil))
		var e Endpoint
		var err error
		if kind == KindConnection {
			e, err = d.connection(w.k, at)
		} else {
			e, err = d.bound(w.k, kind, at)
		}
		if err != nil {
			if !errors.Is(err, ErrFamily) && !errors.Is(err, ErrState) && !errors.Is(err, ErrPort) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if e.Family != FamilyIPv4 && e.Family != FamilyIPv6 || e.LocalPort == 0 {
			t.Fatalf("accepted %+v", e)
		}
		if kind == KindConnection {
			if _, ok := stateOf(e.StateValue); !ok || e.RemotePort == 0 {
				t.Fatalf("accepted connection %+v", e)
			}
		}
		if e.LocalIP.IsValid() && e.Family == FamilyIPv4 != e.LocalIP.Is4() {
			t.Fatalf("family %s with local %v", e.Family, e.LocalIP)
		}
		if (e.OwnerProblem == "") != (e.OwningPID != 0) {
			t.Fatalf("owner %d with problem %q", e.OwningPID, e.OwnerProblem)
		}
		if (e.TimeProblem == "") == e.CreateTime.IsZero() {
			t.Fatalf("time %v with problem %q", e.CreateTime, e.TimeProblem)
		}
	})
}

// Entries and links take values among the real endpoints' next members,
// with arbitrary flags, plus garbage.
func FuzzPortPoolChain(f *testing.F) {
	f.Add([]byte{0x12, 0x21, 0x30, 0x40, 0x05})
	f.Add([]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11})
	f.Fuzz(func(t *testing.T, data []byte) {
		w := newWorld(t)
		const port = 445
		owner := w.process(4, "System")
		var objs []uint64
		for _, p := range []uint16{port, port, port, 446} {
			objs = append(objs, w.bound(boundSpec{kind: KindListener, family: addressFamilyInet, port: p, owner: owner, created: fxCreated}))
		}
		next := w.off(typeTCPListener, memberNext)
		value := func(b byte) uint64 {
			flags := uint64(b>>4) & entryFlagBits
			switch i := int(b&0xf) % 6; {
			case i < len(objs):
				return (objs[i] + next) | flags
			case i == len(objs):
				return flags
			default:
				return fxKernel + 0x7000000 | flags
			}
		}
		head := uint64(0)
		if len(data) > 0 {
			head = value(data[0])
		}
		global := w.portPool(KindListener, map[uint16]portChain{port: {objects: objs[:1]}})
		for i, o := range objs {
			if i+1 < len(data) {
				w.k.u64(o+next, value(data[i+1]))
			}
		}
		set, _ := readPointer(w.k, global)
		compartment, _ := readPointer(w.k, set+w.off(typeCompartmentSet, memberCompartment))
		protocol, _ := readPointer(w.k, compartment+w.off(typeCompartment, memberProtocol))
		pool, _ := readPointer(w.k, protocol+w.off(typeProtocolCompartment, memberPortPool))
		assignment, _ := readPointer(w.k, pool+w.off(typePortPool, memberAssignments)+(port>>portBlockShift)*8)
		list, _ := readPointer(w.k, assignment+w.off(typePortAssignment, memberList))
		w.k.u64(list+w.off(typePortAssignmentList, memberObject)+(port%portBlock)*w.size(typePortAssignmentEntry), head)

		ctx := w.ctx(nil)
		l, err := resolveLayout(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ls := &lister{ctx: ctx, d: newDecoder(ctx, l), t: l.tables, seen: map[uint64]bool{}, rejected: map[string]int{}}
		if err := ls.portPool(KindListener, global); err != nil {
			t.Fatal(err)
		}
		seen := map[uint64]bool{}
		for _, e := range ls.rows {
			if seen[e.ObjectAddress] {
				t.Fatalf("0x%x listed twice", e.ObjectAddress)
			}
			seen[e.ObjectAddress] = true
			if e.LocalPort != port || e.Kind != KindListener {
				t.Fatalf("row %+v under port %d", e, port)
			}
		}
		if len(ls.rows) > 0 && head&entryFlagBits != tcpListenerFlags {
			t.Fatalf("a chain was walked from an entry with flags %d", head&entryFlagBits)
		}
	})
}
