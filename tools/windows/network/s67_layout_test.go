package network

import (
	"testing"
)

// Offsets from S67 section 3, one column per measured build.
var s67Offsets = []struct {
	typ, member         string
	b14393, b19041, b26 int64
}{
	{typeTCPEndpoint, memberInetAF, 0x10, 0x10, 0x18},
	{typeTCPEndpoint, memberAddressInfo, 0x18, 0x18, 0x20},
	{typeTCPEndpoint, memberListEntry, -1, 0x28, 0x30},
	{typeTCPEndpoint, memberState, 0x6c, 0x6c, 0x70},
	{typeTCPEndpoint, memberLocalPort, 0x70, 0x70, 0x74},
	{typeTCPEndpoint, memberRemotePort, 0x72, 0x72, 0x76},
	{typeTCPEndpoint, memberOwner, 0x258, 0x2d8, 0x348},
	{typeTCPEndpoint, memberCreateTime, 0x268, 0x2e8, 0x360},
	{typeTCPListener, memberOwner, 0x30, 0x30, 0x38},
	{typeTCPListener, memberCreateTime, 0x40, 0x40, 0x48},
	{typeTCPListener, memberLocalAddress, 0x60, 0x60, 0x68},
	{typeTCPListener, memberInetAF, 0x68, 0x68, 0x70},
	{typeTCPListener, memberLocalPort, 0x72, 0x72, 0x7a},
	{typeTCPListener, memberNext, -1, 0x78, 0x80},
	{typeUDPEndpoint, memberInetAF, 0x20, 0x20, 0x28},
	{typeUDPEndpoint, memberOwner, 0x28, 0x28, 0x30},
	{typeUDPEndpoint, memberCreateTime, 0x58, 0x58, 0x60},
	{typeUDPEndpoint, memberLocalAddress, 0x60, 0x60, 0x68},
	{typeUDPEndpoint, memberNext, -1, 0x70, 0x78},
	{typeUDPEndpoint, memberLocalPort, 0x78, 0xa0, 0xa8},
	{typeInetAF, memberFamily, 0x18, 0x18, 0x18},
	{typeAddressInfo, memberLocal, 0, 0, 0},
	{typeAddressInfo, memberRemote, 0x10, 0x10, 0x10},
	{typeLocalAddress, memberAddress, 0x10, 0x10, 0x10},
	{typePartition, memberEndpoints, -1, 0x8, 0x8},
	{typeCompartmentSet, memberCompartment, -1, 0x148, 0x148},
	{typeCompartment, memberProtocol, -1, 0x20, 0x20},
	{typeProtocolCompartment, memberPortPool, -1, 0, 0},
	{typePortPool, memberBitmap, -1, 0xd0, 0xd0},
	{typePortPool, memberAssignments, -1, 0xe0, 0xe0},
	{typePortAssignment, memberList, -1, 0x18, 0x18},
	{typePortAssignmentList, memberObject, -1, 0x10, 0x10},
}

func TestEachMeasuredBuildCarriesItsMeasuredOffsets(t *testing.T) {
	for _, b := range []struct {
		build uint32
		col   func(i int) int64
	}{
		{14393, func(i int) int64 { return s67Offsets[i].b14393 }},
		{19041, func(i int) int64 { return s67Offsets[i].b19041 }},
		{19045, func(i int) int64 { return s67Offsets[i].b19041 }},
		{26100, func(i int) int64 { return s67Offsets[i].b26 }},
	} {
		tab, err := LayoutForBuild(b.build)
		if err != nil {
			t.Fatalf("build %d: %v", b.build, err)
		}
		for i, o := range s67Offsets {
			f, err := tab.Field(o.typ, o.member)
			want := b.col(i)
			if want < 0 {
				if err == nil {
					t.Errorf("build %d: %s.%s present at 0x%x, not measured for this build", b.build, o.typ, o.member, f.Offset)
				}
				continue
			}
			if err != nil || f.Offset != uint64(want) {
				t.Errorf("build %d: %s.%s at 0x%x (%v), want 0x%x", b.build, o.typ, o.member, f.Offset, err, want)
				continue
			}
			st, err := tab.Struct(o.typ)
			if err != nil || st.Size < f.Offset+1 {
				t.Errorf("build %d: %s size %d does not cover %s", b.build, o.typ, st.Size, o.member)
			}
		}
	}
}

func TestStridesAreTheMeasuredArraySteps(t *testing.T) {
	for _, c := range []struct {
		build              uint32
		partition, entries uint64
	}{{19045, 0xc0, 0x20}, {26100, 0xc0, 0x20}} {
		tab, _ := LayoutForBuild(c.build)
		if st, _ := tab.Struct(typePartition); st.Size != c.partition {
			t.Errorf("build %d: partition stride 0x%x", c.build, st.Size)
		}
		if st, _ := tab.Struct(typePortAssignmentEntry); st.Size != c.entries {
			t.Errorf("build %d: entry stride 0x%x", c.build, st.Size)
		}
	}
}

func TestTheSecond26100OwnerIsKeptAndCoveredByTheSize(t *testing.T) {
	rec := layoutNamed("tcpip-26100")
	if rec == nil || len(rec.connection.owners) != 2 || rec.connection.owners[0].off != 0x348 || rec.connection.owners[1].off != 0x350 {
		t.Fatalf("26100 owners %+v", rec)
	}
	tab, _ := LayoutForBuild(26100)
	st, _ := tab.Struct(typeTCPEndpoint)
	if st.Size < 0x358 {
		t.Errorf("tcpEndpoint size 0x%x does not cover the second owner", st.Size)
	}
	if got := ownerOffsets("tcpip-26100", 0x348); len(got) != 2 || got[1] != 0x350 {
		t.Errorf("owner offsets %x", got)
	}
}

func TestUnmeasuredBuildsAreRefused(t *testing.T) {
	for _, b := range []uint32{0, 10240, 14392, 14394, 17763, 19040, 19046, 22000, 22631, 26099, 26101} {
		if _, err := LayoutForBuild(b); err == nil {
			t.Errorf("build %d has a layout", b)
		}
	}
	if first, last, ok := LayoutBuilds("tcpip-19041-19045"); !ok || first != 19041 || last != 19045 {
		t.Errorf("19041 range %d %d %v", first, last, ok)
	}
	if _, _, ok := LayoutBuilds("tcpip-22631"); ok {
		t.Error("unmeasured layout named")
	}
}

func TestEveryBuildHasTheMembersEveryDecodeNeeds(t *testing.T) {
	for _, l := range tcpipBuildLayouts {
		c := l.connection
		for _, m := range []measuredOffset{c.inetAF, c.addressInfo, c.state, c.localPort, c.remotePort, c.createTime, l.family, l.local, l.remote, l.addressOfLocal} {
			if !m.present() {
				t.Errorf("%s: a member every build needs is missing", l.name)
			}
		}
		if len(c.owners) == 0 || !c.owners[0].present() {
			t.Errorf("%s: no owner", l.name)
		}
	}
}
