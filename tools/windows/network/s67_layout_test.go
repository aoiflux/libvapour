package network

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
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
		if _, err := LayoutForBuild(b); !errors.Is(err, ErrUnmeasuredBuild) {
			t.Errorf("build %d: %v", b, err)
		}
	}
	_, err := LayoutForBuild(22631)
	if want := "build 22631 (measured: 14393 scan only, 19041-19045, 26100)"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("refusal %v, want it to name %q", err, want)
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

var (
	pdbMem1  = autoload.Fingerprint{PDBName: "tcpip.pdb", GUID: "DAC097D9D8F30AC6467DB71184A8C2E5", Age: 1}
	pdbMem67 = autoload.Fingerprint{PDBName: "tcpip.pdb", GUID: "11B241ADFEA742938BFD75329CFFE121", Age: 1}
)

func pdbIs(fp autoload.Fingerprint, err error) func(tools.Context) (autoload.Fingerprint, error) {
	return func(tools.Context) (autoload.Fingerprint, error) { return fp, err }
}

func TestThe26100CreationTimeFollowsTheTcpipPDB(t *testing.T) {
	unknown := autoload.Fingerprint{PDBName: "tcpip.pdb", GUID: "00000000000000000000000000000000", Age: 2}
	for _, c := range []struct {
		name string
		pdb  func(tools.Context) (autoload.Fingerprint, error)
		want uint64
		diag string
	}{
		{"mem6 and mem7", pdbIs(pdbMem67, nil), 0x358, ""},
		{"mem1", pdbIs(pdbMem1, nil), 0x360, ""},
		{"unmeasured", pdbIs(unknown, nil), 0x360,
			"windows.network.scan: tcpip.sys: tcpip.pdb 00000000000000000000000000000000 age 2 has no measured creation-time offset, so connection creation times are read at 0x360"},
		{"unread", pdbIs(autoload.Fingerprint{}, errors.New("debug data directory: unmapped")), 0x360,
			"windows.network.scan: tcpip.sys: debug data directory: unmapped, so connection creation times are read at 0x360"},
	} {
		var diags []string
		ctx := tools.Context{Options: map[string]any{"diagnostics": &diags}}
		l := &objectLayout{name: "tcpip-26100"}
		l.connection.createTime = 0x360
		pickCreationTime(ctx, Name, l, c.pdb)
		if l.connection.createTime != c.want {
			t.Errorf("%s: creation time at 0x%x, want 0x%x", c.name, l.connection.createTime, c.want)
		}
		if got := strings.Join(diags, "\n"); got != c.diag {
			t.Errorf("%s: diagnostics %q, want %q", c.name, got, c.diag)
		}
	}
}

func TestABuildWithOneCreationTimeReadsNoModule(t *testing.T) {
	var diags []string
	ctx := tools.Context{Options: map[string]any{"diagnostics": &diags}}
	l := &objectLayout{name: "tcpip-19041-19045"}
	l.connection.createTime = 0x2e8
	pickCreationTime(ctx, Name, l, func(tools.Context) (autoload.Fingerprint, error) {
		t.Error("tcpip.sys read for a build with one creation-time offset")
		return autoload.Fingerprint{}, nil
	})
	if l.connection.createTime != 0x2e8 || len(diags) != 0 {
		t.Errorf("creation time 0x%x, diagnostics %q", l.connection.createTime, diags)
	}
}

func TestWithoutTcpipInTheModuleListTheTablesOffsetStays(t *testing.T) {
	w := newWorld(t)
	ctx := w.ctx(nil)
	l, err := resolveLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pickCreationTime(ctx, NetworkListName, l, tcpipPDB)
	if l.connection.createTime != 0x360 {
		t.Errorf("creation time at 0x%x", l.connection.createTime)
	}
	joined := strings.Join(w.diags, "\n")
	if !strings.Contains(joined, "windows.network.list: tcpip.sys: ") ||
		!strings.Contains(joined, "so connection creation times are read at 0x360") {
		t.Errorf("diagnostics %q", w.diags)
	}
}

func layoutName(b winkernel.Build) string {
	table, err := LayoutFor(b)
	if err != nil {
		return "error: " + err.Error()
	}
	return table.Name()
}

func TestTheKernelBuildComesBeforeTheSharedCopy(t *testing.T) {
	unread := errors.New("unread")
	for _, c := range []struct {
		name string
		b    winkernel.Build
		want string
	}{
		{"kernel", winkernel.Build{Kernel: 26100, Major: 10, Shared: 19044}, "tcpip-26100"},
		{"kernel range", winkernel.Build{Kernel: 19044, VersionErr: unread, SharedErr: unread}, "tcpip-19041-19045"},
		{"shared", winkernel.Build{KernelErr: unread, Major: 10, Shared: 19044}, "tcpip-19041-19045"},
		{"unmeasured kernel", winkernel.Build{Kernel: 22631, Major: 10, Shared: 26100}, "tcpip-26100"},
		{"not nt 10.0", winkernel.Build{KernelErr: unread, Major: 6, Minor: 3, Shared: 26100}, "nt version 6.3 is not 10.0"},
		{"nothing", winkernel.Build{KernelErr: unread, VersionErr: unread}, "kernel build: unread; shared build: unread"},
		{"unmeasured both", winkernel.Build{Kernel: 22631, Major: 10, Shared: 22631},
			"kernel build 22631; shared build 22631 (measured: 14393 scan only, 19041-19045, 26100)"},
	} {
		if got := layoutName(c.b); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if _, err := LayoutFor(winkernel.Build{KernelErr: unread, VersionErr: unread}); !errors.Is(err, ErrUnmeasuredBuild) {
		t.Errorf("an unread build: %v", err)
	}
}
