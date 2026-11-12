package tracingbpf

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const (
	mask     = 1<<48 - 1
	progIDR  = Data + 0x8000
	xaNode   = 0xffff888000200000
	progBase = 0xffff888000300000
	auxOff   = 0x800
)

// bpf_prog: jited bit 0 of the u16 at 2, type @4, expected_attach_type @8,
// len @12, jited_len @16, tag @20, bpf_func @48, aux @56.
// bpf_prog_aux: id @0x20, prog @0x30, load_time @0x38, name @0x40.
const (
	progType    = 4
	progAttach  = 8
	progLen     = 12
	progJitLen  = 16
	progTag     = 20
	progFunc    = 48
	progAux     = 56
	auxID       = 0x20
	auxProg     = 0x30
	auxLoadTime = 0x38
	auxName     = 0x40
	nodeSlots   = 0x28
)

type fixture struct {
	types *Types
	mem   *Memory
}

func progAt(i int) uint64 { return progBase + uint64(i)*0x1000 }

func newFixture(withEnum bool) *fixture {
	f := &fixture{types: NewTypes(8), mem: NewMemory()}
	ty := f.types
	vp := Ptr(Void())
	typeRef := Enum("bpf_prog_type")
	if withEnum {
		ty.Enum("bpf_prog_type", 4, "unsigned int", map[string]int64{"BPF_PROG_TYPE_UNSPEC": 0,
			"BPF_PROG_TYPE_KPROBE": 2, "BPF_PROG_TYPE_CGROUP_SKB": 8, "BPF_PROG_TYPE_LSM": 29})
	} else {
		typeRef = Base("unsigned int")
	}
	ty.Enum("bpf_attach_type", 4, "unsigned int", map[string]int64{"BPF_CGROUP_INET_INGRESS": 0, "BPF_LSM_MAC": 27})
	ty.Struct("bpf_prog", 72, map[string]F{
		"jited":                {Off: 2, Type: Bits(0, 1, "short unsigned int")},
		"type":                 {Off: progType, Type: typeRef},
		"expected_attach_type": {Off: progAttach, Type: Enum("bpf_attach_type")},
		"len":                  {Off: progLen, Type: Base("unsigned int")},
		"jited_len":            {Off: progJitLen, Type: Base("unsigned int")},
		"tag":                  {Off: progTag, Type: Arr(8, Base("unsigned char"))},
		"bpf_func":             {Off: progFunc, Type: vp},
		"aux":                  {Off: progAux, Type: Ptr(Struct("bpf_prog_aux"))},
	})
	ty.Struct("bpf_prog_aux", 0x100, map[string]F{
		"id":        {Off: auxID, Type: Base("unsigned int")},
		"prog":      {Off: auxProg, Type: Ptr(Struct("bpf_prog"))},
		"load_time": {Off: auxLoadTime, Type: Base("long long unsigned int")},
		"name":      {Off: auxName, Type: Arr(16, Base("char"))},
	})
	ty.Struct("xarray", 16, map[string]F{"xa_head": {Off: 8, Type: vp}})
	ty.Struct("idr", 24, map[string]F{"idr_rt": {Off: 0, Type: Struct("xarray")},
		"idr_base": {Off: 16, Type: Base("unsigned int")}})
	ty.Struct("xa_node", nodeSlots+64*8, map[string]F{
		"shift":  {Off: 0, Type: Base("unsigned char")},
		"offset": {Off: 1, Type: Base("unsigned char")},
		"parent": {Off: 8, Type: vp},
		"array":  {Off: 0x18, Type: vp},
		"slots":  {Off: nodeSlots, Type: Arr(64, vp)},
	})
	ty.Symbol("prog_idr", progIDR, Struct("idr"))
	f.mem.Map(progIDR, 24)
	f.mem.Map(xaNode, nodeSlots+64*8)
	f.mem.U64(progIDR+8, xaNode|2)
	f.mem.U64(xaNode+0x18, progIDR)
	return f
}

type prog struct {
	id              uint64
	typ, attach     uint32
	name            string
	tag             []byte
	insns, jitLen   uint32
	jited           bool
	loadNS          uint64
	backLink, auxID uint64
	noAux, unmapAux bool
	rawName         []byte
}

func (f *fixture) add(i int, p prog) uint64 {
	at := progAt(i)
	m := f.mem
	m.Map(at, 0x1000)
	m.U32(at+progType, p.typ)
	m.U32(at+progAttach, p.attach)
	m.U32(at+progLen, p.insns)
	m.U32(at+progJitLen, p.jitLen)
	if p.jited {
		m.U16(at+2, 1)
	}
	m.Write(at+progTag, p.tag)
	m.U64(at+progFunc, 0xffffffffc0001000+uint64(i)*0x100)
	m.U64(xaNode+nodeSlots+p.id*8, at)
	if p.noAux {
		return at
	}
	aux := at + auxOff
	m.U64(at+progAux, aux)
	if p.unmapAux {
		m.U64(at+progAux, 0xffff888077000000)
		return at
	}
	link, id := at, p.id
	if p.backLink != 0 {
		link = p.backLink
	}
	if p.auxID != 0 {
		id = p.auxID
	}
	m.U32(aux+auxID, uint32(id))
	m.U64(aux+auxProg, link)
	m.U64(aux+auxLoadTime, p.loadNS)
	if p.rawName != nil {
		m.Write(aux+auxName, p.rawName)
	} else {
		m.Str(aux+auxName, p.name)
	}
	return at
}

func (f *fixture) run(t *testing.T, opts map[string]any) ([]Program, *[]string, error) {
	t.Helper()
	ctx, diags := Context(f.mem, f.types.Table(t), opts)
	rows, err := Run(ctx)
	return rows, diags, err
}

func standard(f *fixture) {
	f.add(0, prog{id: 1, typ: 8, name: "sd_fw_ingress", tag: []byte{0x6d, 0xee, 0xf7, 0x35, 0x7e, 0x7b, 0x45, 0x30},
		insns: 8, jitLen: 59, jited: true, loadNS: 5_071_407_269})
	f.add(1, prog{id: 2, typ: 29, attach: 27, name: "restrict_filesy", tag: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		insns: 120, jitLen: 700, jited: true, loadNS: 6_000_000_000})
	f.add(2, prog{id: 5, typ: 2, name: "probe.v2", tag: make([]byte, 8), insns: 3})
}

func TestProgramsAreListedInIDOrderWithTheirRecords(t *testing.T) {
	f := newFixture(true)
	standard(f)
	rows, diags, err := f.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Program{
		{Address: progAt(0) & mask, ID: 1, Type: "BPF_PROG_TYPE_CGROUP_SKB", TypeValue: 8,
			AttachType: "BPF_CGROUP_INET_INGRESS", Name: "sd_fw_ingress", Tag: "6deef7357e7b4530", Instructions: 8,
			JITed: true, JITedSize: 59, FuncAddress: 0xffffffffc0001000 & mask, AuxAddress: (progAt(0) + auxOff) & mask,
			AuxRead: true, LoadedAfterBoot: 5_071_407_269 * time.Nanosecond, Linked: true, IDMatches: true},
		{Address: progAt(1) & mask, ID: 2, Type: "BPF_PROG_TYPE_LSM", TypeValue: 29, AttachType: "BPF_LSM_MAC",
			AttachTypeValue: 27, Name: "restrict_filesy", Tag: "0102030405060708", Instructions: 120, JITed: true,
			JITedSize: 700, FuncAddress: 0xffffffffc0001100 & mask, AuxAddress: (progAt(1) + auxOff) & mask,
			AuxRead: true, LoadedAfterBoot: 6 * time.Second, Linked: true, IDMatches: true},
		{Address: progAt(2) & mask, ID: 5, Type: "BPF_PROG_TYPE_KPROBE", TypeValue: 2,
			AttachType: "BPF_CGROUP_INET_INGRESS", Name: "probe.v2", Tag: "0000000000000000", Instructions: 3,
			FuncAddress: 0xffffffffc0001200 & mask, AuxAddress: (progAt(2) + auxOff) & mask, AuxRead: true,
			Linked: true, IDMatches: true},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d\n got %+v\nwant %+v", i, rows[i], want[i])
		}
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestATypeWithNoEnumeratorIsLeftUnnamed(t *testing.T) {
	f := newFixture(true)
	f.add(0, prog{id: 1, typ: 31, name: "x", tag: make([]byte, 8)})
	rows, diags, err := f.run(t, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if rows[0].Type != "" || rows[0].TypeValue != 31 {
		t.Errorf("type %q %d", rows[0].Type, rows[0].TypeValue)
	}
	if !contains(*diags, "1 programs have a type value with no bpf_prog_type name") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestWithoutTheImageEnumTheUAPIListNamesTheType(t *testing.T) {
	f := newFixture(false)
	f.add(0, prog{id: 1, typ: 32, name: "nf", tag: make([]byte, 8)})
	rows, _, err := f.run(t, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if rows[0].Type != "BPF_PROG_TYPE_NETFILTER" {
		t.Errorf("type %q", rows[0].Type)
	}
}

func TestABrokenBackLinkAndAnIDMismatchAreFindings(t *testing.T) {
	f := newFixture(true)
	f.add(0, prog{id: 1, typ: 2, name: "a", tag: make([]byte, 8), backLink: 0xffff888000999000})
	f.add(1, prog{id: 3, typ: 2, name: "b", tag: make([]byte, 8), auxID: 9})
	rows, diags, err := f.run(t, map[string]any{"strict": true})
	if err != nil {
		t.Fatalf("mismatches are findings, not losses: %v", err)
	}
	if len(rows) != 2 || rows[0].Linked || !rows[0].IDMatches || !rows[1].Linked || rows[1].IDMatches {
		t.Fatalf("rows %+v", rows)
	}
	if !contains(*diags, "points back at 0x888000999000") || !contains(*diags, "aux id 9 is not its registry id 3") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestAnUnreadableAuxKeepsTheRowAndFailsStrictMode(t *testing.T) {
	f := newFixture(true)
	f.add(0, prog{id: 1, typ: 2, tag: make([]byte, 8), unmapAux: true})
	f.add(1, prog{id: 2, typ: 2, tag: make([]byte, 8), noAux: true})
	rows, diags, err := f.run(t, nil)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	for _, r := range rows {
		if r.AuxRead || r.Name != "" || r.Type != "BPF_PROG_TYPE_KPROBE" {
			t.Errorf("row %+v", r)
		}
	}
	if !contains(*diags, "aux at 0x888077000000 does not read") {
		t.Errorf("diagnostics %q", *diags)
	}
	if !contains(*diags, "aux pointer is null") {
		t.Errorf("diagnostics %q", *diags)
	}
	if _, _, err := f.run(t, map[string]any{"strict": true}); err == nil {
		t.Error("strict mode accepts an unread aux")
	}
}

func TestAProgramThatDoesNotReadIsLeftOut(t *testing.T) {
	f := newFixture(true)
	standard(f)
	f.mem.U64(xaNode+nodeSlots+3*8, 0xffff888066000000)
	rows, diags, err := f.run(t, nil)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !contains(*diags, "bpf_prog at 0x888066000000: does not read") {
		t.Errorf("diagnostics %q", *diags)
	}
	if _, _, err := f.run(t, map[string]any{"strict": true}); err == nil {
		t.Error("strict mode accepts a program left out")
	}
}

func TestANameWithNoNULIsLeftEmpty(t *testing.T) {
	f := newFixture(true)
	f.add(0, prog{id: 1, typ: 2, tag: make([]byte, 8), rawName: []byte("0123456789abcdef")})
	f.mem.U8(progAt(0)+auxOff+auxName+16, 'X')
	rows, diags, err := f.run(t, nil)
	if err != nil || len(rows) != 1 || rows[0].Name != "" || !rows[0].AuxRead {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !contains(*diags, "1 programs have a name with no NUL in its 16 bytes") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestTheRegistryMustBeInTheSymbolTable(t *testing.T) {
	f := newFixture(true)
	ty := NewTypes(8)
	ctx, _ := Context(f.mem, ty.Table(t), nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoProgIDR) {
		t.Errorf("no prog_idr: %v", err)
	}
	ctx, _ = Context(f.mem, f.types.Table(t), nil)
	ctx.Profile = profiles.WindowsX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Error("a Windows profile is accepted")
	}
}

func TestTheToolIsRegistered(t *testing.T) {
	if _, err := tools.Get(Name); err != nil {
		t.Errorf("%s is not registered: %v", Name, err)
	}
}

func contains(diags []string, part string) bool {
	for _, d := range diags {
		if strings.Contains(d, part) {
			return true
		}
	}
	return false
}
