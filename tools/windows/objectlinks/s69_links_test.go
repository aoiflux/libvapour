package objectlinks

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
)

const created = uint64(133500000000000000)

func run(t *testing.T, k *testsupport.S69Kernel) map[uint64]Symlink {
	t.Helper()
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64]Symlink{}
	for _, r := range rows {
		out[r.VirtualOffset] = r
	}
	return out
}

func TestALinkIsListedWithItsTargetAndCreationTime(t *testing.T) {
	k := testsupport.NewS69Kernel()
	c := k.AddLink("C:", `\Device\HarddiskVolume3`, created)
	rows := run(t, k)
	got, ok := rows[c]
	if !ok || len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	want := time.Date(2024, time.January, 17, 21, 20, 0, 0, time.UTC)
	if got.Name != "C:" || got.Target != `\Device\HarddiskVolume3` || got.NameUnreadable || got.TargetUnreadable ||
		got.Callback || !got.CreateTime.Equal(want) || got.CreateTimeUnreadable {
		t.Errorf("link = %+v, want C: to the volume created %v", got, want)
	}
	if got.Offset != k.Physical(c) {
		t.Errorf("Offset 0x%x, want 0x%x", got.Offset, k.Physical(c))
	}
}

func TestACallbackLinkCarriesItsRoutineAndModule(t *testing.T) {
	k := testsupport.NewS69Kernel()
	k.AddModule("ntoskrnl.exe", 0xfffff80100000000, 0x100000)
	in := k.AddCallbackLink("MemoryErrors", 0xfffff80100001230, 0xffffa00000005000, created)
	out := k.AddCallbackLink("Other", 0xfffff80200000000, 0, created)
	rows := run(t, k)
	a := rows[in]
	if !a.Callback || a.CallbackRoutine != 0xfffff80100001230 || a.CallbackContext != 0xffffa00000005000 ||
		a.CallbackModule == "" || a.CallbackUnowned || a.Target != "" || a.TargetUnreadable {
		t.Errorf("callback in a module = %+v", a)
	}
	if b := rows[out]; !b.Callback || !b.CallbackUnowned || b.CallbackModule != "" {
		t.Errorf("callback outside every module = %+v", b)
	}
}

func TestACallbackFlagWithARoutineOutsideKernelSpaceIsRefused(t *testing.T) {
	k := testsupport.NewS69Kernel()
	k.AddCallbackLink("X", 0x7ff600000000, 0, created)
	if rows := run(t, k); len(rows) != 0 {
		t.Errorf("rows = %+v, want none", rows)
	}
}

func TestTargetRules(t *testing.T) {
	k := testsupport.NewS69Kernel()
	odd := k.AddLink("Odd", `\Device\X`, created)
	k.U16(odd+testsupport.S69LinkTarget, 3)
	gone := k.AddLink("Gone", `\Device\Y`, created)
	k.U64(gone+testsupport.S69LinkTarget+8, k.Skip())
	nameless := k.AddLink("", `\Device\Z`, created)
	k.U64(nameless+testsupport.S69LinkTarget+8, k.Skip())
	empty := k.AddLink("Empty", "", created)
	k.U32(empty+testsupport.S69LinkTarget, 0)
	control := k.AddLink("Ctl", "\\Device\x01", created)
	rows := run(t, k)
	if _, ok := rows[odd]; ok {
		t.Error("a LinkTarget with an odd Length is listed")
	}
	if _, ok := rows[nameless]; ok {
		t.Error("a link with neither a name nor a target is listed")
	}
	if g := rows[gone]; g.Name != "Gone" || !g.TargetUnreadable || g.Target != "" {
		t.Errorf("unreadable target = %+v", g)
	}
	if e, ok := rows[empty]; !ok || e.Target != "" || e.TargetUnreadable {
		t.Errorf("empty target = %+v, listed %v", e, ok)
	}
	if c := rows[control]; !c.TargetUnreadable || c.Target != "" {
		t.Errorf("control character target = %+v", c)
	}
}

func TestNameAndTimeRules(t *testing.T) {
	k := testsupport.NewS69Kernel()
	bad := k.AddLink(`a\b`, `\Device\X`, 0)
	rows := run(t, k)
	b := rows[bad]
	if !b.NameUnreadable || b.Name != "" || b.Target != `\Device\X` || !b.CreateTimeUnreadable {
		t.Errorf("link = %+v, want the name and time flagged", b)
	}
}

func TestATableWithoutTheCallbackMembersReadsEveryTarget(t *testing.T) {
	k := testsupport.NewS69Kernel()
	st, _ := k.Table.Struct("_OBJECT_SYMBOLIC_LINK")
	var kept = st.Fields[:0]
	for _, f := range st.Fields {
		if f.Name != "Callback" && f.Name != "CallbackContext" {
			kept = append(kept, f)
		}
	}
	st.Fields = kept
	k.Table.AddStruct(st)
	l := k.AddLink("D:", `\Device\CdRom0`, created)
	k.U32(l+testsupport.S69LinkFlags, 0x10)
	if r := run(t, k)[l]; r.Callback || r.Target != `\Device\CdRom0` {
		t.Errorf("link = %+v", r)
	}
}

func TestFailures(t *testing.T) {
	ctx := testsupport.NewS69Kernel().Context()
	delete(ctx.Options, "physical_memory")
	if _, err := Run(ctx); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Errorf("no physical memory: %v", err)
	}
	k := testsupport.NewS69Kernel()
	st, _ := k.Table.Struct("_OBJECT_SYMBOLIC_LINK")
	st.Fields = st.Fields[:1]
	k.Table.AddStruct(st)
	if _, err := Run(k.Context()); !errors.Is(err, ErrNoLinkType) {
		t.Errorf("missing LinkTarget: %v", err)
	}
}

func TestPlausible(t *testing.T) {
	for _, c := range []struct {
		name, target string
		want         bool
	}{
		{"C:", `\Device\HarddiskVolume3`, true}, {"", `\Device\X`, false}, {`a\b`, `\X`, false},
		{"PIPE", "\\Device\x02", false}, {"x", "", true}, {"x", "\ufffd", false},
	} {
		if got := Plausible(c.name, c.target); got != c.want {
			t.Errorf("Plausible(%q, %q) = %v, want %v", c.name, c.target, got, c.want)
		}
	}
}

type bytesReader []byte

func (b bytesReader) Size() uint64 { return uint64(len(b)) }

func (b bytesReader) ReadAt(off, n uint64) ([]byte, error) {
	if off > uint64(len(b)) || n > uint64(len(b))-off {
		return nil, memory.ErrOutOfBounds
	}
	return b[off : off+n], nil
}

func FuzzSymbolicLinkBody(f *testing.F) {
	k := testsupport.NewS69Kernel()
	l, err := resolve(k.Table)
	if err != nil {
		f.Fatal(err)
	}
	l.namer, _ = scan.NewObjectNamer(k.Table)
	seed := make([]byte, 0x80)
	binary.LittleEndian.PutUint16(seed[0x30+8:], 4)
	binary.LittleEndian.PutUint16(seed[0x30+10:], 6)
	binary.LittleEndian.PutUint64(seed[0x30+16:], 0x70)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		r := bytesReader(raw)
		got, ok := l.decode(r, r, 0x8000000000000000, 0x30)
		if !ok {
			return
		}
		if got.Callback && got.CallbackRoutine < 0x8000000000000000 {
			t.Errorf("callback routine 0x%x outside kernel space", got.CallbackRoutine)
		}
		if got.Target != "" && !plausibleTarget(got.Target) || got.Name != "" && !plausibleName(got.Name) {
			t.Errorf("accepted %q -> %q", got.Name, got.Target)
		}
		if got.TargetUnreadable && got.Name == "" {
			t.Error("a row with neither name nor target")
		}
	})
}
