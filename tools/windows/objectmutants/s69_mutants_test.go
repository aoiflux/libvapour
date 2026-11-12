package objectmutants

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
)

func run(t *testing.T, k *testsupport.S69Kernel) []Mutant {
	t.Helper()
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func byAddress(rows []Mutant) map[uint64]Mutant {
	out := map[uint64]Mutant{}
	for _, r := range rows {
		out[r.VirtualOffset] = r
	}
	return out
}

func TestNamedMutantsAreListedWithTheirOwner(t *testing.T) {
	k := testsupport.NewS69Kernel()
	thread := k.AddThread(0x1c4, 0x2a0)
	free := k.AddMutant("SessionLock", 0)
	held := k.AddMutant("Global_Updater", thread)
	k.Write(held+testsupport.S69MutantAbandoned, []byte{1})
	k.AddMutant("", 0)
	rows := run(t, k)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want the two named mutants", rows)
	}
	got := byAddress(rows)
	if f := got[free]; f.Name != "SessionLock" || f.OwnerThread != 0 || f.OwnerPID != 0 || f.NameUnreadable || f.Abandoned {
		t.Errorf("unowned = %+v", f)
	}
	h := got[held]
	if h.Name != "Global_Updater" || h.OwnerThread != thread || h.OwnerPID != 0x1c4 || h.OwnerTID != 0x2a0 ||
		h.OwnerUnreadable || !h.Abandoned {
		t.Errorf("owned = %+v", h)
	}
	if h.Offset != k.Physical(held) {
		t.Errorf("Offset = 0x%x, want the physical body 0x%x", h.Offset, k.Physical(held))
	}
}

func TestABodyWhoseOwnerAndStateDisagreeIsRefused(t *testing.T) {
	k := testsupport.NewS69Kernel()
	thread := k.AddThread(8, 12)
	signalledButOwned := k.AddMutant("a", thread)
	k.U32(signalledButOwned+testsupport.S64HeaderSignal, 1)
	heldButFree := k.AddMutant("b", 0)
	k.U32(heldButFree+testsupport.S64HeaderSignal, 0)
	k.AddMutant("c", 0x7ff600001000)
	otherType := k.AddMutant("d", 0)
	k.Write(otherType, []byte{1})
	if rows := run(t, k); len(rows) != 0 {
		t.Errorf("rows = %+v, want none", rows)
	}
}

func TestARecursivelyHeldMutantIsAccepted(t *testing.T) {
	k := testsupport.NewS69Kernel()
	m := k.AddMutant("deep", k.AddThread(4, 8))
	k.U32(m+testsupport.S64HeaderSignal, ^uint32(1))
	if rows := run(t, k); len(rows) != 1 || rows[0].Name != "deep" {
		t.Errorf("rows = %+v, want the mutant held twice", rows)
	}
}

func TestANameOutsideTheObjectNameRuleIsFlagged(t *testing.T) {
	k := testsupport.NewS69Kernel()
	k.AddMutant(`Global\x`, 0)
	k.AddMutant("a\x01b", 0)
	rows := run(t, k)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	for _, r := range rows {
		if !r.NameUnreadable || r.Name != "" {
			t.Errorf("row = %+v, want the name flagged", r)
		}
	}
}

// The namer shows an inner NUL, so a rule-breaking suffix after it is judged
// too (S31 O6).
func TestANameIsJudgedPastAnInnerNUL(t *testing.T) {
	k := testsupport.NewS69Kernel()
	kept := k.AddMutant("a\x00b\x00", 0)
	hidden := k.AddMutant("a\x00\\Device\\x", 0)
	got := byAddress(run(t, k))
	if r := got[kept]; r.Name != "a␀b" || r.NameUnreadable {
		t.Errorf("row = %+v, want the NUL shown and the terminator dropped", r)
	}
	if r := got[hidden]; !r.NameUnreadable || r.Name != "" {
		t.Errorf("row = %+v, want the name flagged", r)
	}
}

func TestAnOwnerThatDoesNotReadIsFlagged(t *testing.T) {
	k := testsupport.NewS69Kernel()
	gone := k.Skip()
	k.AddMutant("orphan", gone)
	rows := run(t, k)
	if len(rows) != 1 || !rows[0].OwnerUnreadable || rows[0].OwnerThread != gone || rows[0].OwnerPID != 0 {
		t.Errorf("rows = %+v, want the owner flagged", rows)
	}
}

func TestFailures(t *testing.T) {
	ctx := testsupport.NewS69Kernel().Context()
	delete(ctx.Options, "physical_memory")
	if _, err := Run(ctx); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Errorf("no physical memory: %v", err)
	}
	k := testsupport.NewS69Kernel()
	st, _ := k.Table.Struct("_KMUTANT")
	st.Fields = st.Fields[:2]
	k.Table.AddStruct(st)
	if _, err := Run(k.Context()); !errors.Is(err, ErrNoMutantType) || !strings.Contains(err.Error(), "OwnerThread") {
		t.Errorf("missing member: %v", err)
	}
}

func TestPlausibleName(t *testing.T) {
	for name, want := range map[string]bool{
		"SM0:1234:WilStaging_02": true, "": false, `a\b`: false, "a\x00b": false, "a\x1fb": false,
		"�": false, "Ünïcode name": true,
	} {
		if got := PlausibleName(name); got != want {
			t.Errorf("PlausibleName(%q) = %v, want %v", name, got, want)
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

func FuzzMutantBody(f *testing.F) {
	k := testsupport.NewS69Kernel()
	l, err := resolve(k.Table)
	if err != nil {
		f.Fatal(err)
	}
	l.namer, _ = scan.NewObjectNamer(k.Table)
	seed := make([]byte, 0x100)
	binary.LittleEndian.PutUint32(seed[0x30+4:], 1)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		r := bytesReader(raw)
		got, ok := l.decode(r, r, 0x8000000000000000, 0x30)
		if !ok {
			return
		}
		body := raw[0x30:]
		signal := int32(binary.LittleEndian.Uint32(body[4:]))
		owner := binary.LittleEndian.Uint64(body[testsupport.S69MutantOwner:])
		if got.OwnerThread != owner || (owner == 0) != (signal == 1) || owner != 0 && signal > 0 {
			t.Errorf("accepted owner 0x%x with SignalState %d", owner, signal)
		}
		if got.Name != "" && !PlausibleName(got.Name) {
			t.Errorf("accepted name %q", got.Name)
		}
	})
}
