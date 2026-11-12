package threadaddress

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/pesymbols"
)

const (
	owner    = uint64(0xffffd00000100000)
	dllStart = uint64(0x7ff800000000)
	dllEnd   = uint64(0x7ff80000ffff)
)

var imageRange = memoryranges.Mapping{Start: dllStart, End: dllEnd, Type: memoryranges.KindImage,
	Protection: "PAGE_EXECUTE_WRITECOPY", Path: `\Windows\System32\ntdll.dll`}

func newSpaces(t *testing.T, mem testsupport.S51Memory, ranges []memoryranges.Mapping, walkErr error) (*Spaces, tools.Context, *int) {
	t.Helper()
	ctx, _ := testsupport.S51Context(mem, testsupport.S51Table(), false)
	walks := 0
	procs := []processlist.Process{{PID: 1300, Name: "svchost.exe", EPROCESS: owner, DirectoryTableBase: 0x1ad000}}
	s := NewWith(ctx, procs, func(tools.Context, processlist.Process) ([]memoryranges.Mapping, error) {
		walks++
		return ranges, walkErr
	}, func(_ tools.Context, m pesymbols.Module) ([]pe.Export, error) {
		if m.Base != dllStart || m.Name != "ntdll.dll" || m.Size != dllEnd-dllStart+1 {
			t.Errorf("exports asked of %+v", m)
		}
		return []pe.Export{
			{Name: "RtlUserThreadStart", RVA: 0x100},
			{Name: "AliasB", RVA: 0x200}, {Name: "AliasA", RVA: 0x200},
			{Name: "Forwarded", RVA: 0x300, Forwarder: "other.Fn"},
		}, nil
	})
	return s, ctx, &walks
}

func TestAnAddressIsHeldByTheRangeWhoseEndsEnclose(t *testing.T) {
	ranges := []memoryranges.Mapping{{Start: 0x1000, End: 0x1fff}, imageRange}
	for _, a := range []uint64{dllStart, dllEnd, dllStart + 0x80} {
		if r, ok := Holding(ranges, a); !ok || r.Start != dllStart || r.Path != imageRange.Path {
			t.Errorf("Holding(0x%x) = %+v, %v", a, r, ok)
		}
	}
	if _, ok := Holding(ranges, dllEnd+1); ok {
		t.Error("an address past every range is held")
	}
}

func TestUserSpaceEndsAtTheTopOfTheLowerHalf(t *testing.T) {
	for _, c := range []struct {
		size uint8
		a    uint64
		want bool
	}{
		{8, 0x7fffffffffff, true}, {8, 0xffff800000000000, false}, {8, 0x7fffffffffffffff, true},
		{4, 0x7fffffff, true}, {4, 0x80000000, false},
	} {
		if got := UserAddress(c.size, c.a); got != c.want {
			t.Errorf("UserAddress(%d, 0x%x) = %v, want %v", c.size, c.a, got, c.want)
		}
	}
}

func TestAnExportNamesOnlyTheAddressItStartsAt(t *testing.T) {
	s, ctx, _ := newSpaces(t, testsupport.S51Memory{}, []memoryranges.Mapping{imageRange}, nil)
	for a, want := range map[uint64]string{
		dllStart + 0x100: "RtlUserThreadStart",
		dllStart + 0x101: "",
		dllStart + 0x200: "AliasA",
		dllStart + 0x300: "",
	} {
		p, err := s.Place(ctx, owner, a)
		if err != nil || !p.Mapped || p.Export != want {
			t.Errorf("Place(0x%x) = %+v, %v; want export %q", a, p, err, want)
		}
	}
}

func TestAPrivateRangeIsNotAskedForExports(t *testing.T) {
	private := memoryranges.Mapping{Start: 0x20000, End: 0x2ffff, Type: memoryranges.KindPrivate}
	s, ctx, _ := newSpaces(t, testsupport.S51Memory{}, []memoryranges.Mapping{private}, nil)
	if p, _ := s.Place(ctx, owner, 0x20000); p.Export != "" || p.Range.Type != memoryranges.KindPrivate {
		t.Errorf("Place in a private range = %+v", p)
	}
}

func TestAnOwnerIsWalkedOnceAndAnUnlistedOneNever(t *testing.T) {
	s, ctx, walks := newSpaces(t, testsupport.S51Memory{}, nil, errors.New("tree unread"))
	for range 2 {
		if _, err := s.Ranges(ctx, owner); err == nil {
			t.Error("a failed walk gives no error")
		}
	}
	if *walks != 1 {
		t.Errorf("%d walks, want 1", *walks)
	}
	if _, err := s.Ranges(ctx, owner+0x1000); !errors.Is(err, ErrOwnerNotListed) {
		t.Errorf("unlisted owner: %v", err)
	}
}

func TestAWalkIsShortBelowItsCountOrForASecureProcess(t *testing.T) {
	mem := testsupport.S51Memory{}
	mem.Put64(owner+testsupport.S51VadCount, 3)
	mem.Put64(owner+testsupport.S51SecureState, 0)
	s, ctx, _ := newSpaces(t, mem, nil, nil)
	if !s.Short(ctx, owner, 2) || s.Short(ctx, owner, 3) {
		t.Error("VadCount 3: short at 2 kept and only there")
	}
	mem.Put64(owner+testsupport.S51SecureState, 1)
	if !s.Short(ctx, owner, 3) {
		t.Error("a secure process's walk is not short")
	}
	if s.Short(ctx, owner+0x10000, 0) {
		t.Error("an unreadable count makes the walk short")
	}
}
