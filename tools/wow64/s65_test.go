package wow64

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

type sparse map[uint64]byte

func (m sparse) put32(at uint64, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	for i, c := range b {
		m[at+uint64(i)] = c
	}
}

func (m sparse) put64(at uint64, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	for i, c := range b {
		m[at+uint64(i)] = c
	}
}

func (m sparse) ReadAt(at, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := range out {
		c, ok := m[at+uint64(i)]
		if !ok {
			return nil, memory.ErrUnmapped
		}
		out[i] = c
	}
	return out, nil
}

func (m sparse) Size() uint64 { return 1<<64 - 1 }

const (
	eprocess  = uint64(0xffff9e0400010000)
	wowMember = uint64(0x310)
	ewow      = uint64(0xffff9e0400900000)
	peb32     = uint64(0x60000000)
	ldr32     = uint64(0x61000000)
)

func table(withTypes bool) *symbols.Table {
	t := symbols.NewTable("s65", 8)
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x800, Fields: []symbols.Field{{Name: "WoW64Process", Offset: wowMember}}})
	t.AddStruct(symbols.StructType{Name: "_EWOW64PROCESS", Size: 0x10, Fields: []symbols.Field{{Name: "Peb", Offset: 0}}})
	if withTypes {
		t.AddStruct(symbols.StructType{Name: "_PEB32", Size: 0x480, Fields: []symbols.Field{
			{Name: "Ldr", Offset: 0x0c, Type: symbols.TypeRef{Name: "unsigned int"}}}})
		t.AddStruct(symbols.StructType{Name: "LIST_ENTRY32", Size: 8, Fields: []symbols.Field{
			{Name: "Flink", Offset: 0, Type: symbols.TypeRef{Name: "unsigned int"}},
			{Name: "Blink", Offset: 4, Type: symbols.TypeRef{Name: "unsigned int"}}}})
	}
	return t
}

func context(kernel sparse, t *symbols.Table) tools.Context {
	return tools.Context{Memory: kernel, Symbols: t, Profile: profiles.WindowsX64Profile{}, Options: map[string]any{}}
}

func TestThePEB32IsReachedThroughTheWow64Structure(t *testing.T) {
	kernel := sparse{}
	kernel.put64(eprocess+wowMember, ewow)
	kernel.put64(ewow, peb32)
	ctx := context(kernel, table(true))
	o := ResolveOffsets(ctx)
	if got, ok, why := o.PEB32(ctx, eprocess); got != peb32 || !ok || why != "" {
		t.Errorf("PEB32 0x%x %v %q", got, ok, why)
	}
	for _, tc := range []struct {
		setup func()
		want  string
	}{
		{func() { kernel.put64(eprocess+wowMember, 0) }, ""},
		{func() { delete(kernel, eprocess+wowMember) }, "_EPROCESS.WoW64Process at 0xffff9e0400010310 does not read"},
		{func() { kernel.put64(ewow, 0) }, "_EWOW64PROCESS.Peb at 0xffff9e0400900000 reads 0"},
		{func() { delete(kernel, ewow) }, "_EWOW64PROCESS.Peb at 0xffff9e0400900000 does not read"},
		{func() { kernel.put64(ewow, 0x1_0000_0000) }, "above the 32-bit limit"},
	} {
		kernel.put64(eprocess+wowMember, ewow)
		kernel.put64(ewow, peb32)
		tc.setup()
		got, ok, why := o.PEB32(ctx, eprocess)
		if ok || got != 0 || !strings.Contains(why, tc.want) || (tc.want == "") != (why == "") {
			t.Errorf("want %q: 0x%x %v %q", tc.want, got, ok, why)
		}
	}
	noPeb := table(true)
	noPeb.AddStruct(symbols.StructType{Name: "_EWOW64PROCESS", Size: 0x10})
	kernel.put64(eprocess+wowMember, ewow)
	ctx = context(kernel, noPeb)
	if _, ok, why := ResolveOffsets(ctx).PEB32(ctx, eprocess); ok || why != "symbol table has no _EWOW64PROCESS.Peb" {
		t.Errorf("no Peb member: %v %q", ok, why)
	}
}

// Records at ldr32 + 0x1000·(i+1); each is on all three lists in order.
func space(bases []uint32, blinks bool) sparse {
	s := sparse{}
	s.put32(peb32+0x0c, uint32(ldr32))
	for _, l := range lists {
		head := ldr32 + l.head
		prev := head
		for i := range bases {
			link := ldr32 + uint64(i+1)*0x1000 + l.link
			s.put32(prev, uint32(link))
			if blinks {
				s.put32(link+4, uint32(prev))
			}
			prev = link
		}
		s.put32(prev, uint32(head))
		if blinks {
			s.put32(head+4, uint32(prev))
		}
	}
	for i, b := range bases {
		s.put32(ldr32+uint64(i+1)*0x1000+recordDllBase, b)
	}
	return s
}

func TestEachListGivesItsBases(t *testing.T) {
	want := []uint32{0x400000, 0x77000000, 0x76000000}
	ctx := context(sparse{}, table(true))
	for _, list := range []List{LoadOrder, MemoryOrder, InitOrder} {
		bases, short, back := BasesRecovering(ctx, space(want, true), peb32, list)
		if len(bases) != 3 || short != "" || back != "" {
			t.Errorf("list %d: %v %q %q", list, bases, short, back)
		}
		for _, b := range want {
			if found, ok := bases[uint64(b)]; !ok || found {
				t.Errorf("list %d: base 0x%x %v %v", list, b, ok, found)
			}
		}
	}
}

func TestABrokenLinkIsRecoveredWalkingBack(t *testing.T) {
	s := space([]uint32{0x400000, 0x77000000, 0x76000000}, true)
	first := ldr32 + 0x1000
	s.put32(first, 0)
	ctx := context(sparse{}, table(true))
	bases, short, back := BasesRecovering(ctx, s, peb32, LoadOrder)
	if !strings.Contains(short, "list link is null") || back != "" {
		t.Errorf("short %q back %q", short, back)
	}
	if bases[0x400000] || !bases[0x77000000] || !bases[0x76000000] {
		t.Errorf("bases %v: the first record forward, the others only backward", bases)
	}
}

func TestWithoutTheListTypeOnlyFlinksAreFollowed(t *testing.T) {
	ctx := context(sparse{}, table(false))
	bases, short, _ := BasesRecovering(ctx, space([]uint32{0x400000, 0x77000000}, false), peb32, LoadOrder)
	if len(bases) != 2 || short != "" {
		t.Errorf("bases %v short %q", bases, short)
	}
	ctx = context(sparse{}, table(true))
	if _, short, _ := BasesRecovering(ctx, space([]uint32{0x400000}, false), peb32, LoadOrder); short == "" {
		t.Error("a typed LIST_ENTRY32 without Blinks passed the Blink check")
	}
}

func TestLoaderDataThatIsMissingOrUnreadable(t *testing.T) {
	ctx := context(sparse{}, table(true))
	s := space([]uint32{0x400000, 0x77000000}, true)
	for i := uint64(0); i < 4; i++ {
		delete(s, ldr32+0x2000+recordDllBase+i)
	}
	if bases, _, _ := BasesRecovering(ctx, s, peb32, LoadOrder); len(bases) != 1 {
		t.Errorf("a record whose DllBase does not read was kept: %v", bases)
	}
	s.put32(peb32+0x0c, 0)
	if bases, short, _ := BasesRecovering(ctx, s, peb32, LoadOrder); len(bases) != 0 || short != "" {
		t.Errorf("Ldr 0: %v %q", bases, short)
	}
	if _, short, _ := BasesRecovering(ctx, sparse{}, peb32, LoadOrder); short != "wow64: PEB32 Ldr does not read" {
		t.Errorf("unread Ldr: %q", short)
	}
	s = space([]uint32{0x400000}, true)
	delete(s, ldr32+0x0c)
	if _, short, _ := BasesRecovering(ctx, s, peb32, LoadOrder); !strings.Contains(short, "head at") {
		t.Errorf("unread head: %q", short)
	}
	if _, short, _ := BasesRecovering(ctx, s, peb32, List(9)); short == "" {
		t.Error("an unknown list gave no reason")
	}
}
