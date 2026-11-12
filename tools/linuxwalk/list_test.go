package linuxwalk_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const (
	head     = base + 0x8000
	unmapped = base + 0x900000
)

type listCase struct {
	name    string
	lim     limits.Limits
	build   func(mem *kerntest.Memory, follow, back uint64) uint64
	entries int
	end     linuxwalk.End
	at      func(l []uint64) uint64
	paired  bool
}

// link writes one list_head whose followed pointer is to and whose back
// pointer is from, for whichever direction the case runs in.
func link(mem *kerntest.Memory, at, follow, back, to, from uint64) {
	mem.U64(at+follow, to)
	mem.U64(at+back, from)
}

func chain(mem *kerntest.Memory, follow, back uint64, hd uint64, ls []uint64, last uint64) {
	all := append([]uint64{hd}, ls...)
	for i, at := range all {
		to := last
		if i+1 < len(all) {
			to = all[i+1]
		}
		from := hd
		if i > 0 {
			from = all[i-1]
		}
		if i == 0 {
			from = ls[len(ls)-1]
		}
		link(mem, at, follow, back, to, from)
	}
}

func TestListEnds(t *testing.T) {
	ls := links(items(3), itemLink)
	cases := []listCase{
		{name: "closed", entries: 3, end: linuxwalk.Closed, paired: true,
			build: func(mem *kerntest.Memory, f, b uint64) uint64 { chain(mem, f, b, head, ls, head); return head },
			at:    func([]uint64) uint64 { return 0 }},
		{name: "empty", entries: 0, end: linuxwalk.Closed, paired: true,
			build: func(mem *kerntest.Memory, f, b uint64) uint64 { link(mem, head, f, b, head, head); return head },
			at:    func([]uint64) uint64 { return 0 }},
		{name: "head unreadable", entries: 0, end: linuxwalk.HeadUnreadable, paired: true,
			build: func(*kerntest.Memory, uint64, uint64) uint64 { return unmapped },
			at:    func([]uint64) uint64 { return unmapped }},
		{name: "null link", entries: 2, end: linuxwalk.LinkUnreadable, paired: true,
			build: func(mem *kerntest.Memory, f, b uint64) uint64 { chain(mem, f, b, head, ls[:2], 0); return head },
			at:    func(l []uint64) uint64 { return l[1] }},
		{name: "link into unmapped memory", entries: 1, end: linuxwalk.LinkUnreadable, paired: true,
			build: func(mem *kerntest.Memory, f, b uint64) uint64 {
				chain(mem, f, b, head, ls[:1], unmapped)
				return head
			},
			at: func(l []uint64) uint64 { return l[0] }},
		{name: "entry before an unmapped page", entries: 0, end: linuxwalk.EntryUnreadable, paired: true,
			build: func(mem *kerntest.Memory, f, b uint64) uint64 {
				edge := base + 0x20000
				chain(mem, f, b, head, []uint64{edge}, head)
				return head
			},
			at: func([]uint64) uint64 { return base + 0x20000 }},
		{name: "loop past the head", entries: 2, end: linuxwalk.Revisited, paired: true,
			build: func(mem *kerntest.Memory, f, b uint64) uint64 { chain(mem, f, b, head, ls[:2], ls[0]); return head },
			at:    func(l []uint64) uint64 { return l[1] }},
		{name: "capped", lim: limits.Limits{MaxListEntries: 2}, entries: 2, end: linuxwalk.Capped, paired: true,
			build: func(mem *kerntest.Memory, f, b uint64) uint64 { chain(mem, f, b, head, ls, head); return head },
			at:    func(l []uint64) uint64 { return l[2] }},
		{name: "unpaired back link", entries: 3, end: linuxwalk.Closed,
			build: func(mem *kerntest.Memory, f, b uint64) uint64 {
				chain(mem, f, b, head, ls, head)
				mem.U64(ls[1]+b, ls[2])
				return head
			},
			at: func([]uint64) uint64 { return 0 }},
	}
	for _, c := range cases {
		for _, dir := range []linuxwalk.Direction{linuxwalk.Forward, linuxwalk.Backward} {
			t.Run(c.name+"/"+dir.String(), func(t *testing.T) {
				ty := kerntest.NewTypes(8)
				listTypes(ty)
				mem := kerntest.NewMemory()
				mem.Map(base, 0x10000)
				mem.Map(base+0x20000, page)
				follow, back := uint64(0), uint64(8)
				if dir == linuxwalk.Backward {
					follow, back = back, follow
				}
				hd := c.build(mem, follow, back)
				l, err := reader(t, mem, ty, c.lim).List(hd, "item", "link", dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(l.Entries) != c.entries || l.End != c.end || l.At != c.at(ls) {
					t.Errorf("got %d entries, end %q at %#x; want %d, %q at %#x", len(l.Entries), l.End, l.At,
						c.entries, c.end, c.at(ls))
				}
				if !slices.Equal(l.Entries, items(3)[:len(l.Entries)]) {
					t.Errorf("entries %#x are not the items in walk order", l.Entries)
				}
				if (l.Unpaired == 0) != c.paired {
					t.Errorf("unpaired count %d", l.Unpaired)
				}
				if l.Broken() != (c.end != linuxwalk.Closed) {
					t.Errorf("Broken() = %v for end %q", l.Broken(), l.End)
				}
			})
		}
	}
}

func TestListRefusesAMissingMember(t *testing.T) {
	ty := kerntest.NewTypes(8)
	listTypes(ty)
	mem := kerntest.NewMemory()
	ring(mem, head)
	_, err := reader(t, mem, ty, limits.Limits{}).List(head, "item", "absent", linuxwalk.Forward)
	if !errors.Is(err, linuxwalk.ErrUnsupported) {
		t.Errorf("got %v, want ErrUnsupported", err)
	}
	_, err = reader(t, mem, ty, limits.Limits{}).HList(head, "absent", "hnode")
	if !errors.Is(err, linuxwalk.ErrUnsupported) {
		t.Errorf("hlist: got %v, want ErrUnsupported", err)
	}
}

func TestListAppliesTheAddressForm(t *testing.T) {
	ty := kerntest.NewTypes(8)
	listTypes(ty)
	mem := kerntest.NewMemory()
	const mask = 1<<48 - 1
	ls := links(items(2), itemLink)
	stored := []uint64{head & mask, ls[0] & mask, ls[1] & mask}
	for i, at := range []uint64{head, ls[0], ls[1]} {
		mem.U64(at, stored[(i+1)%3])
		mem.U64(at+8, stored[(i+2)%3])
	}
	r := reader(t, mem, ty, limits.Limits{})
	r.Address = func(v uint64) uint64 {
		v &= mask
		if v&(1<<47) != 0 {
			v |= ^uint64(mask)
		}
		return v
	}
	l, err := r.List(head, "item", "link", linuxwalk.Forward)
	if err != nil || l.End != linuxwalk.Closed || !slices.Equal(l.Entries, items(2)) || l.Unpaired != 0 {
		t.Errorf("masked links: %+v, %v", l, err)
	}
}

func TestHListEnds(t *testing.T) {
	ns := links(items(3), itemHNode)
	cases := []struct {
		name    string
		lim     limits.Limits
		build   func(mem *kerntest.Memory) uint64
		entries int
		end     linuxwalk.End
		at      uint64
		paired  bool
	}{
		{"closed", limits.Limits{}, func(mem *kerntest.Memory) uint64 { hchain(mem, head, ns...); return head },
			3, linuxwalk.Closed, 0, true},
		{"empty", limits.Limits{}, func(mem *kerntest.Memory) uint64 { hchain(mem, head); return head },
			0, linuxwalk.Closed, 0, true},
		{"head unreadable", limits.Limits{}, func(*kerntest.Memory) uint64 { return unmapped },
			0, linuxwalk.HeadUnreadable, unmapped, true},
		{"node unmapped", limits.Limits{}, func(mem *kerntest.Memory) uint64 {
			hchain(mem, head, ns[:2]...)
			mem.U64(ns[1], unmapped)
			return head
		}, 2, linuxwalk.LinkUnreadable, ns[1], true},
		{"first node unmapped", limits.Limits{}, func(mem *kerntest.Memory) uint64 {
			mem.U64(head, unmapped)
			return head
		}, 0, linuxwalk.LinkUnreadable, head, true},
		{"entry before an unmapped page", limits.Limits{}, func(mem *kerntest.Memory) uint64 {
			hchain(mem, head, base+0x20000)
			return head
		}, 0, linuxwalk.EntryUnreadable, base + 0x20000, true},
		{"loop", limits.Limits{}, func(mem *kerntest.Memory) uint64 {
			hchain(mem, head, ns[:2]...)
			mem.U64(ns[1], ns[0])
			return head
		}, 2, linuxwalk.Revisited, ns[1], true},
		{"capped", limits.Limits{MaxListEntries: 2}, func(mem *kerntest.Memory) uint64 {
			hchain(mem, head, ns...)
			return head
		}, 2, linuxwalk.Capped, ns[2], true},
		{"unpaired pprev", limits.Limits{}, func(mem *kerntest.Memory) uint64 {
			hchain(mem, head, ns...)
			mem.U64(ns[2]+8, head)
			return head
		}, 3, linuxwalk.Closed, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ty := kerntest.NewTypes(8)
			listTypes(ty)
			mem := kerntest.NewMemory()
			mem.Map(base, 0x10000)
			mem.Map(base+0x20000, page)
			hd := c.build(mem)
			l, err := reader(t, mem, ty, c.lim).HList(hd, "item", "hnode")
			if err != nil {
				t.Fatal(err)
			}
			if len(l.Entries) != c.entries || l.End != c.end || l.At != c.at {
				t.Errorf("got %d entries, end %q at %#x; want %d, %q at %#x", len(l.Entries), l.End, l.At,
					c.entries, c.end, c.at)
			}
			if !slices.Equal(l.Entries, items(3)[:len(l.Entries)]) {
				t.Errorf("entries %#x are not the items in walk order", l.Entries)
			}
			if (l.Unpaired == 0) != c.paired {
				t.Errorf("unpaired count %d", l.Unpaired)
			}
		})
	}
}

func TestContainerOf(t *testing.T) {
	ty := kerntest.NewTypes(8)
	listTypes(ty)
	mem := kerntest.NewMemory()
	mem.Map(base, page)
	mem.Map(base+0x20000, page)
	r := reader(t, mem, ty, limits.Limits{})
	for _, c := range []struct {
		name  string
		addr  uint64
		entry uint64
		ok    bool
	}{
		{"inside", base + 0x100 + itemLink, base + 0x100, true},
		{"null", 0, 0, false},
		{"container unmapped", base + 0x20000, 0, false},
		{"below the member offset", 4, 0, false},
	} {
		entry, ok, err := r.ContainerOf(c.addr, "item", "link")
		if err != nil || ok != c.ok || ok && entry != c.entry {
			t.Errorf("%s: %#x %v %v", c.name, entry, ok, err)
		}
	}
	if _, _, err := r.ContainerOf(base, "item", "absent"); !errors.Is(err, linuxwalk.ErrUnsupported) {
		t.Errorf("absent member: %v", err)
	}
}
