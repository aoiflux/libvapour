package linuxwalk

import "fmt"

type Direction uint8

const (
	Forward Direction = iota
	Backward
)

func (d Direction) String() string {
	if d == Backward {
		return "backward"
	}
	return "forward"
}

type End uint8

const (
	Closed End = iota
	HeadUnreadable
	LinkUnreadable
	EntryUnreadable
	Revisited
	Capped
)

func (e End) String() string {
	switch e {
	case Closed:
		return "it came back to its head"
	case HeadUnreadable:
		return "its head does not read"
	case LinkUnreadable:
		return "a link is null or leads to memory that does not read"
	case EntryUnreadable:
		return "a link sits in a structure that does not read"
	case Revisited:
		return "a link leads back to a node already walked"
	case Capped:
		return "it reached Limits.MaxListEntries"
	}
	return fmt.Sprintf("End(%d)", uint8(e))
}

type List struct {
	Entries  []uint64
	End      End
	At       uint64
	Unpaired int
}

func (l List) Broken() bool { return l.End != Closed }

func (r Reader) List(head uint64, container, member string, dir Direction) (List, error) {
	if err := r.ready(); err != nil {
		return List{}, err
	}
	in, err := r.offset(container, member)
	if err != nil {
		return List{}, err
	}
	next, err := r.offset("list_head", "next")
	if err != nil {
		return List{}, err
	}
	prev, err := r.offset("list_head", "prev")
	if err != nil {
		return List{}, err
	}
	if dir == Backward {
		next, prev = prev, next
	}
	return r.circular(head, in, next, prev), nil
}

func (r Reader) circular(head, in, follow, back uint64) List {
	var l List
	link, ok := r.pointer(head + follow)
	if !ok {
		l.End, l.At = HeadUnreadable, head
		return l
	}
	span := max(follow, back) + r.width()
	most := r.bounds().MaxListEntries
	seen := map[uint64]struct{}{}
	from := head
	for {
		if link == head {
			return l
		}
		if _, again := seen[link]; again {
			l.End, l.At = Revisited, from
			return l
		}
		node, ok := r.read(link, span)
		if link == 0 || !ok {
			l.End, l.At = LinkUnreadable, from
			return l
		}
		entry, ok := r.container(link, in)
		if !ok {
			l.End, l.At = EntryUnreadable, link
			return l
		}
		if len(l.Entries) >= most {
			l.End, l.At = Capped, link
			return l
		}
		l.Entries = append(l.Entries, entry)
		seen[link] = struct{}{}
		if r.form(r.word(node, back)) != from {
			l.Unpaired++
		}
		from, link = link, r.form(r.word(node, follow))
	}
}

func (r Reader) HList(head uint64, container, member string) (List, error) {
	if err := r.ready(); err != nil {
		return List{}, err
	}
	in, err := r.offset(container, member)
	if err != nil {
		return List{}, err
	}
	first, err := r.offset("hlist_head", "first")
	if err != nil {
		return List{}, err
	}
	next, err := r.offset("hlist_node", "next")
	if err != nil {
		return List{}, err
	}
	pprev, err := r.offset("hlist_node", "pprev")
	if err != nil {
		return List{}, err
	}

	var l List
	link, ok := r.pointer(head + first)
	if !ok {
		l.End, l.At = HeadUnreadable, head
		return l, nil
	}
	span := max(next, pprev) + r.width()
	most := r.bounds().MaxListEntries
	seen := map[uint64]struct{}{}
	from, holder := head, r.form(head+first)
	for link != 0 {
		if _, again := seen[link]; again {
			l.End, l.At = Revisited, from
			return l, nil
		}
		node, ok := r.read(link, span)
		if !ok {
			l.End, l.At = LinkUnreadable, from
			return l, nil
		}
		entry, ok := r.container(link, in)
		if !ok {
			l.End, l.At = EntryUnreadable, link
			return l, nil
		}
		if len(l.Entries) >= most {
			l.End, l.At = Capped, link
			return l, nil
		}
		l.Entries = append(l.Entries, entry)
		seen[link] = struct{}{}
		if r.form(r.word(node, pprev)) != holder {
			l.Unpaired++
		}
		from, holder, link = link, r.form(link+next), r.form(r.word(node, next))
	}
	return l, nil
}

func (r Reader) container(link, in uint64) (uint64, bool) {
	if link < in {
		return 0, false
	}
	entry := r.form(link - in)
	_, ok := r.read(entry, 1)
	return entry, ok
}

func (r Reader) ContainerOf(addr uint64, container, member string) (uint64, bool, error) {
	if err := r.ready(); err != nil {
		return 0, false, err
	}
	in, err := r.offset(container, member)
	if err != nil {
		return 0, false, err
	}
	link := r.form(addr)
	if link == 0 {
		return 0, false, nil
	}
	entry, ok := r.container(link, in)
	return entry, ok, nil
}
