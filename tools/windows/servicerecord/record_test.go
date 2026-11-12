package servicerecord

import (
	"strings"
	"testing"
)

func TestEachLayoutDecodesItsRecord(t *testing.T) {
	for _, l := range layouts {
		w := newWorld(l)
		r := running(fixtureHeap, "Schedule", 7)
		r.previous, r.next, r.processOrDriver = 0x11110, 0x22220, 0x33330
		w.record(r)
		rec, why := decode(w.mem, l, fixtureHeap, fixtureImage)
		if why != "" {
			t.Fatalf("layout %s: rejected: %s", l.name, why)
		}
		if rec.name != "Schedule" || rec.display != "Schedule display" || rec.sequence != 7 ||
			rec.status.serviceType != 0x20 || rec.status.currentState != 4 || rec.startType != 2 || rec.errorControl != 1 ||
			rec.previous != 0x11110 || rec.next != 0x22220 || rec.processOrDriver != 0x33330 {
			t.Errorf("layout %s: decoded %+v", l.name, rec)
		}
	}
}

func TestEachRecordRuleRejectsOnItsOwn(t *testing.T) {
	long := strings.Repeat("n", maxNameUnits+1)
	cases := []struct {
		name string
		edit func(w *world, r *fixtureRecord)
		want rejection
	}{
		{"tag", func(w *world, r *fixtureRecord) {}, rejectTag},
		{"name missing", func(w *world, r *fixtureRecord) { r.name = "" }, rejectName},
		{"name with a slash", func(w *world, r *fixtureRecord) { r.name = "a/b" }, rejectName},
		{"name with a backslash", func(w *world, r *fixtureRecord) { r.name = `a\b` }, rejectName},
		{"name too long", func(w *world, r *fixtureRecord) { r.name = long }, rejectName},
		{"state 0", func(w *world, r *fixtureRecord) { r.state = 0 }, rejectState},
		{"state 8", func(w *world, r *fixtureRecord) { r.state = 8 }, rejectState},
		{"type without a kind", func(w *world, r *fixtureRecord) { r.serviceType = 0x100 }, rejectType},
		{"type bit 0x200", func(w *world, r *fixtureRecord) { r.serviceType = 0x210 }, rejectType},
		{"start type 5", func(w *world, r *fixtureRecord) { r.startType = 5 }, rejectStartType},
		{"error control 4", func(w *world, r *fixtureRecord) { r.errorControl = 4 }, rejectErrorControl},
		{"sequence 0", func(w *world, r *fixtureRecord) { r.sequence = 0 }, rejectSequence},
	}
	for _, l := range layouts {
		for _, c := range cases {
			w := newWorld(l)
			r := running(fixtureHeap, "svc", 1)
			c.edit(w, &r)
			w.record(r)
			if c.want == rejectTag {
				w.mem.u32(fixtureHeap+l.tagAt, 0x41414141)
			}
			if _, why := decode(w.mem, l, fixtureHeap, fixtureImage); why != c.want {
				t.Errorf("layout %s, %s: rejection %q, want %q", l.name, c.name, why, c.want)
			}
		}
	}
}

func TestARecordOffTheHeapAlignmentIsNotOne(t *testing.T) {
	l := layoutNamed("26100")
	w := newWorld(l)
	w.record(running(fixtureHeap+8, "svc", 1))
	if _, why := decode(w.mem, l, fixtureHeap+8, fixtureImage); why != rejectTag {
		t.Errorf("rejection %q, want %q", why, rejectTag)
	}
}

func TestAnObjectRecordNeedsItsFirstPointerInTheImage(t *testing.T) {
	for _, name := range []string{"19041", "26100"} {
		l := layoutNamed(name)
		w := newWorld(l)
		w.record(running(fixtureHeap, "svc", 1))
		w.mem.u64(fixtureHeap, fixtureImageEnd)
		if _, why := decode(w.mem, l, fixtureHeap, fixtureImage); why != rejectImagePointer {
			t.Errorf("layout %s: rejection %q, want %q", name, why, rejectImagePointer)
		}
	}
}

func TestAnUnreadRecordOrNameIsRejected(t *testing.T) {
	l := layoutNamed("14393")
	w := newWorld(l)
	w.record(running(fixtureHeap, "svc", 1))
	name, _ := readPointer(w.mem, fixtureHeap+l.serviceName)
	w.mem.drop(name)
	if _, why := decode(w.mem, l, fixtureHeap, fixtureImage); why != rejectName {
		t.Errorf("unread name: rejection %q", why)
	}
	if _, why := decode(w.mem, l, fixtureHeap+0x100000, fixtureImage); why != rejectUnread {
		t.Errorf("unread record: rejection %q", why)
	}
}

func TestAnUnreadDisplayNameIsMarkedNotRejected(t *testing.T) {
	l := layoutNamed("26100")
	w := newWorld(l)
	w.record(running(fixtureHeap, "svc", 1))
	w.mem.u64(fixtureHeap+l.displayName, 0x5000000000)
	rec, why := decode(w.mem, l, fixtureHeap, fixtureImage)
	if why != "" || !rec.displayUnreadable || rec.display != "" {
		t.Errorf("rejection %q, record %+v", why, rec)
	}
	w.mem.u64(fixtureHeap+l.displayName, 0)
	if rec, _ := decode(w.mem, l, fixtureHeap, fixtureImage); rec.displayUnreadable {
		t.Error("a null display name is not unreadable")
	}
}

func TestAStringEndingBeforeAMissingPageReads(t *testing.T) {
	m := newSparse()
	at := uint64(0x10000 - 8)
	m.text(at, "abc")
	if s, ok := readUTF16(m, at, maxNameUnits); !ok || s != "abc" {
		t.Errorf("got %q %v", s, ok)
	}
	m.text(at, "abcdefgh")
	m.drop(0x10000)
	if _, ok := readUTF16(m, at, maxNameUnits); ok {
		t.Error("a string that runs into a missing page read")
	}
	if _, ok := readUTF16(m, at+1, maxNameUnits); ok {
		t.Error("an odd address read")
	}
}
