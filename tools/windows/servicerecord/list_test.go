package servicerecord

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
)

func TestEachHeadFormIsFoundInTheImage(t *testing.T) {
	for _, l := range layouts {
		w := newWorld(l)
		h := w.list("a", "b", "c")
		heads := searchHeads(w.mem, fixtureImage)
		if len(heads) != 1 || heads[0].address != h.address || heads[0].form != l.head {
			t.Errorf("layout %s: heads %+v, want one at 0x%x", l.name, heads, h.address)
		}
	}
}

func TestAHeadTagWhoseLinksDoNotLeadBackIsNotAHead(t *testing.T) {
	w := newWorld(layoutNamed("26100"))
	h := w.list("a", "b")
	w.mem.u64(fixtureHeap+0x10, 0x4444)
	if heads := searchHeads(w.mem, fixtureImage); len(heads) != 0 {
		t.Errorf("first record's previous link set: heads %+v", heads)
	}
	w = newWorld(layoutNamed("14393"))
	h = w.list("a", "b")
	w.mem.u64(fixtureHeap+0x08, 0)
	if heads := searchHeads(w.mem, fixtureImage); len(heads) != 0 {
		t.Errorf("sentinel not pointed back to at 0x%x: heads %+v", h.address, heads)
	}
}

func TestThePDBGlobalGivesTheHead(t *testing.T) {
	w := newWorld(layoutNamed("14393"))
	h := w.list("a", "b")
	table := symbols.NewTable("services", 8)
	table.AddSymbol(symbols.Symbol{Name: publicSentinel, Address: h.address - fixtureImageStart})
	table.AddSymbol(symbols.Symbol{Name: publicSentinelSize, Address: 0x30000})
	w.mem.u32(fixtureImageStart+0x30000, 2)
	got, err := pdbHead(w.mem, table, fixtureImage)
	if err != nil || got.address != h.address || got.form != headSentinel || !got.fromPDB || !got.sentinelCountKnown || got.sentinelCount != 2 {
		t.Fatalf("head %+v, err %v", got, err)
	}
	w.mem.u32(h.address, 0)
	if _, err := pdbHead(w.mem, table, fixtureImage); err == nil {
		t.Error("a PDB global without the tag was taken")
	}
	if _, err := pdbHead(w.mem, symbols.NewTable("empty", 8), fixtureImage); !errors.Is(err, errNoPDBHead) {
		t.Errorf("no public: err %v", err)
	}
}

func TestTheWalkFollowsTheList(t *testing.T) {
	for _, l := range layouts {
		w := newWorld(l)
		h := w.list("a", "b", "c")
		got := bestWalk(w.mem, h, fixtureImage, 0, nil)
		if got.cut != nil || len(got.records) != 3 || got.layout.name != l.name || got.badBackLinks != 0 {
			t.Errorf("layout %s: walk %s, %d records, cut %v, bad links %d", l.name, got.layout.name, len(got.records), got.cut, got.badBackLinks)
		}
		if p := got.headProblems(h); len(p) != 0 {
			t.Errorf("layout %s: head problems %v", l.name, p)
		}
	}
}

func TestTheWalkStopsOnAFailingRecordARepeatOrTheCap(t *testing.T) {
	l := layoutNamed("26100")
	w := newWorld(l)
	h := w.list("a", "b", "c", "d")
	w.mem.u32(fixtureHeap+0x400+l.status+4, 9)
	got := walkList(w.mem, l, h, fixtureImage, 0)
	if len(got.records) != 2 || !errors.Is(got.cut, errRejected) || got.cutAt != fixtureHeap+0x400 {
		t.Errorf("failing record: %d records, cut %v at 0x%x", len(got.records), got.cut, got.cutAt)
	}
	w = newWorld(l)
	h = w.list("a", "b", "c")
	w.mem.u64(fixtureHeap+0x400+l.next, fixtureHeap)
	if got := walkList(w.mem, l, h, fixtureImage, 0); len(got.records) != 3 || !errors.Is(got.cut, errRepeat) {
		t.Errorf("repeat: %d records, cut %v", len(got.records), got.cut)
	}
	w = newWorld(l)
	h = w.list("a", "b", "c")
	if got := walkList(w.mem, l, h, fixtureImage, 2); len(got.records) != 2 || !errors.Is(got.cut, errEntryCap) {
		t.Errorf("cap: %d records, cut %v", len(got.records), got.cut)
	}
}

func TestAWrongBackLinkIsCountedAndTheHeadIsChecked(t *testing.T) {
	l := layoutNamed("19041")
	w := newWorld(l)
	h := w.list("a", "b", "c")
	w.mem.u64(fixtureHeap+0x400+l.previous, 0x1230)
	w.mem.u32(h.address+databaseCount, 5)
	w.mem.u32(h.address+databaseCounter, 2)
	w.mem.u64(h.address+databaseLast, fixtureHeap)
	got := walkList(w.mem, l, h, fixtureImage, 0)
	if got.badBackLinks != 1 || got.firstBadLink != fixtureHeap+0x400 {
		t.Errorf("bad links %d at 0x%x", got.badBackLinks, got.firstBadLink)
	}
	p := strings.Join(got.headProblems(h), "; ")
	for _, want := range []string{"as the last record", "head counts 5 records", "above the head's counter 2"} {
		if !strings.Contains(p, want) {
			t.Errorf("head problems %q lack %q", p, want)
		}
	}
	s := head{form: headSentinel, sentinelCount: 4, sentinelCountKnown: true}
	if p := (walk{records: make([]record, 3)}).headProblems(s); len(p) != 1 || !strings.Contains(p[0], "ScTotalNumServiceRecs is 4") {
		t.Errorf("sentinel count: %v", p)
	}
}

func TestAHeadThatDoesNotReadCutsTheWalk(t *testing.T) {
	l := layoutNamed("26100")
	got := walkList(newSparse(), l, head{address: fixtureImageStart, form: headDatabase}, fixtureImage, 0)
	if !errors.Is(got.cut, errRejected) || len(got.records) != 0 {
		t.Errorf("cut %v, %d records", got.cut, len(got.records))
	}
}
