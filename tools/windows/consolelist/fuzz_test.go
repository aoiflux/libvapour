package consolelist

import (
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

const fuzzHeapBytes = 0x4000

// The console object and the first heap pages as bytes, so the fuzzer starts
// from a console that reads whole.
func fuzzSeed(t testing.TB) (console, heap []byte) {
	l, _ := LayoutFor(true, 10, 0, 19041)
	f := newFixture(l)
	f.m.write(fixtureHeap, make([]byte, fuzzHeapBytes))
	spec := defaultConsole()
	spec.screens[0].first = 1
	f.console(fixtureConsole, spec)
	console, _ = f.m.ReadAt(fixtureConsole, uint64(l.console.historyCount.off)+8)
	heap, _ = f.m.ReadAt(fixtureHeap, fuzzHeapBytes)
	return console, heap
}

func fuzzSpace(console, heap []byte) Space {
	m := newSparse()
	m.write(fixtureImage, make([]byte, fixtureImageSize))
	m.write(fixtureConsole, console[:min(len(console), int(fixtureImage+fixtureImageSize-fixtureConsole))])
	m.write(fixtureHeap, make([]byte, fuzzHeapBytes))
	m.write(fixtureHeap, heap[:min(len(heap), fuzzHeapBytes)])
	return NewSpace(m, []Region{
		{Start: fixtureHeap, End: fixtureHeap + fuzzHeapBytes},
		{Start: fixtureImage, End: fixtureImage + fixtureImageSize},
	})
}

func fuzzLimits() limits.Limits {
	b := limits.Default()
	b.MaxListEntries, b.MaxRowsPerObject, b.MaxTextBytes = 64, 64, 4096
	return b
}

func FuzzReadConsole(f *testing.F) {
	console, heap := fuzzSeed(f)
	f.Add(console, heap)
	f.Add(console[:200], heap[:64])
	l, _ := LayoutFor(true, 10, 0, 19041)
	f.Fuzz(func(t *testing.T, console, heap []byte) {
		s, b := fuzzSpace(console, heap), fuzzLimits()
		v := l.InspectConsole(s, fixtureConsole, b)
		if !v.Accepted() {
			if v.Rule == "" || v.Err == nil {
				t.Fatalf("rejection without a rule: %+v", v)
			}
			return
		}
		c := l.ReadConsole(s, fixtureConsole, nil, b)
		if len(c.AttachedProcesses) == 0 || c.ScreenBufferColumns <= 0 || c.ScreenBufferRows <= 0 {
			t.Fatalf("accepted console breaks its rules: %+v", c)
		}
		if len(c.Histories) > int(c.NumberOfHistoryBuffers) {
			t.Fatalf("%d histories, at most %d", len(c.Histories), c.NumberOfHistoryBuffers)
		}
		for _, sc := range c.Screens {
			if len(sc.Rows) > sc.RowCount || sc.RowCount > b.MaxRowsPerObject {
				t.Fatalf("screen %+v", sc)
			}
			for i := 1; i < len(sc.Rows); i++ {
				if sc.Rows[i].Row <= sc.Rows[i-1].Row {
					t.Fatalf("rows out of order: %+v", sc.Rows)
				}
			}
		}
		for _, h := range c.Histories {
			if uint64(len(h.Commands)) > h.BufferSize || len(h.Commands) > b.MaxRowsPerObject {
				t.Fatalf("history %+v", h)
			}
		}
	})
}

func FuzzReadHistory(f *testing.F) {
	for _, build := range []uint64{19041} {
		l, _ := LayoutFor(true, 10, 0, build)
		fx := newFixture(l)
		fx.m.write(fixtureHeap, make([]byte, fuzzHeapBytes))
		node := fx.loneHistory(historySpec{app: "cmd.exe", commands: []string{"dir", "a command that needs the heap"}, recall: 1})
		heap, _ := fx.m.ReadAt(fixtureHeap, fuzzHeapBytes)
		f.Add(build == 26100, heap, node-fixtureHeap)
	}
	f.Fuzz(func(t *testing.T, wide bool, heap []byte, off uint64) {
		_ = wide
		build := uint64(19041)
		l, _ := LayoutFor(true, 10, 0, build)
		s, b := fuzzSpace(nil, heap), fuzzLimits()
		node := fixtureHeap + off%fuzzHeapBytes
		v := l.InspectHistory(s, node, 0, b)
		if !v.Accepted() {
			return
		}
		h := l.ReadHistory(s, node, b)
		if h.BufferSize == 0 || uint64(len(h.Commands)) > h.BufferSize || h.Application == "" && !h.ApplicationUnreadable {
			t.Fatalf("accepted history breaks its rules: %+v", h)
		}
		if h.RecallPosition < -1 || h.RecallPosition >= int64(max(len(h.Commands), 1)) && !h.CommandsIncomplete {
			t.Fatalf("recall %d of %d", h.RecallPosition, len(h.Commands))
		}
		for i, c := range h.Commands {
			if c.Index != i {
				t.Fatalf("commands %+v", h.Commands)
			}
		}
	})
}

func FuzzWideString(f *testing.F) {
	l, _ := LayoutFor(true, 10, 0, 19041)
	fx := newFixture(l)
	fx.m.write(fixtureHeap, make([]byte, fuzzHeapBytes))
	at := fx.alloc(l.text.size)
	fx.wide(at, "a string that lives on the heap")
	heap, _ := fx.m.ReadAt(fixtureHeap, fuzzHeapBytes)
	f.Add(heap)
	f.Fuzz(func(t *testing.T, heap []byte) {
		s := fuzzSpace(nil, heap)
		w, err := l.wideString(s, fixtureHeap, 256)
		if err != nil {
			return
		}
		if w.Length > w.Capacity || w.Capacity < l.inlineChars() || w.Length*wideBytes > 256 {
			t.Fatalf("string %+v", w)
		}
		if w.Inline != (w.Capacity <= l.inlineChars()) {
			t.Fatalf("inline %v for capacity %d", w.Inline, w.Capacity)
		}
	})
}
