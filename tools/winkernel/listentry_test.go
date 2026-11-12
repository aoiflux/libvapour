package winkernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
)

// Readable bytes at base, except inside any hole.
type flatMem struct {
	base  uint64
	buf   []byte
	holes [][2]uint64
}

func (m *flatMem) ReadAt(at, size uint64) ([]byte, error) {
	if at < m.base || at-m.base > uint64(len(m.buf)) || size > uint64(len(m.buf))-(at-m.base) {
		return nil, fmt.Errorf("0x%x not mapped", at)
	}
	for _, h := range m.holes {
		if at < h[1] && h[0] < at+size {
			return nil, fmt.Errorf("0x%x in a hole", at)
		}
	}
	off := at - m.base
	return append([]byte(nil), m.buf[off:off+size]...), nil
}

func (m *flatMem) Size() uint64 { return uint64(len(m.buf)) }

const (
	ringBase   = uint64(0x10000)
	ringStride = uint64(0x40)
	unmapped   = uint64(0xdead0000)
)

// A well-formed list: node 0 is the head, nodes 1..n the entries in Flink order.
type ring struct {
	width uint64
	n     int
	mem   *flatMem
}

func newRing(width uint64, n int) *ring {
	r := &ring{width: width, n: n, mem: &flatMem{base: ringBase, buf: make([]byte, uint64(n+1)*ringStride)}}
	for i := 0; i <= n; i++ {
		r.setFlink(i, r.at((i+1)%(n+1)))
		r.setBlink(i, r.at((i+n)%(n+1)))
	}
	return r
}

func (r *ring) at(i int) uint64 { return ringBase + uint64(i)*ringStride }

func (r *ring) put(at, v uint64) {
	off := at - ringBase
	if r.width == 4 {
		binary.LittleEndian.PutUint32(r.mem.buf[off:], uint32(v))
		return
	}
	binary.LittleEndian.PutUint64(r.mem.buf[off:], v)
}

func (r *ring) setFlink(i int, v uint64) { r.put(r.at(i), v) }
func (r *ring) setBlink(i int, v uint64) { r.put(r.at(i)+r.width, v) }

func (r *ring) layout() ListLayout {
	return ListLayout{Width: r.width, Flink: 0, Blink: r.width, HasBlink: true}
}

func (r *ring) walker(strict bool, limit int, reports *[]string) ListWalker {
	return ListWalker{Tool: "test.tool", Memory: r.mem, Layout: r.layout(), Limit: limit, Strict: strict,
		Report: func(format string, args ...any) { *reports = append(*reports, fmt.Sprintf(format, args...)) }}
}

func (r *ring) nodes(idx ...int) []uint64 {
	var out []uint64
	for _, i := range idx {
		out = append(out, r.at(i))
	}
	return out
}

func TestTheForwardWalk(t *testing.T) {
	for _, width := range []uint64{4, 8} {
		for _, tc := range []struct {
			name    string
			n       int
			limit   int
			noBlink bool
			breakIt func(*ring)
			want    []int
			wantErr error
		}{
			{name: "intact", n: 3, want: []int{1, 2, 3}},
			{name: "empty", n: 0},
			{name: "entry back-link", n: 3, breakIt: func(r *ring) { r.setBlink(2, r.at(3)) }, want: []int{1}, wantErr: ErrListBackLink},
			{name: "head back-link", n: 3, breakIt: func(r *ring) { r.setBlink(0, r.at(1)) }, want: []int{1, 2, 3}, wantErr: ErrListBackLink},
			{name: "cycle", n: 3, breakIt: func(r *ring) { r.setFlink(3, r.at(1)) }, want: []int{1, 2, 3}, wantErr: ErrListCycle},
			{name: "null", n: 3, breakIt: func(r *ring) { r.setFlink(2, 0) }, want: []int{1, 2}, wantErr: ErrListNull},
			{name: "unreadable entry", n: 3, breakIt: func(r *ring) { r.setFlink(2, unmapped) }, want: []int{1, 2}, wantErr: ErrListUnreadable},
			{name: "limit", n: 3, limit: 2, want: []int{1, 2}, wantErr: ErrListLimit},
			{name: "no blink ignores a bad blink", n: 3, noBlink: true, breakIt: func(r *ring) { r.setBlink(2, 0) }, want: []int{1, 2, 3}},
		} {
			t.Run(fmt.Sprintf("%d/%s", width, tc.name), func(t *testing.T) {
				r := newRing(width, tc.n)
				if tc.breakIt != nil {
					tc.breakIt(r)
				}
				var reports []string
				w := r.walker(false, tc.limit, &reports)
				if tc.noBlink {
					w.Layout.HasBlink = false
				}
				walk, err := w.Walk(r.at(0), "TestHead")
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(walk.Entries, r.nodes(tc.want...)) {
					t.Errorf("entries %#x, want %#x", walk.Entries, r.nodes(tc.want...))
				}
				if !errors.Is(walk.Forward, tc.wantErr) || (tc.wantErr == nil) != (walk.Forward == nil) {
					t.Errorf("break %v, want %v", walk.Forward, tc.wantErr)
				}
				if walk.Backward != 0 || walk.Back != nil {
					t.Errorf("plain walk went backward: %+v", walk)
				}
				wantReports := 0
				if tc.wantErr != nil {
					wantReports = 1
				}
				if len(reports) != wantReports {
					t.Errorf("reports %q, want %d", reports, wantReports)
				}
				for _, rep := range reports {
					if !strings.HasPrefix(rep, "test.tool: TestHead ") || !strings.Contains(rep, " at 0x") {
						t.Errorf("report %q lacks tool, label or address", rep)
					}
				}
			})
		}
	}
}

func TestAHeadThatDoesNotReadIsAnErrorInEveryMode(t *testing.T) {
	r := newRing(8, 2)
	for _, strict := range []bool{false, true} {
		var reports []string
		w := r.walker(strict, 0, &reports)
		for _, walk := range []func(uint64, string) (ListWalk, error){w.Walk, w.WalkRecovering} {
			got, err := walk(unmapped, "TestHead")
			if !errors.Is(err, ErrListUnreadable) || got.Entries != nil {
				t.Errorf("strict %v: %+v, %v; want ErrListUnreadable and nothing", strict, got, err)
			}
		}
	}
}

func TestStrictModeReturnsTheFirstBreakAndNoEntries(t *testing.T) {
	r := newRing(8, 4)
	r.setFlink(2, 0)
	var reports []string
	w := r.walker(true, 0, &reports)
	for _, walk := range []func(uint64, string) (ListWalk, error){w.Walk, w.WalkRecovering} {
		got, err := walk(r.at(0), "TestHead")
		if !errors.Is(err, ErrListNull) || got.Entries != nil {
			t.Errorf("%+v, %v; want ErrListNull and nothing", got, err)
		}
	}
	if len(reports) != 0 {
		t.Errorf("strict mode reported %q", reports)
	}
}

func TestTheRecoveringWalk(t *testing.T) {
	for _, width := range []uint64{4, 8} {
		for _, tc := range []struct {
			name     string
			n, limit int
			noBlink  bool
			breakIt  func(*ring)
			want     []int
			backward int
			fwdErr   error
			backErr  error
		}{
			{name: "intact needs no backward walk", n: 3, want: []int{1, 2, 3}},
			{name: "one break bridged", n: 4, breakIt: func(r *ring) { r.setFlink(2, unmapped) },
				want: []int{1, 2, 4, 3}, backward: 2, fwdErr: ErrListUnreadable},
			{name: "two breaks miss the middle", n: 5, breakIt: func(r *ring) { r.setFlink(2, unmapped); r.setBlink(4, 0) },
				want: []int{1, 2, 5, 4}, backward: 2, fwdErr: ErrListUnreadable, backErr: ErrListNull},
			{name: "limit starts no backward walk", n: 4, limit: 2, want: []int{1, 2}, fwdErr: ErrListLimit},
			{name: "limit covers both walks", n: 5, limit: 3, breakIt: func(r *ring) { r.setFlink(2, unmapped) },
				want: []int{1, 2, 5}, backward: 1, fwdErr: ErrListUnreadable, backErr: ErrListLimit},
			{name: "no blink, no backward walk", n: 4, noBlink: true, breakIt: func(r *ring) { r.setFlink(2, unmapped) },
				want: []int{1, 2}, fwdErr: ErrListUnreadable},
			{name: "back-link break recovered from the other side", n: 4, breakIt: func(r *ring) { r.setBlink(3, r.at(1)) },
				want: []int{1, 2, 4, 3}, backward: 2, fwdErr: ErrListBackLink},
		} {
			t.Run(fmt.Sprintf("%d/%s", width, tc.name), func(t *testing.T) {
				r := newRing(width, tc.n)
				if tc.breakIt != nil {
					tc.breakIt(r)
				}
				var reports []string
				w := r.walker(false, tc.limit, &reports)
				if tc.noBlink {
					w.Layout.HasBlink = false
				}
				walk, err := w.WalkRecovering(r.at(0), "TestHead")
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(walk.Entries, r.nodes(tc.want...)) || walk.Backward != tc.backward {
					t.Errorf("entries %#x backward %d, want %#x backward %d", walk.Entries, walk.Backward, r.nodes(tc.want...), tc.backward)
				}
				if !errors.Is(walk.Forward, tc.fwdErr) || (tc.fwdErr == nil) != (walk.Forward == nil) {
					t.Errorf("forward break %v, want %v", walk.Forward, tc.fwdErr)
				}
				if !errors.Is(walk.Back, tc.backErr) || (tc.backErr == nil) != (walk.Back == nil) {
					t.Errorf("backward break %v, want %v", walk.Back, tc.backErr)
				}
				breaks := 0
				for _, e := range []error{tc.fwdErr, tc.backErr} {
					if e != nil {
						breaks++
					}
				}
				if len(reports) != breaks {
					t.Errorf("reports %q, want %d", reports, breaks)
				}
			})
		}
	}
}

func TestALayoutWidthOtherThan4Or8IsRefused(t *testing.T) {
	r := newRing(8, 1)
	var reports []string
	w := r.walker(false, 0, &reports)
	w.Layout.Width = 2
	if _, err := w.Walk(r.at(0), "TestHead"); !errors.Is(err, ErrListLayout) {
		t.Errorf("got %v, want ErrListLayout", err)
	}
	if _, err := ListLayoutOf(symbols.NewTable("k", 8), "_LIST_ENTRY", 16); !errors.Is(err, ErrListLayout) {
		t.Errorf("ListLayoutOf width 16: got %v, want ErrListLayout", err)
	}
}

func TestListLayoutComesFromTheTable(t *testing.T) {
	table := symbols.NewTable("k", 8)
	table.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 16, Fields: []symbols.Field{
		{Name: "Flink", Offset: 0}, {Name: "Blink", Offset: 8}}})
	table.AddStruct(symbols.StructType{Name: "LIST_ENTRY32", Size: 8, Fields: []symbols.Field{{Name: "Flink", Offset: 0}}})

	if l, err := NativeListLayout(table); err != nil || l != (ListLayout{Width: 8, Flink: 0, Blink: 8, HasBlink: true}) {
		t.Errorf("native: %+v, %v", l, err)
	}
	if l, err := ListLayoutOf(table, "LIST_ENTRY32", 4); err != nil || l.HasBlink || l.Width != 4 {
		t.Errorf("flink-only: %+v, %v", l, err)
	}
	if _, err := ListLayoutOf(table, "_MISSING", 8); err == nil {
		t.Error("a type with no Flink gave a layout")
	}
}

func TestAnEntryReadThatWouldPassTheEndOfTheSpaceIsUnreadable(t *testing.T) {
	r := newRing(8, 2)
	r.setFlink(1, ^uint64(0)-4)
	var reports []string
	walk, err := r.walker(false, 0, &reports).Walk(r.at(0), "TestHead")
	if err != nil || !errors.Is(walk.Forward, ErrListUnreadable) || !slices.Equal(walk.Entries, r.nodes(1)) {
		t.Errorf("%+v, %v", walk, err)
	}
}

func TestContainer(t *testing.T) {
	for _, tc := range []struct {
		entry, member, want uint64
		ok                  bool
	}{
		{0x1020, 0x20, 0x1000, true},
		{0x20, 0x20, 0, true},
		{0x1f, 0x20, 0, false},
	} {
		if got, ok := Container(tc.entry, tc.member); got != tc.want || ok != tc.ok {
			t.Errorf("Container(%#x, %#x) = %#x, %v; want %#x, %v", tc.entry, tc.member, got, ok, tc.want, tc.ok)
		}
	}
}

func FuzzWalkRecovering(f *testing.F) {
	for _, width := range []uint64{4, 8} {
		r := newRing(width, 4)
		f.Add(r.mem.buf, width == 4, uint8(10), false)
		r.setFlink(2, r.at(1))
		f.Add(r.mem.buf, width == 4, uint8(10), true)
	}
	f.Add([]byte{}, false, uint8(0), false)

	f.Fuzz(func(t *testing.T, data []byte, narrow bool, limit uint8, strict bool) {
		width := uint64(8)
		if narrow {
			width = 4
		}
		mem := &flatMem{base: ringBase, buf: data}
		max := int(limit%16) + 1
		w := ListWalker{Tool: "fuzz", Memory: mem, Layout: ListLayout{Width: width, Blink: width, HasBlink: true},
			Limit: max, Strict: strict}
		for _, walk := range []func(uint64, string) (ListWalk, error){w.Walk, w.WalkRecovering} {
			got, err := walk(ringBase, "FuzzHead")
			if strict && err != nil && len(got.Entries) > 0 {
				t.Fatalf("strict walk gave entries with error %v", err)
			}
			if len(got.Entries) > max {
				t.Fatalf("%d entries past the limit %d", len(got.Entries), max)
			}
			if got.Backward > len(got.Entries) {
				t.Fatalf("backward %d of %d entries", got.Backward, len(got.Entries))
			}
			seen := map[uint64]bool{}
			for _, e := range got.Entries {
				if e == ringBase {
					t.Fatal("head listed")
				}
				if seen[e] {
					t.Fatalf("0x%x listed twice", e)
				}
				seen[e] = true
			}
		}
	})
}
