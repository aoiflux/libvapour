package memoryranges

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
)

func vadStarts(rows []VAD) []uint64 { return starts(rows, func(v VAD) uint64 { return v.Start }) }

func threeVADs() *tImage {
	img := newImage([]tVAD{
		{start: 0x20000, end: 0x2ffff, private: true},
		{start: 0x10000, end: 0x10fff, private: true},
		{start: 0x7ff600000000, end: 0x7ff600003fff, kind: 2},
	})
	img.root(0)
	img.left(0, 1)
	img.right(0, 2)
	return img
}

func TestTheWalkListsEveryNodeInAddressOrder(t *testing.T) {
	img := threeVADs()
	vads, err := ProcessVADs(img.ctx(nil), tProcess)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := vadStarts(vads), []uint64{0x10000, 0x20000, 0x7ff600000000}; !slices.Equal(got, want) {
		t.Errorf("starts %x, want %x", got, want)
	}
	if vads[0].End != 0x10fff || vads[2].End != 0x7ff600003fff {
		t.Errorf("ends %x and %x, want the last byte of the last page", vads[0].End, vads[2].End)
	}
	if vads[0].Base != nodeAt(1) || vads[0].Tag != "VadS" || !vads[0].PrivateMemoryKnown || !vads[0].PrivateMemory {
		t.Errorf("first VAD %+v", vads[0])
	}
	if !vads[2].IsMMVAD() || vads[0].IsMMVAD() {
		t.Errorf("IsMMVAD: section view %v, private %v", vads[2].IsMMVAD(), vads[0].IsMMVAD())
	}
	if len(img.diags) != 0 {
		t.Errorf("diagnostics %q", img.diags)
	}
}

func TestAnEmptyTreeHasNoVADs(t *testing.T) {
	img := newImage(nil)
	img.root(-1)
	vads, err := ProcessVADs(img.ctx(nil), tProcess)
	if err != nil || len(vads) != 0 {
		t.Errorf("got %v, %v; want none", vads, err)
	}
}

func TestAnUnreadableRootIsAnError(t *testing.T) {
	img := newImage(nil)
	img.mem.drop(tEprocess+tVadRoot, 8)
	if _, err := ProcessVADs(img.ctx(nil), tProcess); err == nil || !strings.Contains(err.Error(), "VadRoot") {
		t.Errorf("err %v, want a VadRoot read error", err)
	}
}

func TestTheHighBytesPlaceARangeAboveSixteenTerabytes(t *testing.T) {
	img := newImage([]tVAD{{start: 0x7ffe_1234_5000, end: 0x7ffe_1234_5fff, private: true}})
	img.root(0)
	vads, err := ProcessVADs(img.ctx(nil), tProcess)
	if err != nil || len(vads) != 1 || vads[0].Start != 0x7ffe_1234_5000 || vads[0].End != 0x7ffe_1234_5fff {
		t.Errorf("got %+v, %v", vads, err)
	}
}

type cutCase struct {
	name   string
	build  func() *tImage
	reason error
	starts []uint64
}

func cutCases() []cutCase {
	return []cutCase{
		{"out of order on the left", func() *tImage {
			img := threeVADs()
			img.putVAD(1, tVAD{start: 0x30000, end: 0x30fff, private: true})
			img.left(0, 1)
			return img
		}, ErrVADOutOfOrder, []uint64{0x20000, 0x7ff600000000}},
		{"overlapping its parent", func() *tImage {
			img := threeVADs()
			img.putVAD(1, tVAD{start: 0x10000, end: 0x20fff, private: true})
			img.left(0, 1)
			return img
		}, ErrVADOutOfOrder, []uint64{0x20000, 0x7ff600000000}},
		{"inverted", func() *tImage {
			img := threeVADs()
			img.putVAD(1, tVAD{start: 0x18000, end: 0x10000, private: true})
			img.left(0, 1)
			return img
		}, ErrVADInverted, []uint64{0x20000, 0x7ff600000000}},
		{"above user space", func() *tImage {
			img := threeVADs()
			img.putVAD(2, tVAD{start: 0x7fff_ffff_0000, end: 0x7fff_ffff_ffff})
			img.right(0, 2)
			return img
		}, ErrVADAboveUserSpace, []uint64{0x10000, 0x20000}},
		{"unreadable", func() *tImage {
			img := threeVADs()
			img.mem.drop(nodeAt(2)+tEndLow, 4)
			return img
		}, ErrVADUnread, []uint64{0x10000, 0x20000}},
		{"reached twice", func() *tImage {
			img := threeVADs()
			img.mem.u64(nodeAt(2)+8, nodeAt(2))
			return img
		}, ErrVADReachedTwice, []uint64{0x10000, 0x20000, 0x7ff600000000}},
	}
}

func TestANodeThatBreaksARuleIsLeftOutWithItsSubtree(t *testing.T) {
	for _, c := range cutCases() {
		t.Run(c.name, func(t *testing.T) {
			img := c.build()
			vads, err := ProcessVADs(img.ctx(nil), tProcess)
			if err != nil {
				t.Fatal(err)
			}
			if got := vadStarts(vads); !slices.Equal(got, c.starts) {
				t.Errorf("starts %x, want %x", got, c.starts)
			}
			if len(img.diags) != 1 || !strings.Contains(img.diags[0], "pid 404 _EPROCESS at 0xffff800000001000: 1 VAD tree nodes left out") {
				t.Errorf("diagnostics %q", img.diags)
			}
			img.diags = nil
			if _, err := ProcessVADs(img.ctx(map[string]any{"strict": true}), tProcess); !errors.Is(err, c.reason) {
				t.Errorf("strict: err %v, want %v", err, c.reason)
			}
		})
	}
}

func chain(n int) *tImage {
	vads := make([]tVAD, n)
	for i := range vads {
		start := uint64(0x10000_0000) - uint64(i+1)*0x10000
		vads[i] = tVAD{start: start, end: start + 0xfff, private: true}
	}
	img := newImage(vads)
	img.root(0)
	for i := 1; i < n; i++ {
		img.left(i-1, i)
	}
	return img
}

func TestTheHeightBoundIsTheTallestAVLTreeOfTheBudget(t *testing.T) {
	for budget, want := range map[int]int{1: 1, 2: 2, 3: 2, 4: 3, 7: 4, 12: 5, 1936: 15, 2583: 16, 1 << 20: 28} {
		if got := avlHeightBound(budget); got != want {
			t.Errorf("avlHeightBound(%d) = %d, want %d", budget, got, want)
		}
	}
}

func TestADeepChainIsRefused(t *testing.T) {
	img := chain(30)
	if _, err := ProcessVADs(img.ctx(nil), tProcess); !errors.Is(err, ErrVADTreeTooDeep) {
		t.Errorf("a chain of 30: err %v, want ErrVADTreeTooDeep", err)
	}
	img = chain(28)
	if vads, err := ProcessVADs(img.ctx(nil), tProcess); err != nil || len(vads) != 28 {
		t.Errorf("a chain of 28: %d VADs, %v", len(vads), err)
	}
}

func TestTheNodeBudgetEndsTheWalk(t *testing.T) {
	img := threeVADs()
	c := img.ctx(nil)
	c.Limits = limits.Limits{MaxListEntries: 2}
	vads, err := ProcessVADs(c, tProcess)
	if err != nil || len(vads) != 2 {
		t.Fatalf("%d VADs, %v; want 2", len(vads), err)
	}
	if len(img.diags) != 1 || !strings.Contains(img.diags[0], "past the node budget") {
		t.Errorf("diagnostics %q", img.diags)
	}
}

func TestAnUnreadableUserLimitFallsBackToTheDocumentedTop(t *testing.T) {
	img := threeVADs()
	img.mem.drop(tHighestVA, 8)
	if vads, err := ProcessVADs(img.ctx(nil), tProcess); err != nil || len(vads) != 3 {
		t.Fatalf("%d VADs, %v", len(vads), err)
	}
	if len(img.diags) != 1 || !strings.Contains(img.diags[0], "MmHighestUserAddress at 0xffff800000003000: not read, user space taken to end at 0x7fffffffffff") {
		t.Errorf("diagnostics %q", img.diags)
	}
}

func TestTheTreeWalkerGivesLinksAndParents(t *testing.T) {
	img := threeVADs()
	w, err := NewTreeWalker(img.t)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := w.Walk(img.ctx(nil), tProcess)
	if err != nil {
		t.Fatal(err)
	}
	want := []TreeNode{
		{Base: nodeAt(1), Parent: nodeAt(0), Start: 0x10000, End: 0x10fff, Tag: "VadS"},
		{Base: nodeAt(0), Left: nodeAt(1), Right: nodeAt(2), Start: 0x20000, End: 0x2ffff, Tag: "VadS"},
		{Base: nodeAt(2), Parent: nodeAt(0), Start: 0x7ff600000000, End: 0x7ff600003fff, Tag: "Vad "},
	}
	if !slices.Equal(nodes, want) {
		t.Errorf("nodes\n%+v\nwant\n%+v", nodes, want)
	}
}

func TestATreeWalkerNeedsParentValue(t *testing.T) {
	img := threeVADs()
	st, _ := img.t.Struct("_RTL_BALANCED_NODE")
	st.Fields = st.Fields[:2]
	img.t.AddStruct(st)
	if _, err := NewTreeWalker(img.t); !errors.Is(err, ErrVADLayout) {
		t.Errorf("err %v, want ErrVADLayout", err)
	}
}

func TestAMissingRequiredMemberIsALayoutError(t *testing.T) {
	img := threeVADs()
	img.t.AddStruct(symbolsWithout(img, "_MMVAD_SHORT", "EndingVpn"))
	if _, err := ProcessVADs(img.ctx(nil), tProcess); !errors.Is(err, ErrVADLayout) {
		t.Errorf("err %v, want ErrVADLayout", err)
	}
}

func symbolsWithout(img *tImage, typ, member string) symbols.StructType {
	st, _ := img.t.Struct(typ)
	kept := st.Fields[:0:0]
	for _, f := range st.Fields {
		if f.Name != member {
			kept = append(kept, f)
		}
	}
	st.Fields = kept
	return st
}
