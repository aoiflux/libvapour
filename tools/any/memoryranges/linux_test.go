package memoryranges

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	mmTree      = 0xa0
	mmMapCount  = 0xb0
	treeFlags   = 0x04
	treeRoot    = 0x08
	r64Pivots   = 0x08
	r64Slots    = 0x80
	r64Meta     = 0xf8
	a64Pivots   = 0x08
	a64Slots    = 0x50
	a64Meta     = 0xf0
	leafType    = 1
	rangeType   = 2
	arangeType  = 3
	rootMark    = 0x02
	childMark   = 0x04
	maxIndex    = ^uint64(0)
	parentRange = 0x06
)

func tField(name string, off uint64, typ symbols.TypeRef) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: typ}
}

func tArray(name string, n uint64) symbols.TypeRef {
	return symbols.TypeRef{Name: name, IsArray: true, ArrayLength: n, Element: &symbols.TypeRef{Name: name}}
}

// treeKernel is the AddFS kernel with mm_struct holding a maple tree in place
// of the area list, laid out as the 64-bit types of S39 T3.
func treeKernel(t *testing.T) *lt.Kernel {
	t.Helper()
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	tb := k.Table
	mm, err := tb.Struct("mm_struct")
	if err != nil {
		t.Fatal(err)
	}
	var kept []symbols.Field
	for _, f := range mm.Fields {
		if f.Name != "mmap" {
			kept = append(kept, f)
		}
	}
	mm.Fields = append(kept, tField("mm_mt", mmTree, symbols.TypeRef{Name: "maple_tree"}),
		tField("map_count", mmMapCount, symbols.TypeRef{Name: "int"}))
	tb.AddStruct(mm)
	ul := symbols.TypeRef{Name: "long unsigned int"}
	voidp := symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: "void"}}
	tb.AddStruct(symbols.StructType{Name: "maple_tree", Size: 0x10, Fields: []symbols.Field{
		tField("ma_flags", treeFlags, symbols.TypeRef{Name: "unsigned int"}), tField("ma_root", treeRoot, voidp)}})
	tb.AddStruct(symbols.StructType{Name: "maple_metadata", Size: 2, Fields: []symbols.Field{
		tField("end", 0, symbols.TypeRef{Name: "unsigned char"}), tField("gap", 1, symbols.TypeRef{Name: "unsigned char"})}})
	tb.AddStruct(symbols.StructType{Name: "maple_node", Size: 256, Fields: []symbols.Field{
		tField("parent", 0, voidp), tField("slot", 8, tArray("void", 31))}})
	tb.AddStruct(symbols.StructType{Name: "maple_range_64", Size: 256, Fields: []symbols.Field{
		tField("parent", 0, voidp), tField("pivot", r64Pivots, tArray(ul.Name, 15)),
		tField("slot", r64Slots, tArray("void", 16)), tField("meta", r64Meta, symbols.TypeRef{Name: "maple_metadata"})}})
	tb.AddStruct(symbols.StructType{Name: "maple_arange_64", Size: 248, Fields: []symbols.Field{
		tField("parent", 0, voidp), tField("pivot", a64Pivots, tArray(ul.Name, 9)),
		tField("slot", a64Slots, tArray("void", 10)), tField("gap", 0xa0, tArray(ul.Name, 10)),
		tField("meta", a64Meta, symbols.TypeRef{Name: "maple_metadata"})}})
	return k
}

type area struct{ start, end, flags, file uint64 }

func putArea(k *lt.Kernel, mm uint64, a area) uint64 {
	v := k.Alloc(lt.FSVMASize)
	k.Mem.U64(v+lt.FSVMAStart, a.start)
	k.Mem.U64(v+lt.FSVMAEnd, a.end)
	k.Mem.U64(v+lt.FSVMAMM, mm)
	k.Mem.U64(v+lt.FSVMAFlags, a.flags)
	k.Mem.U64(v+lt.FSVMAFile, a.file)
	return v
}

func node(k *lt.Kernel) uint64 {
	a := k.Alloc(512)
	return (a + 255) &^ 255
}

type slot struct {
	last, entry uint64
}

// putNode writes one node; a child slot's entry is a node address and gets
// its encoding and parent link here, as mas_set_parent does.
func putNode(k *lt.Kernel, at, kind, parent uint64, slots []slot, metaEnd uint8) uint64 {
	pivots, slotAt, meta, npiv := uint64(r64Pivots), uint64(r64Slots), uint64(r64Meta), 15
	if kind == arangeType {
		pivots, slotAt, meta, npiv = a64Pivots, a64Slots, a64Meta, 9
	}
	k.Mem.U64(at, parent)
	for i, s := range slots {
		if i < npiv {
			k.Mem.U64(at+pivots+uint64(i)*8, s.last)
		}
		k.Mem.U64(at+slotAt+uint64(i)*8, s.entry)
	}
	k.Mem.Write(at+meta, []byte{metaEnd})
	return at | kind<<3 | childMark
}

func setTree(k *lt.Kernel, mm, root uint64, height int, count int32) {
	k.Mem.U64(mm+mmTree+treeRoot, root|rootMark)
	k.Mem.U32(mm+mmTree+treeFlags, uint32(height)<<2|1)
	k.Mem.U32(mm+mmMapCount, uint32(count))
}

func childParent(n uint64, slot int) uint64 { return n | uint64(slot)<<3 | parentRange }

type treeCase struct {
	k     *lt.Kernel
	mm    uint64
	task  uint64
	areas []uint64
}

// twoLevels builds an arange_64 root over two leaf_64 nodes holding four
// areas with gaps, the shape of a small process (S39 T2 to T5).
func twoLevels(t *testing.T) *treeCase {
	t.Helper()
	k := treeKernel(t)
	mm := k.Alloc(lt.FSMMSize)
	c := &treeCase{k: k, mm: mm}
	for _, a := range []area{{0x400000, 0x401000, 5, 0}, {0x401000, 0x403000, 3, 0}, {0x7f000000, 0x7f001000, 1, 0},
		{0x7ffd0000, 0x7ffd2000, 3, 0}} {
		c.areas = append(c.areas, putArea(k, mm, a))
	}
	root, left, right := node(k), node(k), node(k)
	putNode(k, left, leafType, childParent(root, 0), []slot{{0x3fffff, 0}, {0x400fff, c.areas[0]}, {0x402fff, c.areas[1]},
		{0x7effffff, 0}}, 3)
	putNode(k, right, leafType, childParent(root, 1), []slot{{0x7f000fff, c.areas[2]}, {0x7ffcffff, 0},
		{0x7ffd1fff, c.areas[3]}, {0, 0}}, 3)
	rootEnode := putNode(k, root, arangeType, k.Alloc(8)|1, []slot{
		{0x7effffff, left | leafType<<3 | childMark}, {maxIndex, right | leafType<<3 | childMark}}, 1)
	setTree(k, mm, rootEnode, 2, 4)
	c.task = k.AddTask(lt.Task{PID: 100, TGID: 100, Comm: "app", MM: mm})
	k.LinkTasks(c.task)
	k.NewRootFS().Enter(c.task)
	return c
}

func (c *treeCase) walker(t *testing.T, lim limits.Limits) *LinuxWalker {
	t.Helper()
	ctx, _ := c.k.Context(nil)
	ctx.Limits = lim
	lw, err := NewLinuxWalker(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return lw
}

func areaStarts(vmas []LinuxVMA) []uint64 {
	var out []uint64
	for _, v := range vmas {
		out = append(out, v.Start)
	}
	return out
}

func TestAMapleTreeGivesItsAreasInOrder(t *testing.T) {
	c := twoLevels(t)
	mm, vmas, err := c.walker(t, limits.Limits{}).TaskVMAs(c.task)
	if err != nil || mm != c.mm {
		t.Fatalf("TaskVMAs: mm %#x, %v", mm, err)
	}
	if want := []uint64{0x400000, 0x401000, 0x7f000000, 0x7ffd0000}; !slices.Equal(areaStarts(vmas), want) {
		t.Errorf("starts = %x, want %x", areaStarts(vmas), want)
	}
	if vmas[1].End != 0x403000 || vmas[1].Addr != c.areas[1] {
		t.Errorf("second area = %+v", vmas[1])
	}
	_, losses := c.walker(t, limits.Limits{}).AreaWalk(c.mm)
	if losses.TreeNodes != 3 || losses.TreeHeight != 2 || losses.FlagHeight != 2 || losses.Mismatch() {
		t.Errorf("walk = %+v", losses)
	}
}

func TestADataEndFollowsTheLastPivot(t *testing.T) {
	k := treeKernel(t)
	mm := k.Alloc(lt.FSMMSize)
	slots := []slot{{0xffff, 0}}
	var want []uint64
	for i := range 14 {
		start := uint64(0x10000 + i*0x1000)
		slots = append(slots, slot{start + 0xfff, putArea(k, mm, area{start, start + 0x1000, 1, 0})})
		want = append(want, start)
	}
	leaf := node(k)
	putNode(k, leaf, leafType, k.Alloc(8)|1, slots, 0)
	setTree(k, mm, leaf|leafType<<3|childMark, 1, 14)
	task := k.AddTask(lt.Task{PID: 5, TGID: 5, Comm: "full", MM: mm})
	k.LinkTasks(task)
	c := &treeCase{k: k, mm: mm, task: task}
	_, vmas, err := c.walker(t, limits.Limits{}).TaskVMAs(task)
	if err != nil || !slices.Equal(areaStarts(vmas), want) {
		t.Errorf("a node whose last pivot is set: %x, %v; want %x", areaStarts(vmas), err, want)
	}
	k.Mem.U64(leaf+r64Pivots+14*8, 0)
	k.Mem.Write(leaf+r64Meta, []byte{3})
	_, vmas, _ = c.walker(t, limits.Limits{}).TaskVMAs(task)
	if !slices.Equal(areaStarts(vmas), want[:3]) {
		t.Errorf("a node ended by its metadata: %x; want %x", areaStarts(vmas), want[:3])
	}
}

func lossesOf(t *testing.T, err error) AreaLosses {
	t.Helper()
	var l AreaLosses
	if !errors.As(err, &l) {
		t.Fatalf("err %v, want AreaLosses", err)
	}
	return l
}

func TestAMapleTreeDropsWhatTheKernelWouldNotHaveStored(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(c *treeCase)
		rule string
		kept int
	}{
		"an area stored over another range": {func(c *treeCase) { c.k.Mem.U64(c.areas[0]+lt.FSVMAEnd, 0x402000) }, lossStored, 3},
		"an area of another mm":             {func(c *treeCase) { c.k.Mem.U64(c.areas[2]+lt.FSVMAMM, c.mm+8) }, lossOwner, 3},
		"an area with unaligned bounds": {func(c *treeCase) {
			c.k.Mem.U64(c.areas[3]+lt.FSVMAStart, 0x7ffd0010)
		}, lossBounds, 3},
		"an internal leaf entry": {func(c *treeCase) {
			right := leafOf(c, 1)
			c.k.Mem.U64(right+r64Slots, 0x402)
		}, lossInternal, 3},
		"a slot past its node's range": {func(c *treeCase) {
			c.k.Mem.U64(leafOf(c, 0)+r64Pivots+16, 0x8000000000)
		}, lossRange, 3},
		"a dead node": {func(c *treeCase) {
			left := leafOf(c, 0)
			c.k.Mem.U64(left, left)
		}, lossDead, 2},
		"a child naming another parent": {func(c *treeCase) {
			c.k.Mem.U64(leafOf(c, 1), childParent(rootOf(c), 0))
		}, lossParent, 2},
		"a node reached twice": {func(c *treeCase) {
			root := rootOf(c)
			c.k.Mem.U64(root+a64Slots+8, read64(c.k, root+a64Slots))
		}, lossRevisit, 2},
		"an inner slot that is not a node": {func(c *treeCase) {
			c.k.Mem.U64(rootOf(c)+a64Slots+8, c.areas[2])
		}, lossChild, 2},
	} {
		c := twoLevels(t)
		tc.edit(c)
		_, vmas, err := c.walker(t, limits.Limits{}).TaskVMAs(c.task)
		l := lossesOf(t, err)
		if l.Counts[tc.rule] != 1 || len(vmas) != tc.kept || !l.Mismatch() || !strings.Contains(l.Error(), tc.rule) {
			t.Errorf("%s: kept %d, losses %+v; want 1 %q and %d kept", name, len(vmas), l, tc.rule, tc.kept)
		}
	}
	c := twoLevels(t)
	_, vmas, err := c.walker(t, limits.Limits{MaxListEntries: 2}).TaskVMAs(c.task)
	if l := lossesOf(t, err); l.Counts[lossCap] != 1 || len(vmas) != 2 {
		t.Errorf("two nodes at most: kept %d, %+v", len(vmas), l)
	}
}

func rootOf(c *treeCase) uint64 {
	return read64(c.k, c.mm+mmTree+treeRoot) &^ 0xff
}

func leafOf(c *treeCase, i int) uint64 {
	return read64(c.k, rootOf(c)+a64Slots+uint64(i)*8) &^ 0xff
}

func listKernel(t *testing.T, areas []area) (*lt.Kernel, uint64, uint64) {
	t.Helper()
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	var vmas []lt.VMA
	for _, a := range areas {
		vmas = append(vmas, lt.VMA{Start: a.start, End: a.end, Flags: a.flags, File: a.file})
	}
	mm := k.AddMM(lt.MM{StartBrk: 0x600000, Brk: 0x621000, StartStack: 0x7ffd1000, VMAs: vmas})
	task := k.AddTask(lt.Task{PID: 42, TGID: 42, Comm: "list", MM: mm})
	k.LinkTasks(task)
	k.NewRootFS().Enter(task)
	return k, mm, task
}

func TestAnAreaListIsFollowedAndChecked(t *testing.T) {
	k, mm, task := listKernel(t, []area{{0x400000, 0x401000, 5, 0}, {0x600000, 0x621000, 3, 0}, {0x500000, 0x501000, 1, 0},
		{0x7ffd0000, 0x7ffd2000, 3, 0}})
	c := &treeCase{k: k, mm: mm, task: task}
	_, vmas, err := c.walker(t, limits.Limits{}).TaskVMAs(task)
	l := lossesOf(t, err)
	if want := []uint64{0x400000, 0x600000, 0x7ffd0000}; !slices.Equal(areaStarts(vmas), want) || l.Counts[lossOrder] != 1 {
		t.Errorf("list = %x, %+v; want the area below its predecessor dropped", areaStarts(vmas), l)
	}
	last := vmas[2].Addr
	k.Mem.U64(last+lt.FSVMANext, vmas[0].Addr)
	_, _, err = c.walker(t, limits.Limits{}).TaskVMAs(task)
	if l := lossesOf(t, err); l.Counts[lossRevisit] != 1 {
		t.Errorf("a list that loops: %+v", l)
	}
}

func FuzzMapleTree(f *testing.F) {
	f.Add(make([]byte, 0x300), uint8(arangeType))
	f.Fuzz(func(t *testing.T, data []byte, kind uint8) {
		k := treeKernel(t)
		mm := k.Alloc(lt.FSMMSize)
		region := node(k)
		k.Alloc(0x1000)
		if len(data) > 0x800 {
			data = data[:0x800]
		}
		k.Mem.Write(region, data)
		setTree(k, mm, region|uint64(kind&0xf)<<3|childMark, 3, 0)
		ctx, _ := k.Context(nil)
		ctx.Limits = limits.Limits{MaxListEntries: 64}
		lw, err := NewLinuxWalker(ctx)
		if err != nil {
			t.Fatal(err)
		}
		vmas, l := lw.AreaWalk(mm)
		if l.TreeNodes > 64 || len(vmas) > 64*31 {
			t.Fatalf("walk past its cap: %d nodes, %d areas", l.TreeNodes, len(vmas))
		}
		for i := 1; i < len(vmas); i++ {
			if vmas[i].Start < vmas[i-1].End {
				t.Fatalf("areas out of order: %+v", vmas)
			}
		}
	})
}

func read64(k *lt.Kernel, at uint64) uint64 {
	b, err := k.Mem.ReadAt(at, 8)
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(b)
}
