package linuxwalk_test

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const (
	fuzzBytes = 0x2000
	fuzzCap   = 64
)

var fuzzLimits = limits.Limits{MaxListEntries: fuzzCap, MaxTableEntries: fuzzCap, MaxRecursionDepth: 16}

// fold keeps every pointer the fuzzer writes inside the mapped region, so
// the walk meets real loops and back links instead of failing on the first
// read.
func fold(v uint64) uint64 {
	if v == 0 || v >= base && v < base+fuzzBytes {
		return v
	}
	return base + v%fuzzBytes
}

func fuzzMemory(data []byte) *kerntest.Memory {
	mem := kerntest.NewMemory()
	mem.Map(base, fuzzBytes)
	mem.Write(base, data[:min(len(data), fuzzBytes)])
	return mem
}

func fuzzReader(t *testing.T, data []byte, ty *kerntest.Types) linuxwalk.Reader {
	r := reader(t, fuzzMemory(data), ty, fuzzLimits)
	r.Address = fold
	return r
}

func seedList() []byte {
	b := make([]byte, 0x200)
	at := func(off, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }
	at(0, base+0x48)
	at(8, base+0x88)
	at(0x48, base+0x88)
	at(0x50, base)
	at(0x88, base)
	at(0x90, base+0x48)
	return b
}

func checkList(t *testing.T, l linuxwalk.List) {
	if len(l.Entries) > fuzzCap {
		t.Fatalf("%d entries past the cap of %d", len(l.Entries), fuzzCap)
	}
	if l.End == linuxwalk.Closed && l.At != 0 {
		t.Fatalf("closed walk names %#x", l.At)
	}
}

func FuzzList(f *testing.F) {
	f.Add(seedList(), false)
	f.Add(make([]byte, 16), true)
	f.Fuzz(func(t *testing.T, data []byte, back bool) {
		ty := kerntest.NewTypes(8)
		listTypes(ty)
		dir := linuxwalk.Forward
		if back {
			dir = linuxwalk.Backward
		}
		l, err := fuzzReader(t, data, ty).List(base, "item", "link", dir)
		if err != nil {
			t.Fatal(err)
		}
		checkList(t, l)
	})
}

func FuzzHList(f *testing.F) {
	f.Add(seedList())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		ty := kerntest.NewTypes(8)
		listTypes(ty)
		l, err := fuzzReader(t, data, ty).HList(base, "item", "hnode")
		if err != nil {
			t.Fatal(err)
		}
		checkList(t, l)
	})
}

func FuzzTasks(f *testing.F) {
	f.Add(seedList(), true, uint8(viaSignal))
	f.Add(make([]byte, taskSize), false, uint8(viaGroup))
	f.Fuzz(func(t *testing.T, data []byte, threads bool, l uint8) {
		ty := kerntest.NewTypes(8)
		listTypes(ty)
		taskTypes(ty, layout(l%2))
		ty.Symbol("init_task", base, kerntest.Struct("task_struct"))
		w, err := fuzzReader(t, data, ty).Tasks(threads, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range w.Walks {
			checkList(t, l)
		}
		seen := map[uint64]bool{}
		for _, at := range w.Tasks {
			if at == base || seen[at] {
				t.Fatalf("task %#x listed twice or is init_task", at)
			}
			seen[at] = true
		}
	})
}

func FuzzTree(f *testing.F) {
	seed := make([]byte, 0x400)
	binary.LittleEndian.PutUint64(seed[8:], (base+0x100)|2)
	seed[0x100] = 4
	binary.LittleEndian.PutUint64(seed[0x100+nodeSlots:], (base+0x200)|2)
	binary.LittleEndian.PutUint64(seed[0x100+nodeSlots+8:], base+0x300)
	f.Add(seed, true)
	f.Add(seed, false)
	f.Fuzz(func(t *testing.T, data []byte, xarray bool) {
		ty := kerntest.NewTypes(8)
		treeTypes(ty, xarray, 16)
		root := "radix_tree_root"
		if xarray {
			root = "xarray"
		}
		tr, err := fuzzReader(t, data, ty).Tree(base, root)
		if err != nil {
			t.Fatal(err)
		}
		if len(tr.Entries) > fuzzCap || len(tr.Indexes) != len(tr.Entries) {
			t.Fatalf("%d entries, %d indexes", len(tr.Entries), len(tr.Indexes))
		}
	})
}
