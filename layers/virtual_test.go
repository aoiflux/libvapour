package layers

import (
	"bytes"
	"errors"
	"runtime"
	"testing"

	"github.com/aoiflux/libvapour/memory"
)

func TestAReadCrossesPagesThatAreApartInPhysicalMemory(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva, 0x90000)
	pt.page(kva+0x1000, 0x80000)
	copy(img.buf[0x90ffe:], "ab")
	copy(img.buf[0x80000:], "cd")
	v := NewVirtualMemoryLayer(img, pt.translator())
	got, err := v.ReadAt(kva+0xffe, 4)
	if err != nil || string(got) != "abcd" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := v.ReadAt(kva, 0); err != nil || len(got) != 0 {
		t.Fatalf("empty read: %q, %v", got, err)
	}
	if v.Size() != img.Size() {
		t.Fatal("size is not the physical layer's")
	}
}

func TestAReadPastTheTopOfTheSpaceFails(t *testing.T) {
	v := NewVirtualMemoryLayer(newPhys(0x1000), DirectTranslator{})
	if _, err := v.ReadAt(^uint64(0)-1, 4); !errors.Is(err, memory.ErrOutOfBounds) {
		t.Fatalf("got %v", err)
	}
	if _, err := v.ReadAt(0, ^uint64(0)); !errors.Is(err, memory.ErrSizeOverflow) {
		t.Fatalf("got %v", err)
	}
}

func TestAHugeReadThatFailsAllocatesLittle(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	v := NewVirtualMemoryLayer(img, pt.translator())
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := v.ReadAt(kva, 1<<40)
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; err == nil || grew > 4*MaxReadPrealloc {
		t.Fatalf("err %v, %d bytes allocated", err, grew)
	}
}

func TestAPagedOutPageReadsFromItsPagefile(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.set(3, kva, 0x0000000300000000|2<<1|4<<5)
	v := NewVirtualMemoryLayer(img, pt.translator())
	if _, err := v.ReadAt(kva+8, 4); !errors.Is(err, ErrPageInPagefile) {
		t.Fatalf("without pagefiles: %v", err)
	}
	file := newPhys(0x10000)
	copy(file.buf[0x3008:], "swap")
	v.SetPagefiles(map[int]memory.MemoryReader{2: file})
	if got, err := v.ReadAt(kva+8, 4); err != nil || string(got) != "swap" {
		t.Fatalf("with the pagefile: %q, %v", got, err)
	}
	v.SetPagefiles(map[int]memory.MemoryReader{1: file})
	if _, err := v.ReadAt(kva+8, 4); !errors.Is(err, ErrPageInPagefile) {
		t.Fatalf("with another pagefile: %v", err)
	}
}

func TestDirtyIsReadOnlyFromAPresentEntry(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.set(3, kva, 0x80000|fP|fD)
	pt.set(3, kva+0x1000, 0x81000|fP)
	pt.set(3, kva+0x2000, 0x82000|fTr|fD)
	v := NewVirtualMemoryLayer(img, pt.translator())
	for _, c := range []struct {
		va    uint64
		dirty bool
	}{{kva + 0x10, true}, {kva + 0x1fff, false}, {kva + 0x2000, false}} {
		if got, err := v.IsDirty(c.va); err != nil || got != c.dirty {
			t.Errorf("0x%x: %v, %v", c.va, got, err)
		}
	}
	if e, err := v.LeafEntry(kva + 0x123); err != nil || e != 0x80000|fP|fD {
		t.Fatalf("LeafEntry: 0x%x, %v", e, err)
	}
	direct := NewVirtualMemoryLayer(img, DirectTranslator{})
	if _, err := direct.IsDirty(0); err == nil {
		t.Fatal("a translator without entries answered")
	}
}

func TestAProcessLayerCachesOnlyOverASnapshot(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(0x10000, 0x80000)
	copy(img.buf[0x80000:], "user")
	live := NewProcessLayer(img, 0x1000, 16)
	if live.translator.(*IntelTranslator).cache != nil {
		t.Fatal("a live reader got a cache")
	}
	img.immutable = true
	snap := NewProcessLayer(img, 0x1000, 16)
	if c := snap.translator.(*IntelTranslator).cache; c == nil || cap(c.slots) != 16 {
		t.Fatal("a snapshot got no cache of the asked size")
	}
	if got, err := snap.ReadAt(0x10000, 4); err != nil || !bytes.Equal(got, []byte("user")) {
		t.Fatalf("got %q, %v", got, err)
	}
}
