package testsupport

import (
	"bytes"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
)

const testUserVA = uint64(0x00007ff600001000)

func virtualOf(pm *PagedMemory, dtb uint64) memory.MemoryReader {
	return layers.NewVirtualMemoryLayer(pm, &layers.IntelTranslator{Physical: pm, CR3: dtb})
}

func TestVirtualReadGoesThroughThePageTables(t *testing.T) {
	pm := NewPagedMemory(1 << 20)
	as := pm.NewAddressSpace()
	data := []byte("mapped through four levels")
	pa := as.MapData(testUserVA, data)
	if pa == testUserVA {
		t.Fatal("frame equals the virtual address")
	}
	if _, err := pm.ReadAt(testUserVA, uint64(len(data))); !errors.Is(err, memory.ErrOutOfBounds) {
		t.Fatalf("physical read at the virtual address: %v", err)
	}
	got, err := virtualOf(pm, as.DTB).ReadAt(testUserVA, uint64(len(data)))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("virtual read %q, %v", got, err)
	}
}

func TestEachSpaceResolvesItsOwnPages(t *testing.T) {
	pm := NewPagedMemory(1 << 20)
	a, b, c := pm.NewAddressSpace(), pm.NewAddressSpace(), pm.NewAddressSpace()
	a.MapData(testUserVA, []byte("first"))
	b.MapData(testUserVA, []byte("other"))
	for _, s := range []struct {
		as   *AddressSpace
		want string
	}{{a, "first"}, {b, "other"}} {
		got, err := virtualOf(pm, s.as.DTB).ReadAt(testUserVA, 5)
		if err != nil || string(got) != s.want {
			t.Fatalf("read %q, %v, want %q", got, err, s.want)
		}
	}
	if _, err := virtualOf(pm, c.DTB).ReadAt(testUserVA, 5); err == nil {
		t.Fatal("a space that never mapped the page reads it")
	}
}

func TestEntriesFollowTheFourLevelFormat(t *testing.T) {
	pm := NewPagedMemory(1 << 20)
	as := pm.NewAddressSpace()
	va := uint64(0xfffff80012345000)
	pa := as.MapPageFlags(va, PTEDirty)
	table := as.DTB
	for _, shift := range []uint{39, 30, 21} {
		e := pm.readU64(table + (va>>shift&0x1ff)*8)
		if e&0xfff != ptePresent {
			t.Fatalf("table entry at shift %d has flags 0x%x, want present only", shift, e&0xfff)
		}
		table = e & pteAddrMask
	}
	leaf := pm.readU64(table + (va>>12&0x1ff)*8)
	if leaf != pa|ptePresent|PTEDirty {
		t.Fatalf("leaf 0x%x, want 0x%x", leaf, pa|ptePresent|PTEDirty)
	}
}

func TestPhysicalBounds(t *testing.T) {
	pm := NewPagedMemory(0)
	if pm.Size() != 4*pageSize {
		t.Fatalf("size 0x%x, want four pages", pm.Size())
	}
	if first := pm.AllocPage(); first == 0 {
		t.Fatal("frame 0 handed out")
	}
	if b, err := pm.ReadAt(pm.Size(), 0); err != nil || len(b) != 0 {
		t.Fatalf("empty read at the end: %v", err)
	}
	if _, err := pm.ReadAt(pm.Size()-4, 8); !errors.Is(err, memory.ErrOutOfBounds) {
		t.Fatalf("read across the end: %v", err)
	}
	pm.AllocPage()
	pm.AllocPage()
	defer func() {
		if recover() == nil {
			t.Fatal("allocation past the end did not panic")
		}
	}()
	pm.AllocPage()
}

func TestMapImageCountsPages(t *testing.T) {
	pm := NewPagedMemory(1 << 20)
	as := pm.NewAddressSpace()
	image := bytes.Repeat([]byte{0xAB}, int(pageSize)+1)
	if n := as.MapImage(0x10000, image); n != 2 {
		t.Fatalf("%d pages, want 2", n)
	}
	got, err := virtualOf(pm, as.DTB).ReadAt(0x10000+pageSize, 2)
	if err != nil || !bytes.Equal(got, []byte{0xAB, 0}) {
		t.Fatalf("tail page %x, %v", got, err)
	}
}
