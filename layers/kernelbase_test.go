package layers

import (
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
)

const (
	tBase    = uint64(0xfffff80000231000)
	tHeadRVA = uint64(0x5010)
)

func headTable(rva uint64) *symbols.Table {
	t := processTable()
	t.AddSymbol(symbols.Symbol{Name: "PsActiveProcessHead", Address: rva})
	return t
}

// kernelImage maps an image at tBase whose three header pages come from
// physical 0x80000, and a list page at kva.
func kernelImage(pdb string) (*physImage, *pageTables) {
	img := newPhys(0x400000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	writeImage(img.buf, 0x80000, pdb, peMagic64)
	for i := range uint64(6) {
		pt.page(tBase+i*0x1000, 0x80000+i*0x1000)
	}
	pt.page(kva, 0x90000)
	return img, pt
}

func TestTheListHeadGivesTheBase(t *testing.T) {
	img, _ := kernelImage("ntkrnlmp.pdb")
	base, err := FindKernelBaseFromListHead(img, 0x1000, headTable(tHeadRVA), tBase+tHeadRVA)
	if err != nil || base != tBase {
		t.Fatalf("0x%x, %v", base, err)
	}
	for name, c := range map[string]struct {
		rva, head uint64
	}{
		"no head":            {tHeadRVA, 0},
		"not image-relative": {tBase, tBase + tHeadRVA},
		"below the kernel":   {tHeadRVA, 0x5010},
		"no image":           {tHeadRVA + 0x1000, tBase + tHeadRVA},
	} {
		if _, err := FindKernelBaseFromListHead(img, 0x1000, headTable(c.rva), c.head); err == nil {
			t.Errorf("%s: found a base", name)
		}
	}
}

func TestTheProcessListLeadsToTheHead(t *testing.T) {
	img, _ := kernelImage("ntkrnlmp.pdb")
	img.put8(0x90000, kva+0x100)
	img.put8(0x90100, tBase+tHeadRVA)
	base, err := FindKernelBaseByProcessListAnchor(img, 0x1000, headTable(tHeadRVA), kva, 8)
	if err != nil || base != tBase {
		t.Fatalf("0x%x, %v", base, err)
	}
	if _, err := FindKernelBaseByProcessListAnchor(img, 0x1000, headTable(tHeadRVA), kva, 1); err == nil {
		t.Fatal("found the head past the entry limit")
	}
	img.put8(0x90100, kva)
	if _, err := FindKernelBaseByProcessListAnchor(img, 0x1000, headTable(tHeadRVA), kva, 8); err == nil ||
		!strings.Contains(err.Error(), "returns to its start") {
		t.Fatalf("a closed list: %v", err)
	}
	if _, err := FindKernelBaseByProcessListAnchor(img, 0x1000, headTable(tHeadRVA), 0, 8); err == nil {
		t.Fatal("no anchor walked")
	}
}

func TestTheDebuggerDataBlockGivesTheBase(t *testing.T) {
	img := newPhys(0x200000)
	block := uint64(0x123450)
	copy(img.buf[block+0x10:], "KDBG")
	img.put4(block+0x14, 0x368)
	img.put8(block+0x18, tBase)
	copy(img.buf[0x20010:], "KDBG")
	img.put4(0x20014, 0x368)
	img.put8(0x20018, tBase+0x10)
	base, err := FindKernelBaseFromKDBG(img)
	if err != nil || base != tBase {
		t.Fatalf("0x%x, %v", base, err)
	}
	if _, err := FindKernelBaseFromKDBG(newPhys(0x10000)); err == nil {
		t.Fatal("found a block in zeros")
	}
}

func TestTheImageScanFindsTheNamedImage(t *testing.T) {
	img, pt := kernelImage("ntkrnlmp.pdb")
	writeImage(img.buf, 0xa0000, `x:\hal.pdb`, peMagic64)
	for i := range uint64(3) {
		pt.page(0xfffff80000100000+i*0x1000, 0xa0000+i*0x1000)
	}
	writeImage(img.buf, 0xb0000, "ntkrnlmp.pdb", peMagic64)
	for i := range uint64(3) {
		pt.page(0x10000+i*0x1000, 0xb0000+i*0x1000)
	}
	base, err := FindKernelImageBase(img, 0x1000, "NTKRNLMP.PDB")
	if err != nil || base != tBase {
		t.Fatalf("0x%x, %v", base, err)
	}
	if _, err := FindKernelImageBase(img, 0x1000, "ntkrla57.pdb"); err == nil {
		t.Fatal("found an image nothing names")
	}
	if _, err := FindKernelImageBase(img, 0x1000, ""); err == nil {
		t.Fatal("scanned for no name")
	}
}
