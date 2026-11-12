package autoload

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

const (
	testKernelVA = uint64(0xfffff80000400000)
	testStartAt  = uint64(0x11000)
)

// startImage is physical memory with one set of 4-level page tables, whose
// frames are taken from 2 MiB up so the pages below 1 MiB hold only what a
// test puts there.
type startImage struct {
	flatImage
	cr3, next uint64
}

func newStartImage() *startImage {
	m := &startImage{flatImage: flatImage{buf: make([]byte, 3<<20)}, next: 2 << 20}
	m.cr3 = m.frame()
	return m
}

func (m *startImage) frame() uint64 {
	f := m.next
	m.next += kernelPageSize
	return f
}

func (m *startImage) mapPage(va, pa uint64) {
	table := m.cr3
	for shift := 39; shift > 12; shift -= 9 {
		at := table + (va>>shift)&511*8
		entry := binary.LittleEndian.Uint64(m.buf[at:])
		if entry&ptePresent == 0 {
			entry = m.frame() | ptePresent
			binary.LittleEndian.PutUint64(m.buf[at:], entry)
		}
		table = entry & pteFramemask
	}
	binary.LittleEndian.PutUint64(m.buf[table+(va>>12)&511*8:], pa|ptePresent)
}

func (m *startImage) putImage(va uint64, pdb string, seed byte) {
	img := make([]byte, fixtureImageSpan)
	putKernelImage(img, 0, pdb, seed, 1, fixtureRecordRVA)
	for at := uint64(0); at < fixtureImageSpan; at += kernelPageSize {
		pa := m.frame()
		copy(m.buf[pa:], img[at:at+kernelPageSize])
		m.mapPage(va+at, pa)
	}
}

func (m *startImage) putStart(at, cr3, target uint64) {
	page := m.buf[at : at+kernelPageSize]
	page[0] = startJumpNear
	binary.LittleEndian.PutUint16(page[1:], 0x650-startJumpLength)
	binary.LittleEndian.PutUint32(page[4:], 1)
	binary.LittleEndian.PutUint64(page[startTargetAt:], target)
	binary.LittleEndian.PutUint64(page[startStateAt+stateCR3At:], cr3)
}

func kernelImage() *startImage {
	m := newStartImage()
	m.putImage(testKernelVA, "ntkrnlmp.pdb", 0x30)
	m.putStart(testStartAt, m.cr3, testKernelVA+0x1010)
	return m
}

func TestTheStartPageNamesTheRunningKernel(t *testing.T) {
	m := kernelImage()
	k, found, err := lowStubKernel(m, limits.DefaultMaxKernelImageBytes)
	if !found || err != nil {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if k.Base != testKernelVA || k.DTB != m.cr3 || k.Fingerprint.PDBName != "ntkrnlmp.pdb" || k.Fingerprint.Age != 1 {
		t.Fatalf("kernel %+v", k)
	}
	id, err := IdentifyKernel(m, limits.Limits{})
	if err != nil || id.Method != MethodLowStub || id.Base != testKernelVA {
		t.Fatalf("IdentifyKernel = %+v (%v)", id, err)
	}
}

func TestTheSearchStepsOverTheImageAfterTheKernelAndUnmappedPages(t *testing.T) {
	m := newStartImage()
	m.putImage(testKernelVA, "ntkrnlmp.pdb", 0x30)
	hal := testKernelVA + 0x10000
	m.putImage(hal, "hal.pdb", 0x50)
	m.putStart(testStartAt, m.cr3|0x18, hal+0x1234)
	k, found, err := lowStubKernel(m, limits.DefaultMaxKernelImageBytes)
	if !found || err != nil || k.Base != testKernelVA || k.DTB != m.cr3 {
		t.Fatalf("kernel %+v found=%v err=%v", k, found, err)
	}
}

func TestWithoutAStartPageIdentificationScans(t *testing.T) {
	m := newStartImage()
	putKernelImage(m.buf, 0x2c0000, "ntkrnlmp.pdb", 0x30, 1, fixtureRecordRVA)
	if _, found, err := lowStubKernel(m, limits.DefaultMaxKernelImageBytes); found || err != nil {
		t.Fatalf("found=%v err=%v in an image with no start page", found, err)
	}
	id, err := IdentifyKernel(m, limits.Limits{})
	if err != nil || id.Method != MethodScan {
		t.Fatalf("IdentifyKernel = %+v (%v)", id, err)
	}
}

func TestAStartPageThatLeadsNowhereIsReported(t *testing.T) {
	cases := map[string]func(m *startImage){
		"CR3 outside":     func(m *startImage) { m.putStart(testStartAt, 1<<40, testKernelVA+0x1010) },
		"user target":     func(m *startImage) { m.putStart(testStartAt, m.cr3, 0x7ff000001000) },
		"unmapped target": func(m *startImage) { m.putStart(testStartAt, m.cr3, testKernelVA+0x100000) },
		"no kernel below": func(m *startImage) {
			m.putStart(testStartAt, m.cr3, testKernelVA+0x1010)
			m.putImage(testKernelVA, "hal.pdb", 1)
		},
		"zero CR3": func(m *startImage) { m.putStart(testStartAt, 0, testKernelVA+0x1010) },
	}
	for name, setup := range cases {
		m := kernelImage()
		setup(m)
		if k, found, err := lowStubKernel(m, limits.DefaultMaxKernelImageBytes); !found || err == nil {
			t.Errorf("%s: found=%v kernel=%+v err=%v", name, found, k, err)
		}
	}
	m := kernelImage()
	m.putStart(testStartAt, 1<<40, testKernelVA+0x1010)
	putKernelImage(m.buf, 0x2c0000, "ntkrnlmp.pdb", 0x30, 1, fixtureRecordRVA)
	_, err := IdentifyKernel(m, limits.Limits{})
	if err != nil {
		t.Fatalf("the scan did not stand in for a start page that leads nowhere: %v", err)
	}
}

func TestOnlyAPageWithAJumpIntoItselfIsAStartPage(t *testing.T) {
	page := make([]byte, kernelPageSize)
	page[0] = startJumpNear
	for target, want := range map[int]bool{0x650: true, startFieldsEnd: true, startFieldsEnd - 1: false, 0x1000: false, -0x10: false} {
		binary.LittleEndian.PutUint16(page[1:], uint16(int16(target-startJumpLength)))
		if _, ok := startPageAt(page, 0); ok != want {
			t.Errorf("jump to %#x: start page %v, want %v", target, ok, want)
		}
	}
	page[0] = 0xeb
	if _, ok := startPageAt(page, 0); ok {
		t.Error("a short jump was taken for the start page")
	}
}

func TestStartPagesThatNameTwoKernelsAreRefused(t *testing.T) {
	m := kernelImage()
	m.putStart(testStartAt+kernelPageSize, m.cr3, testKernelVA+0x1010)
	if k, _, err := lowStubKernel(m, limits.DefaultMaxKernelImageBytes); err != nil || k == nil {
		t.Fatalf("two agreeing start pages: %v", err)
	}
	other := testKernelVA + 0x200000
	m.putImage(other, "ntkrnlmp.pdb", 0x70)
	m.putStart(testStartAt+2*kernelPageSize, m.cr3, other+0x1010)
	if _, found, err := lowStubKernel(m, limits.DefaultMaxKernelImageBytes); !found || !errors.Is(err, errStartsDisagree) {
		t.Fatalf("two kernels: found=%v err=%v", found, err)
	}
}

func TestTheSearchIsBoundedByMaxKernelImageBytes(t *testing.T) {
	m := newStartImage()
	m.putImage(testKernelVA, "ntkrnlmp.pdb", 0x30)
	far := testKernelVA + 0x400000
	m.mapPage(far, m.frame())
	m.putStart(testStartAt, m.cr3, far)
	if _, _, err := lowStubKernel(m, 0x100000); err == nil || !strings.Contains(err.Error(), "MaxKernelImageBytes (1048576)") {
		t.Fatalf("a kernel 4 MiB below with a 1 MiB span: %v", err)
	}
	if k, _, err := lowStubKernel(m, 0x400000); err != nil || k.Base != testKernelVA {
		t.Fatalf("with a 4 MiB span: %+v (%v)", k, err)
	}
}

func FuzzProcessorStartPage(f *testing.F) {
	m := kernelImage()
	f.Add(m.buf[testStartAt : testStartAt+0x100])
	f.Fuzz(func(t *testing.T, head []byte) {
		m := kernelImage()
		copy(m.buf[testStartAt:testStartAt+kernelPageSize], head)
		k, found, err := lowStubKernel(m, 1<<20)
		if err == nil && k != nil {
			if !found || !isKernelPDB(k.Fingerprint.PDBName) || k.Base%kernelPageSize != 0 || k.DTB%kernelPageSize != 0 {
				t.Fatalf("named %+v (found=%v)", k, found)
			}
		}
	})
}
