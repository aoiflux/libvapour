package autoload

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

func scanAll(t *testing.T, buf []byte) []KernelCandidate {
	t.Helper()
	found, err := scanKernelCandidates(&flatImage{buf: buf}, kernelScanStep, limits.DefaultMaxKernelImageBytes)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return found
}

func TestARecordIsDeclaredOnlyWhereItsImageHeaderPutsIt(t *testing.T) {
	buf := make([]byte, 0x10000)
	putKernelImage(buf, 0, "ntkrnlmp.pdb", 0x30, 3, fixtureRecordRVA)
	putKernelImage(buf, 0x8000, "ntkrnlmp.pdb", 0x50, 4, 0x2400)
	found := scanAll(t, buf)
	if len(found) != 2 {
		t.Fatalf("found %+v, want two records", found)
	}
	if c := found[0]; c.Offset != fixtureRecordRVA || c.ImageBase != 0 || !c.Corroborated || c.Fingerprint.Age != 3 {
		t.Errorf("declared record: %+v", c)
	}
	if c := found[1]; c.Offset != 0x8000+fixtureRecordRVA || c.ImageBase != 0x8000 || c.Corroborated {
		t.Errorf("record its header puts elsewhere: %+v", c)
	}
}

func TestOnlyTheNearestImageHeaderIsAsked(t *testing.T) {
	buf := make([]byte, 0x10000)
	putKernelImage(buf, 0, "ntkrnlmp.pdb", 0x30, 3, fixtureRecordRVA)
	putKernelImage(buf, 0x4000, "hal.pdb", 0x60, 1, fixtureRecordRVA)
	putRSDSNamed(buf, 0x7000, "ntkrnlmp.pdb", 0x30, 3)
	found := scanAll(t, buf)
	if len(found) != 2 || found[1].ImageBase != 0x4000 || found[1].Corroborated {
		t.Errorf("found %+v, want the record at 0x7000 inside hal's image and not declared", found)
	}
}

func TestOnlyKernelPDBNamesWithinMaxPathAreCandidates(t *testing.T) {
	buf := make([]byte, 0x2000)
	putRSDSNamed(buf, 0x100, `d:\build\amd64\ntoskrnl.pdb`, 1, 1)
	putRSDSNamed(buf, 0x300, "ntdll.pdb", 1, 1)
	copy(buf[0x500:], "RSDS")
	for i := 0x500 + rsdsNameAt; i < 0x500+rsdsNameAt+rsdsMaxPath; i++ {
		buf[i] = 'a'
	}
	copy(buf[0x500+rsdsNameAt+rsdsMaxPath-len("ntoskrnl.pdb"):], "ntoskrnl.pdb")
	found := scanAll(t, buf)
	if len(found) != 1 || found[0].Offset != 0x100 || found[0].Fingerprint.PDBName != "ntoskrnl.pdb" {
		t.Errorf("found %+v, want only the record at 0x100", found)
	}
}

func TestTheStepDoesNotChangeWhatTheScanFinds(t *testing.T) {
	buf := make([]byte, 0x6000)
	putKernelImage(buf, 0, "ntkrnlmp.pdb", 0x30, 1, fixtureRecordRVA)
	putRSDSNamed(buf, 0x3ffa, "ntoskrnl.pdb", 0x40, 2)
	whole := scanAll(t, buf)
	for _, step := range []uint64{0x10, 0x1000, 0x2008, 0x3ffd} {
		got, err := scanKernelCandidates(&flatImage{buf: buf}, step, limits.DefaultMaxKernelImageBytes)
		if err != nil || !reflect.DeepEqual(got, whole) {
			t.Errorf("step 0x%x: %+v (%v), want %+v", step, got, err, whole)
		}
	}
}

func TestTheWalkToAHeaderStopsAtMaxKernelImageBytes(t *testing.T) {
	buf := make([]byte, 0x30000)
	putKernelImage(buf, 0, "ntkrnlmp.pdb", 0x30, 1, 0x20000)
	putRSDSNamed(buf, 0x20000, "ntkrnlmp.pdb", 0x30, 1)
	near, _ := scanKernelCandidates(&flatImage{buf: buf}, kernelScanStep, 0x20000)
	far, _ := scanKernelCandidates(&flatImage{buf: buf}, kernelScanStep, 0x1f000)
	if len(near) != 2 || !near[1].Corroborated || len(far) != 2 || far[1].Corroborated || far[1].ImageBase != 0 {
		t.Errorf("span 0x20000: %+v; span 0x1f000: %+v", near, far)
	}
}

func TestAHoleInTheCaptureIsSteppedOver(t *testing.T) {
	const mib = 1 << 20
	backing := &flatImage{buf: make([]byte, 6*mib)}
	putKernelImage(backing.buf, 4*mib, "ntkrnlmp.pdb", 0x30, 7, fixtureRecordRVA)
	sparse, err := memory.NewSegmentedReader(backing, []memory.Segment{
		{PhysicalBase: 0, FileOffset: 0, Length: 5 * mib},
		{PhysicalBase: 8 * mib, FileOffset: 5 * mib, Length: mib},
	})
	if err != nil {
		t.Fatal(err)
	}
	fp, err := ScanKernel(sparse, limits.Limits{})
	if err != nil || fp.Age != 7 {
		t.Fatalf("ScanKernel = %+v (%v)", fp, err)
	}
	if _, err := ScanKernel(unreadableImage{size: 16 << 20}, limits.Limits{}); !errors.Is(err, errCaptureGone) {
		t.Errorf("unreadable capture: %v, want the read failure", err)
	}
}

func candidate(age uint32, at uint64, declared bool) KernelCandidate {
	return KernelCandidate{Fingerprint: Fingerprint{PDBName: "ntkrnlmp.pdb", GUID: strings.Repeat("AB", 16), Age: age}, Offset: at, Corroborated: declared}
}

func TestSelectionTakesOneBuildOrTheOneDeclared(t *testing.T) {
	for _, tc := range []struct {
		name        string
		in          []KernelCandidate
		age         uint32
		provisional bool
		err         error
	}{
		{"copies of one build", []KernelCandidate{candidate(1, 0x9000, false), candidate(1, 0x1000, false)}, 1, false, nil},
		{"one of two declared", []KernelCandidate{candidate(1, 0x1000, false), candidate(2, 0x9000, true)}, 2, true, nil},
		{"two declared", []KernelCandidate{candidate(1, 0x1000, true), candidate(2, 0x9000, true)}, 0, false, errKernelAmbiguous},
		{"none declared", []KernelCandidate{candidate(1, 0x1000, false), candidate(2, 0x9000, false)}, 0, false, errKernelUndeclared},
		{"nothing", nil, 0, false, errNoKernelRecord},
	} {
		fp, provisional, err := selectKernel(tc.in)
		switch {
		case tc.err != nil:
			if !errors.Is(err, tc.err) {
				t.Errorf("%s: %v, want %v", tc.name, err, tc.err)
			}
		case err != nil || fp.Age != tc.age || provisional != tc.provisional:
			t.Errorf("%s: %+v provisional %v (%v)", tc.name, fp, provisional, err)
		}
	}
	_, err := SelectKernel([]KernelCandidate{candidate(2, 0x9000, false), candidate(1, 0x1000, false), candidate(1, 0x5000, false)})
	if err == nil || !strings.Contains(err.Error(), "-1 at 0x1000, 2 copies; ntkrnlmp.pdb/"+strings.Repeat("AB", 16)+"-2 at 0x9000") {
		t.Errorf("the refusal does not list the builds in address order: %v", err)
	}
}

type crashImage struct {
	*startImage
	header memory.CrashDumpHeader
}

func (c crashImage) CrashHeader() memory.CrashDumpHeader { return c.header }

const (
	listHeadVA = testKernelVA + 0x800000
	entryVA    = testKernelVA + 0x801000
)

func dumpOf(kernelPDB string) crashImage {
	m := newStartImage()
	m.putImage(testKernelVA, kernelPDB, 0x30)
	head, entry := m.frame(), m.frame()
	m.mapPage(listHeadVA, head)
	m.mapPage(entryVA, entry)
	binary.LittleEndian.PutUint64(m.buf[head:], entryVA)
	binary.LittleEndian.PutUint64(m.buf[entry+loaderBaseAt:], testKernelVA)
	return crashImage{startImage: m, header: memory.CrashDumpHeader{DirectoryTableBase: m.cr3, PsLoadedModuleList: listHeadVA}}
}

func TestACrashDumpNamesTheKernelItsModuleListStartsWith(t *testing.T) {
	d := dumpOf("ntkrnlmp.pdb")
	id, err := IdentifyKernel(d, limits.Limits{})
	if err != nil || id.Method != MethodCrashDumpHeader || id.Base != testKernelVA || id.DTB != d.cr3 || id.Provisional {
		t.Fatalf("IdentifyKernel = %+v (%v)", id, err)
	}
	fp, isDump, err := KernelFromCrashDump(d)
	if !isDump || err != nil || fp.PDBName != "ntkrnlmp.pdb" {
		t.Errorf("KernelFromCrashDump = %+v %v %v", fp, isDump, err)
	}
	if fp, isDump, err := KernelFromCrashDump(&flatImage{buf: make([]byte, 0x1000)}); fp != nil || isDump || err != nil {
		t.Errorf("not a crash dump: %+v %v %v", fp, isDump, err)
	}
}

func TestACrashDumpHeaderThatLeadsNowhereIsSaidAndTheScanTakesOver(t *testing.T) {
	for name, change := range map[string]func(*crashImage){
		"no list head":     func(d *crashImage) { d.header.PsLoadedModuleList = 0 },
		"unmapped head":    func(d *crashImage) { d.header.PsLoadedModuleList = testKernelVA + 0x900000 },
		"empty list":       func(d *crashImage) { putPointer(d, listHeadVA, listHeadVA) },
		"not the kernel":   func(d *crashImage) { d.putImage(testKernelVA, "hal.pdb", 0x60) },
		"no image at base": func(d *crashImage) { putPointer(d, entryVA+loaderBaseAt, testKernelVA+0x1000) },
	} {
		d := dumpOf("ntkrnlmp.pdb")
		change(&d)
		if _, isDump, err := crashDumpKernel(d); !isDump || err == nil {
			t.Errorf("%s: isDump %v, err %v", name, isDump, err)
		}
		if id, err := IdentifyRunningKernel(d, limits.Limits{}); id != nil || err == nil || !strings.Contains(err.Error(), string(MethodCrashDumpHeader)) {
			t.Errorf("%s: IdentifyRunningKernel = %+v (%v)", name, id, err)
		}
		putKernelImage(d.buf, 0x2c0000, "ntkrnlmp.pdb", 0x30, 1, fixtureRecordRVA)
		if id, err := IdentifyKernel(d, limits.Limits{}); err != nil || id.Method != MethodScan {
			t.Errorf("%s: IdentifyKernel = %+v (%v)", name, id, err)
		}
	}
}

func putPointer(d *crashImage, va, value uint64) {
	v := &kernelVirtual{phys: d, dtb: d.cr3}
	pa, err := v.translate(va)
	if err != nil {
		panic(err)
	}
	binary.LittleEndian.PutUint64(d.buf[pa:], value)
}

func TestAnImageWithNeitherDirectPathIsNotIdentifiedRunning(t *testing.T) {
	buf := make([]byte, 0x200000)
	if id, err := IdentifyRunningKernel(&flatImage{buf: buf}, limits.Limits{}); id != nil || err != nil {
		t.Errorf("IdentifyRunningKernel = %+v (%v)", id, err)
	}
	if _, err := IdentifyKernel(&flatImage{buf: buf}, limits.Limits{}); !errors.Is(err, errNoKernelRecord) {
		t.Errorf("IdentifyKernel = %v, want %v", err, errNoKernelRecord)
	}
}

func TestAPDBPathIsCutAtEitherSeparator(t *testing.T) {
	for path, want := range map[string]string{
		`d:\os\obj\amd64fre\ntkrnlmp.pdb`: "ntkrnlmp.pdb",
		"/build/ntoskrnl.pdb":             "ntoskrnl.pdb",
		"ntkrpamp.pdb":                    "ntkrpamp.pdb",
		`dir\`:                            "",
	} {
		if got := pdbBaseName(path); got != want {
			t.Errorf("pdbBaseName(%q) = %q, want %q", path, got, want)
		}
	}
}

func FuzzKernelScanWindows(f *testing.F) {
	img := make([]byte, 0x4000)
	putKernelImage(img, 0, "ntkrnlmp.pdb", 0x30, 1, fixtureRecordRVA)
	putRSDSNamed(img, 0x3100, "ntoskrnl.pdb", 0x40, 2)
	f.Add(img, uint16(0x1000))
	f.Add(img, uint16(0x2010))
	f.Fuzz(func(t *testing.T, data []byte, step uint16) {
		r := &flatImage{buf: data}
		whole, wholeErr := scanKernelCandidates(r, uint64(len(data))+1, limits.DefaultMaxKernelImageBytes)
		windowed, err := scanKernelCandidates(r, 16+uint64(step)%0x2000, limits.DefaultMaxKernelImageBytes)
		if (err == nil) != (wholeErr == nil) || !reflect.DeepEqual(windowed, whole) {
			t.Fatalf("step 0x%x found %+v (%v); one window found %+v (%v)", 16+uint64(step)%0x2000, windowed, err, whole, wholeErr)
		}
		for _, c := range windowed {
			if !isKernelPDB(c.Fingerprint.PDBName) || string(data[c.Offset:c.Offset+4]) != "RSDS" || c.ImageBase > c.Offset {
				t.Fatalf("candidate %+v", c)
			}
		}
	})
}
