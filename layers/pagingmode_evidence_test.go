package layers

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

type evidenceImage struct {
	buf   []byte
	holes map[uint64]bool
	reads int
}

func (m *evidenceImage) ReadAt(offset, size uint64) ([]byte, error) {
	m.reads++
	if m.holes[offset] {
		return nil, errors.New("hole")
	}
	if offset > uint64(len(m.buf)) || size > uint64(len(m.buf))-offset {
		return nil, errors.New("out of range")
	}
	return m.buf[offset : offset+size], nil
}

func (m *evidenceImage) Size() uint64 { return uint64(len(m.buf)) }

func newEvidenceImage(size int) *evidenceImage {
	return &evidenceImage{buf: make([]byte, size), holes: map[uint64]bool{}}
}

func (m *evidenceImage) put8(table, index, value uint64) {
	binary.LittleEndian.PutUint64(m.buf[table+8*index:], value)
}

func (m *evidenceImage) put4(table, index uint64, value uint32) {
	binary.LittleEndian.PutUint32(m.buf[table+4*index:], value)
}

const (
	evP   = uint64(1)
	evRW  = uint64(1) << 1
	evPS  = uint64(1) << 7
	page2 = uint64(0x1200000)
)

func fourLevelImage() *evidenceImage {
	m := newEvidenceImage(0x10000)
	m.put8(0x1000, 511, 0x2000|evP|evRW)
	m.put8(0x2000, 510, 0x3000|evP|evRW)
	m.put8(0x3000, 8, page2|evPS|evP|evRW)
	m.put8(0x3000, 9, 0x4000|evP|evRW)
	return m
}

func fiveLevelImage() *evidenceImage {
	m := newEvidenceImage(0x10000)
	m.put8(0x1000, 511, 0x2000|evP|evRW)
	m.put8(0x2000, 511, 0x3000|evP|evRW)
	m.put8(0x3000, 510, 0x4000|evP|evRW)
	m.put8(0x4000, 8, page2|evPS|evP|evRW)
	return m
}

func decideOK(t *testing.T, m *evidenceImage, root uint64, width int, want PagingMode) PagingModeDecision {
	t.Helper()
	d, err := DetectPagingMode(m, root, width)
	if err != nil {
		t.Fatalf("DetectPagingMode: %v", err)
	}
	if d.Mode.Name() != want.Name() {
		t.Fatalf("mode %s, want %s; evidence: %s", d.Mode.Name(), want.Name(), d.Evidence)
	}
	return d
}

func TestAFourLevelTableWithA2MBPageRefutesTheFiveLevelReading(t *testing.T) {
	d := decideOK(t, fourLevelImage(), 0x1000, 8, ModeX64)
	if !strings.Contains(d.Evidence, "5-level reading refuted") || !strings.Contains(d.Evidence, "5-16") {
		t.Errorf("evidence %q does not cite the 1-GByte PDPTE reserved bits", d.Evidence)
	}
}

func TestAFiveLevelTableWithALargePageIsFiveLevel(t *testing.T) {
	decideOK(t, fiveLevelImage(), 0x1000, 8, ModeLA57)
}

func TestCR3FlagBitsAreMaskedOff(t *testing.T) {
	decideOK(t, fourLevelImage(), 0x1000|0x18|0x3, 8, ModeX64)
}

func TestReservedCR3BitsRefuteBothWideReadings(t *testing.T) {
	_, err := DetectPagingMode(fourLevelImage(), 0x1000|1<<55, 8)
	if err == nil || !strings.Contains(err.Error(), "undecided") {
		t.Fatalf("err %v, want undecided", err)
	}
}

func TestAReservedBitAtTheRootRefutes(t *testing.T) {
	m := fourLevelImage()
	m.put8(0x1000, 300, 0x5000|evPS|evP)
	_, err := DetectPagingMode(m, 0x1000, 8)
	if err == nil || !strings.Contains(err.Error(), "PML4E 300") {
		t.Fatalf("err %v, want the PML4E 300 refutation", err)
	}
}

func TestARootWithNoUpperHalfEntryRefutes(t *testing.T) {
	m := newEvidenceImage(0x10000)
	m.put8(0x1000, 0, 0x2000|evP|evRW)
	_, err := DetectPagingMode(m, 0x1000, 8)
	if err == nil || !strings.Contains(err.Error(), "upper half") {
		t.Fatalf("err %v, want an upper-half refutation", err)
	}
}

func TestAReferencePastTheImageRefutes(t *testing.T) {
	m := fourLevelImage()
	m.put8(0x2000, 4, 0x7fff000|evP)
	_, err := DetectPagingMode(m, 0x1000, 8)
	if err == nil || !strings.Contains(err.Error(), "past the image's end") {
		t.Fatalf("err %v, want a past-the-end refutation", err)
	}
}

func TestAnUnreadableLowerTableIsEvidenceOfNothing(t *testing.T) {
	m := fourLevelImage()
	m.put8(0x1000, 300, 0x5000|evP|evRW)
	m.holes[0x5000] = true
	d := decideOK(t, m, 0x1000, 8, ModeX64)
	if !strings.Contains(d.Evidence, "1 tables unreadable") {
		t.Errorf("evidence %q does not count the unreadable table", d.Evidence)
	}
}

func TestASelfReferencingRootTerminates(t *testing.T) {
	m := fourLevelImage()
	m.put8(0x1000, 493, 0x1000|evP|evRW)
	decideOK(t, m, 0x1000, 8, ModeX64)
	if m.reads > 2*(1+evidenceBudget) {
		t.Errorf("%d reads", m.reads)
	}
}

func TestWithoutALargePageTheWideReadingsAreUndecided(t *testing.T) {
	m := newEvidenceImage(0x10000)
	m.put8(0x1000, 511, 0x2000|evP|evRW)
	m.put8(0x2000, 0, 0x3000|evP|evRW)
	if _, err := DetectPagingMode(m, 0x1000, 8); err == nil || !strings.Contains(err.Error(), "undecided") {
		t.Fatalf("err %v, want undecided", err)
	}
}

func paeImage() *evidenceImage {
	m := newEvidenceImage(0x10000)
	m.put8(0x1020, 3, 0x2000|evP)
	m.put8(0x2000, 0, 0x200000|evPS|evP|evRW)
	m.put8(0x2000, 1, 0x3000|evP|evRW)
	return m
}

func TestAPAETableIsPAE(t *testing.T) {
	decideOK(t, paeImage(), 0x1020, 4, ModeX86PAE)
}

func TestAPAEReservedPDPTEBitRefutes(t *testing.T) {
	m := paeImage()
	m.put8(0x1020, 3, 0x2000|evP|evRW)
	_, err := DetectPagingMode(m, 0x1020, 4)
	if err == nil || !strings.Contains(err.Error(), "5-8") {
		t.Fatalf("err %v, want the PDPTE reserved-bit refutation", err)
	}
}

func TestALowerPDPTEIsNoEvidenceSinceAMDLoadsItOnlyWhenUsed(t *testing.T) {
	m := paeImage()
	m.put8(0x1020, 0, 0x5000|evP|evRW|1<<60)
	decideOK(t, m, 0x1020, 4, ModeX86PAE)
}

func TestARootAbove4GBytesIsNeitherPAENor32Bit(t *testing.T) {
	_, err := DetectPagingMode(paeImage(), 1<<32|0x1020, 4)
	if err == nil || !strings.Contains(err.Error(), "4 GBytes") {
		t.Fatalf("err %v, want a 4-GByte refutation", err)
	}
}

func thirtyTwoBitImage() *evidenceImage {
	m := newEvidenceImage(0x10000)
	m.put4(0x1000, 768, uint32(0x2000|evP|evRW))
	m.put4(0x1000, 769, uint32(0x400000|evPS|evP|evRW))
	return m
}

func TestA32BitTableIs32Bit(t *testing.T) {
	decideOK(t, thirtyTwoBitImage(), 0x1000, 4, ModeX86NonPAE)
}

func TestA32BitDirectoryWithWritableLowPDEsRefutesPAE(t *testing.T) {
	m := thirtyTwoBitImage()
	m.put4(0x1000, 4, uint32(0x5000|evP|evRW))
	d := decideOK(t, m, 0x1000, 4, ModeX86NonPAE)
	if !strings.Contains(d.Evidence, "PAE reading refuted") {
		t.Errorf("evidence %q", d.Evidence)
	}
}

func TestA4MBPageWithBit21Refutes32Bit(t *testing.T) {
	m := thirtyTwoBitImage()
	m.put4(0x1000, 769, uint32(0x400000|1<<21|evPS|evP))
	if _, err := DetectPagingMode(m, 0x1000, 4); err == nil || !strings.Contains(err.Error(), "5-4") {
		t.Fatalf("err %v, want the 4-MByte PDE refutation", err)
	}
}

func TestAnUnreadableRootIsAnError(t *testing.T) {
	m := fourLevelImage()
	m.holes[0x1000] = true
	if _, err := DetectPagingMode(m, 0x1000, 8); err == nil || !strings.Contains(err.Error(), "read root") {
		t.Fatalf("err %v", err)
	}
}

func TestAWidthOtherThan4Or8IsAnError(t *testing.T) {
	if _, err := DetectPagingMode(fourLevelImage(), 0x1000, 2); err == nil || !strings.Contains(err.Error(), "pointer width 2") {
		t.Fatalf("err %v", err)
	}
}

func FuzzDetectPagingMode(f *testing.F) {
	f.Add(fourLevelImage().buf, uint64(0x1000), uint8(8))
	f.Add(fiveLevelImage().buf, uint64(0x1000), uint8(8))
	f.Add(paeImage().buf, uint64(0x1020), uint8(4))
	f.Add(thirtyTwoBitImage().buf, uint64(0x1000), uint8(4))
	f.Fuzz(func(t *testing.T, data []byte, root uint64, width uint8) {
		m := &evidenceImage{buf: data, holes: map[uint64]bool{}}
		d, err := DetectPagingMode(m, root, int(width))
		if m.reads > 2*(1+evidenceBudget) {
			t.Fatalf("%d reads, over the budget", m.reads)
		}
		if err != nil {
			return
		}
		switch d.Mode.Name() {
		case ModeX64.Name(), ModeLA57.Name():
			if width != 8 {
				t.Fatalf("width %d decided %s", width, d.Mode.Name())
			}
		case ModeX86PAE.Name(), ModeX86NonPAE.Name():
			if width != 4 {
				t.Fatalf("width %d decided %s", width, d.Mode.Name())
			}
		default:
			t.Fatalf("mode %q is not a preset", d.Mode.Name())
		}
	})
}
