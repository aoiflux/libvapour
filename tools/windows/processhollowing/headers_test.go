package processhollowing

import (
	"encoding/binary"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/pe"
)

func TestEqualHeadersHaveNoDifferences(t *testing.T) {
	page := headerPage(imageBase)
	got, err := headerDifferences(page, page[:0x400])
	if err != nil || got != nil {
		t.Errorf("%v %v", got, err)
	}
}

func TestBytesPastTheSectionTableAreNotCompared(t *testing.T) {
	mapped, file := headerPage(imageBase), headerPage(imageBase)
	h, _ := pe.ParseHeaders(mapped)
	mapped[h.HeaderSpan()] = 0x41
	if got, err := headerDifferences(mapped, file); err != nil || got != nil {
		t.Errorf("%v %v", got, err)
	}
}

func TestEachDifferingFieldIsNamed(t *testing.T) {
	mapped, file := headerPage(otherBase), headerPage(imageBase)
	nt := uint64(testsupport.MappedPELfanew)
	binary.LittleEndian.PutUint32(mapped[nt+4+20+56:], 0x8000)
	got, err := headerDifferences(mapped, file)
	want := []string{"ImageBase 0x7ff720000000, section 0x7ff710000000", "SizeOfImage 0x8000, section 0x4000"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("got %q, %v; want %q", got, err, want)
	}
}

func TestADifferingSectionHeaderIsNamed(t *testing.T) {
	mapped, file := headerPage(imageBase), headerPage(imageBase)
	h, _ := pe.ParseHeaders(mapped)
	mapped[h.Sections[1].HeaderOffset] = 'X'
	got, err := headerDifferences(mapped, file)
	if err != nil || !slices.Equal(got, []string{"section header 1"}) {
		t.Errorf("%q %v", got, err)
	}
}

func TestOtherDifferingBytesAreReported(t *testing.T) {
	mapped, file := headerPage(imageBase), headerPage(imageBase)
	mapped[0x40] = 0x99
	got, err := headerDifferences(mapped, file)
	if err != nil || !slices.Equal(got, []string{"other bytes below 0x1d8"}) {
		t.Errorf("%q %v", got, err)
	}
}

func TestASectionPageThatIsNotPEIsAnError(t *testing.T) {
	if _, err := headerDifferences(headerPage(imageBase), make([]byte, 0x400)); err == nil {
		t.Error("a zero section page compared")
	}
}

func FuzzHeaderDifferences(f *testing.F) {
	f.Add(headerPage(imageBase), headerPage(otherBase))
	f.Add(headerPage(imageBase), []byte{})
	f.Add([]byte("MZ"), headerPage(imageBase))
	f.Fuzz(func(t *testing.T, mapped, file []byte) {
		got, err := headerDifferences(mapped, file)
		if err == nil && got != nil && len(got) == 0 {
			t.Fatal("an empty difference list")
		}
		if self, err := headerDifferences(mapped, mapped); err == nil && self != nil {
			t.Fatalf("a header differs from itself: %q", self)
		}
	})
}
