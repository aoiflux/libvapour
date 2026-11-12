package processhollowing

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

var known = map[Finding]bool{
	FindingImageBaseUnmapped: true, FindingImageBaseInsideRange: true, FindingImageBaseNotImage: true,
	FindingSectionBaseDiffers: true, FindingSectionBaseUnmapped: true, FindingControlAreaDiffers: true,
	FindingSectionObjectDiffers: true, FindingFileNameDiffers: true, FindingImageFileNameDiffers: true,
	FindingHeaderNotPE: true, FindingHeaderImageBaseDiffers: true, FindingImageSizeExceedsRange: true,
	FindingHeaderDiffersFromFile: true,
}

// Arbitrary bases, view bounds and header pages: the examiner never panics,
// gives only the findings of section 7, and gives each at most once.
func FuzzExamine(f *testing.F) {
	f.Add(imageBase, imageBase, uint64(0), headerPage(imageBase), headerPage(imageBase), "app.exe")
	f.Add(otherBase, imageBase, uint64(0x1000), make([]byte, 0x1000), headerPage(imageBase), "svchost.exe")
	f.Fuzz(func(t *testing.T, base, section, shrink uint64, mapped, file []byte, name string) {
		name = name[:min(len(name), 14)]
		mapped, file = mapped[:min(len(mapped), 0x1000)], file[:min(len(file), 0x1000)]
		p := consistent(1000)
		p.ImageBaseAddress, p.SectionBaseAddress, p.Name = base, section, name
		if shrink < imageSize {
			p.Views[1].End -= shrink &^ 0xfff
		}
		p.Views[1].File.Header = file
		p.UserMemory = map[uint64][]byte{base &^ 0xfff: mapped}
		img := testsupport.BuildS43Image([]testsupport.S43Process{p})
		e, err := newExaminer(img.Context())
		if err != nil {
			t.Fatal(err)
		}
		rows, _ := e.examine(listed(img, 1000))
		seen := map[Finding]bool{}
		for _, r := range rows {
			if !known[r.Finding] || seen[r.Finding] {
				t.Fatalf("finding %q in %+v", r.Finding, rows)
			}
			seen[r.Finding] = true
		}
	})
}
