package processhollowing

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

const (
	imageBase  = uint64(0x7ff7_1000_0000)
	otherBase  = uint64(0x7ff7_2000_0000)
	imageSize  = uint64(testsupport.MappedPESize)
	viewFile   = `\Windows\System32\app.exe`
	auditFile  = `\Device\HarddiskVolume2\Windows\System32\app.exe`
	execWCopy  = 7
	readWrite  = 4
	execRWrite = 6
)

func headerPage(base uint64) []byte { return testsupport.BuildMappedPE(base)[:0x1000] }

// A process whose image the kernel and the process agree on, as every
// examined process on the measured captures does (S43 M1 to M9).
func consistent(pid uint64) testsupport.S43Process {
	return testsupport.S43Process{
		PID: pid, Name: "app.exe", ImageBaseAddress: imageBase, SectionBaseAddress: imageBase,
		Views: []testsupport.S43View{
			{Start: 0x10000, End: 0x1ffff, Private: true, Protection: readWrite},
			{Start: imageBase, End: imageBase + imageSize - 1, VadType: testsupport.S43ImageVadType, Protection: execWCopy,
				File: &testsupport.S43File{Name: viewFile, Header: headerPage(imageBase)}},
		},
		FilePointerView: 1,
		AuditName:       auditFile,
		UserMemory:      map[uint64][]byte{imageBase: headerPage(imageBase)},
	}
}

func listed(img *testsupport.S43Image, pid uint64) processlist.Process {
	p := img.Process(pid)
	return processlist.Process{PID: p.PID, Name: p.Name, EPROCESS: p.EPROCESS, DirectoryTableBase: p.DirectoryTableBase}
}

func examineOne(t *testing.T, p testsupport.S43Process) ([]Row, *skip, *testsupport.S43Image) {
	t.Helper()
	img := testsupport.BuildS43Image([]testsupport.S43Process{p})
	e, err := newExaminer(img.Context())
	if err != nil {
		t.Fatalf("newExaminer: %v", err)
	}
	rows, s := e.examine(listed(img, p.PID))
	e.report()
	return rows, s, img
}

func findings(rows []Row) []Finding {
	out := make([]Finding, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Finding)
	}
	return out
}

func TestAConsistentProcessHasNoFindings(t *testing.T) {
	rows, s, img := examineOne(t, consistent(1000))
	if s != nil || len(rows) != 0 {
		t.Fatalf("rows %v, skip %v; diagnostics %q", rows, s, img.Diagnostics)
	}
	if !slices.ContainsFunc(img.Diagnostics, func(d string) bool { return strings.Contains(d, "1 section header pages compared") }) {
		t.Errorf("diagnostics %q do not count the compared section header page", img.Diagnostics)
	}
}

func TestEachRuleFindsItsOwnDisagreement(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testsupport.S43Process)
		want   []Finding
	}{
		{"no view holds the image base", func(p *testsupport.S43Process) {
			p.Views = p.Views[:1]
			p.FilePointerView = -1
		}, []Finding{FindingImageBaseUnmapped}},
		{"the image base is inside the view", func(p *testsupport.S43Process) {
			p.ImageBaseAddress = imageBase + 0x1000
			p.UserMemory = nil
		}, []Finding{FindingImageBaseInsideRange, FindingSectionBaseDiffers}},
		{"private memory at the image base", func(p *testsupport.S43Process) {
			p.Views[1] = testsupport.S43View{Start: imageBase, End: imageBase + imageSize - 1, Private: true, Protection: execRWrite}
			p.FilePointerView = -1
		}, []Finding{FindingImageBaseNotImage}},
		{"a data view at the image base", func(p *testsupport.S43Process) {
			p.Views[1].VadType = 0
			p.Views[1].File.NotImage = true
		}, []Finding{FindingImageBaseNotImage}},
		{"the image moved to private memory and the section view is gone", func(p *testsupport.S43Process) {
			p.ImageBaseAddress = otherBase
			p.Views[1] = testsupport.S43View{Start: otherBase, End: otherBase + imageSize - 1, Private: true, Protection: execRWrite}
			p.FilePointerView = -1
			p.UserMemory = map[uint64][]byte{otherBase: headerPage(otherBase)}
		}, []Finding{FindingImageBaseNotImage, FindingSectionBaseDiffers, FindingSectionBaseUnmapped}},
		{"ImageFilePointer opens another image section", func(p *testsupport.S43Process) {
			p.FilePointerImageSection = 0xffff_f800_dead_0000
		}, []Finding{FindingControlAreaDiffers}},
		{"SectionObject holds another control area", func(p *testsupport.S43Process) {
			p.SectionObjectCA = 0xffff_f800_beef_0000
		}, []Finding{FindingSectionObjectDiffers}},
		{"the view maps another file", func(p *testsupport.S43Process) {
			p.Views[1].File.Name = `\Users\x\other.exe`
		}, []Finding{FindingFileNameDiffers}},
		{"ImageFileName names another file", func(p *testsupport.S43Process) {
			p.Name = "svchost.exe"
		}, []Finding{FindingImageFileNameDiffers}},
		{"the mapped header page is wiped", func(p *testsupport.S43Process) {
			p.UserMemory = map[uint64][]byte{imageBase: make([]byte, 0x1000)}
		}, []Finding{FindingHeaderNotPE}},
		{"the mapped headers carry another ImageBase", func(p *testsupport.S43Process) {
			p.UserMemory = map[uint64][]byte{imageBase: headerPage(otherBase)}
		}, []Finding{FindingHeaderImageBaseDiffers, FindingHeaderDiffersFromFile}},
		{"SizeOfImage passes the end of the view", func(p *testsupport.S43Process) {
			p.Views[1].End = imageBase + 0x2000 - 1
		}, []Finding{FindingImageSizeExceedsRange}},
		{"the mapped headers differ from the section's", func(p *testsupport.S43Process) {
			page := headerPage(imageBase)
			binary.LittleEndian.PutUint32(page[testsupport.MappedPELfanew+8:], 0x6000_0000)
			p.UserMemory = map[uint64][]byte{imageBase: page}
		}, []Finding{FindingHeaderDiffersFromFile}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := consistent(1000)
			c.change(&p)
			rows, s, img := examineOne(t, p)
			if s != nil {
				t.Fatalf("not examined: %v", s)
			}
			if got := findings(rows); !slices.Equal(got, c.want) {
				t.Errorf("findings %v, want %v; rows %+v; diagnostics %q", got, c.want, rows, img.Diagnostics)
			}
			for _, r := range rows {
				if r.PID != 1000 || r.Process != p.Name || r.ImageBaseAddress != p.ImageBaseAddress ||
					r.SectionBaseAddress != p.SectionBaseAddress {
					t.Errorf("row %+v does not name the process and its two bases", r)
				}
			}
		})
	}
}

func TestTheRowNamesTheRangeAtTheImageBase(t *testing.T) {
	p := consistent(1000)
	p.Name = "evil.exe"
	rows, _, _ := examineOne(t, p)
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	r := rows[0]
	if r.RangeStart != imageBase || r.RangeEnd != imageBase+imageSize-1 || r.RangeType != "image" ||
		r.Protection != "PAGE_EXECUTE_WRITECOPY" || r.Path != viewFile {
		t.Errorf("row %+v", r)
	}
	if !strings.Contains(r.Detail, `"evil.exe"`) || !strings.Contains(r.Detail, `"app.exe"`) {
		t.Errorf("detail %q does not give both names", r.Detail)
	}
}

func TestTheFileHeaderTimeStampDifferenceIsNamed(t *testing.T) {
	p := consistent(1000)
	page := headerPage(imageBase)
	binary.LittleEndian.PutUint32(page[testsupport.MappedPELfanew+8:], 0x6000_0000)
	p.UserMemory = map[uint64][]byte{imageBase: page}
	rows, _, _ := examineOne(t, p)
	if len(rows) != 1 || !strings.HasPrefix(rows[0].Detail, "TimeDateStamp 0x60000000, section 0x5f000000") {
		t.Errorf("rows %+v", rows)
	}
}

func TestALongImageFileNameMatchesTheStartOfTheFileName(t *testing.T) {
	p := consistent(1000)
	p.Views[1].File.Name = `\Windows\StartMenuExperienceHost.exe`
	p.AuditName = `\Device\HarddiskVolume2\Windows\StartMenuExperienceHost.exe`
	p.Name = "StartMenuExper"
	if rows, _, _ := examineOne(t, p); len(rows) != 0 {
		t.Errorf("rows %+v", rows)
	}
	p.Name = "StartMenuExpex"
	if rows, _, _ := examineOne(t, p); !slices.Equal(findings(rows), []Finding{FindingImageFileNameDiffers}) {
		t.Errorf("rows %+v", rows)
	}
}

func TestNamesAreComparedByLastComponentWithoutCase(t *testing.T) {
	p := consistent(1000)
	p.Views[1].File.Name = `\VSMB-{x}\os\Windows\System32\APP.EXE`
	if rows, _, _ := examineOne(t, p); len(rows) != 0 {
		t.Errorf("rows %+v", rows)
	}
}

func TestProcessesThatCannotBeExaminedSaySo(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testsupport.S43Process)
		reason error
		cause  bool
	}{
		{"no PEB", func(p *testsupport.S43Process) { p.NoPeb = true }, errNoPEB, false},
		{"a secure process without a view", func(p *testsupport.S43Process) {
			p.Views = p.Views[:1]
			p.Secure = 0x140000031
		}, errSecure, false},
		{"fewer ranges than VadCount", func(p *testsupport.S43Process) {
			p.Views = p.Views[:1]
			p.VadCount = 211
		}, errTreeIncomplete, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := consistent(1000)
			c.change(&p)
			rows, s, _ := examineOne(t, p)
			if s == nil || !errors.Is(s, c.reason) || (s.cause != nil) != c.cause || len(rows) != 0 {
				t.Errorf("rows %+v, skip %v, want %v", rows, s, c.reason)
			}
		})
	}
}

func TestAnUnreadImageBaseIsDiagnosedAndRefusedInStrictMode(t *testing.T) {
	p := consistent(1000)
	img := testsupport.BuildS43Image([]testsupport.S43Process{p})
	for _, u := range img.User {
		u.Unmap(0x7ff6_0001_0000)
	}
	ctx := img.Context()
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %v, err %v", rows, err)
	}
	if !slices.ContainsFunc(img.Diagnostics, func(d string) bool {
		return strings.Contains(d, "pid 1000 _EPROCESS at 0x") && strings.Contains(d, "not examined: ImageBaseAddress not read")
	}) {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil || !errors.Is(err, errImageBaseUnread) {
		t.Errorf("strict: %v", err)
	}
}

func TestAnUnreadHeaderPageIsCountedNotFound(t *testing.T) {
	p := consistent(1000)
	p.UserMemory = nil
	rows, s, img := examineOne(t, p)
	if s != nil || len(rows) != 0 {
		t.Fatalf("rows %v skip %v", rows, s)
	}
	if !slices.ContainsFunc(img.Diagnostics, func(d string) bool { return strings.Contains(d, "header page at ImageBaseAddress 1") }) {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
}

func TestAZeroPageInBothCopiesIsNotAFinding(t *testing.T) {
	p := consistent(1000)
	p.UserMemory = map[uint64][]byte{imageBase: make([]byte, 0x1000)}
	p.Views[1].File.Header = make([]byte, 0x1000)
	rows, s, img := examineOne(t, p)
	if s != nil || len(rows) != 0 {
		t.Fatalf("rows %v skip %v", rows, s)
	}
	if !slices.ContainsFunc(img.Diagnostics, func(d string) bool { return strings.Contains(d, "section header page not PE or not resident 1") }) {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
}

func TestRunListsFindingsInProcessOrderAndKeepsThePIDAsked(t *testing.T) {
	a, b, c := consistent(1000), consistent(1004), consistent(1008)
	b.Name = "other.exe"
	c.SectionObjectCA = 0xffff_f800_beef_0000
	img := testsupport.BuildS43Image([]testsupport.S43Process{a, b, c})
	ctx := img.Context()
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []uint64
	for _, r := range rows {
		got = append(got, r.PID)
	}
	if !slices.Equal(got, []uint64{1004, 1008}) {
		t.Errorf("rows of %v, want 1004 then 1008: %+v", got, rows)
	}
	if !slices.Contains(img.Diagnostics, Name+": 3 processes, 3 examined") {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
	ctx = img.Context()
	ctx.Options["pid"] = "1008"
	out, err := tools.Execute(ctx, Name)
	if err != nil {
		t.Fatal(err)
	}
	if rows := out.([]Row); len(rows) != 1 || rows[0].PID != 1008 {
		t.Errorf("pid 1008: %+v", rows)
	}
}

func TestTheSystemProcessIsNotExamined(t *testing.T) {
	sys := consistent(4)
	sys.Name = "System"
	img := testsupport.BuildS43Image([]testsupport.S43Process{sys, consistent(1000)})
	if _, err := Run(img.Context()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(img.Diagnostics, Name+": 2 processes, 1 examined; not examined: 1 system process") {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
}

func TestATableWithoutTheRequiredMembersIsRefused(t *testing.T) {
	img := testsupport.BuildS43Image([]testsupport.S43Process{consistent(1000)})
	st, _ := img.Table.Struct("_EPROCESS")
	st.Fields = slices.DeleteFunc(st.Fields, func(f symbols.Field) bool { return f.Name == "SectionBaseAddress" })
	img.Table.AddStruct(st)
	if _, err := Run(img.Context()); !errors.Is(err, ErrLayout) {
		t.Errorf("err %v, want ErrLayout", err)
	}
}

func TestOnlyWindowsIsExamined(t *testing.T) {
	img := testsupport.BuildS43Image(nil)
	ctx := img.Context()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Error("a Linux profile was examined")
	}
}
