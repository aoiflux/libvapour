package processghosting

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

const (
	imageBase = uint64(0x7ff7_1000_0000)
	dllBase   = uint64(0x7ffc_9824_0000)
	imageSize = uint64(testsupport.MappedPESize)
	exeFile   = `\Windows\System32\app.exe`
	dllFile   = `\Windows\System32\helper.dll`
)

func withImages(pid uint64) testsupport.S43Process {
	return testsupport.S43Process{
		PID: pid, Name: "app.exe", ImageBaseAddress: imageBase, SectionBaseAddress: imageBase,
		Views: []testsupport.S43View{
			{Start: 0x10000, End: 0x1ffff, Private: true, Protection: 4},
			{Start: 0x20000, End: 0x2ffff, Protection: 2, File: &testsupport.S43File{Name: `\data.bin`, NotImage: true, DeletePending: true}},
			{Start: imageBase, End: imageBase + imageSize - 1, VadType: testsupport.S43ImageVadType, Protection: 7,
				File: &testsupport.S43File{Name: exeFile}},
			{Start: dllBase, End: dllBase + imageSize - 1, VadType: testsupport.S43ImageVadType, Protection: 7,
				File: &testsupport.S43File{Name: dllFile}},
		},
		FilePointerView: 2,
	}
}

func listed(img *testsupport.S43Image, pid uint64) processlist.Process {
	p := img.Process(pid)
	return processlist.Process{PID: p.PID, Name: p.Name, EPROCESS: p.EPROCESS, DirectoryTableBase: p.DirectoryTableBase}
}

func examineOne(t *testing.T, p testsupport.S43Process) ([]Row, *testsupport.S43Image) {
	t.Helper()
	img := testsupport.BuildS43Image([]testsupport.S43Process{p})
	e, err := newExaminer(img.Context())
	if err != nil {
		t.Fatalf("newExaminer: %v", err)
	}
	rows, err := e.examine(listed(img, p.PID))
	if err != nil {
		t.Fatalf("examine: %v", err)
	}
	e.report()
	return rows, img
}

func TestImageFilesThatAreNamedAndNotDeletePendingHaveNoRows(t *testing.T) {
	if rows, img := examineOne(t, withImages(1000)); len(rows) != 0 {
		t.Errorf("rows %+v; diagnostics %q", rows, img.Diagnostics)
	}
}

func TestADeletePendingProcessImageIsTheMainRow(t *testing.T) {
	p := withImages(1000)
	p.Views[2].File.DeletePending = true
	rows, img := examineOne(t, p)
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	r, placed := rows[0], img.Placed[1000][2]
	if r.PID != 1000 || r.Process != "app.exe" || r.Source != SourceImageView || !r.Main || r.Base != imageBase ||
		r.End != imageBase+imageSize-1 || r.ControlArea != placed.ControlArea || r.FileObject != placed.FileObject ||
		r.Path != exeFile || !r.DeletePending || r.DeleteOnClose || r.NameEmpty || r.NoFileObject ||
		!slices.Equal(r.Findings, []Finding{FindingDeletePending}) {
		t.Errorf("row %+v", r)
	}
}

func TestEachImageViewIsChecked(t *testing.T) {
	p := withImages(1000)
	p.Views[3].File.Name = ""
	p.Views[3].File.DeleteOnClose = true
	rows, _ := examineOne(t, p)
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	r := rows[0]
	if r.Main || r.Base != dllBase || !r.NameEmpty || !r.DeleteOnClose || r.Path != "" ||
		!slices.Equal(r.Findings, []Finding{FindingFileNameEmpty}) {
		t.Errorf("row %+v", r)
	}
}

func TestDeleteOnCloseAloneIsCountedNotFound(t *testing.T) {
	p := withImages(1000)
	p.Views[3].File.DeleteOnClose = true
	img := testsupport.BuildS43Image([]testsupport.S43Process{p})
	rows, err := Run(img.Context())
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
	want := Name + ": 1 processes, 1 examined, 2 image views, 1 with DeleteOnClose set in their control area"
	if !slices.Contains(img.Diagnostics, want) {
		t.Errorf("diagnostics %q, want %q", img.Diagnostics, want)
	}
}

func TestAnImageSectionWithoutAFileObjectIsFound(t *testing.T) {
	p := withImages(1000)
	p.Views[3].File.NoFilePointer = true
	rows, _ := examineOne(t, p)
	if len(rows) != 1 || !rows[0].NoFileObject || rows[0].FileObject != 0 ||
		!slices.Equal(rows[0].Findings, []Finding{FindingSectionWithoutFile}) {
		t.Errorf("rows %+v", rows)
	}
}

func TestAnUnreadControlAreaIsCountedNotFound(t *testing.T) {
	p := withImages(1000)
	img := testsupport.BuildS43Image([]testsupport.S43Process{p})
	img.Kernel.WriteU64(img.Placed[1000][3].ControlArea+testsupport.S19ControlAreaSize, 0xffff_f8ff_0000_0000)
	rows, err := Run(img.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("rows %+v", rows)
	}
	if !slices.ContainsFunc(img.Diagnostics, func(d string) bool { return strings.Contains(d, "image view file object 1") }) {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
}

func TestADeletePendingImageFilePointerIsItsOwnRow(t *testing.T) {
	p := withImages(1000)
	p.FilePointer = &testsupport.S43File{Name: `\Users\x\AppData\Local\Temp\x.tmp`, DeletePending: true}
	rows, img := examineOne(t, p)
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	r := rows[0]
	if r.Source != SourceImageFilePointer || !r.Main || r.Base != imageBase || r.FileObject != img.FilePointer[1000] ||
		r.ControlArea != 0 || r.Path != `\Users\x\AppData\Local\Temp\x.tmp` || !r.DeletePending {
		t.Errorf("row %+v", r)
	}
}

func TestAnImageFilePointerThatIsTheViewsFileObjectIsCheckedOnce(t *testing.T) {
	p := withImages(1000)
	p.Views[2].File.DeletePending = true
	img := testsupport.BuildS43Image([]testsupport.S43Process{p})
	view := img.Placed[1000][2].FileObject
	img.Kernel.WriteU64(img.Process(1000).EPROCESS+testsupport.S43ImageFilePointer, view)
	e, err := newExaminer(img.Context())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := e.examine(listed(img, 1000))
	if err != nil || len(rows) != 1 || rows[0].Source != SourceImageView {
		t.Errorf("rows %+v, err %v", rows, err)
	}
}

func TestAnUnreadNameIsCountedAndItsRuleNotApplied(t *testing.T) {
	p := withImages(1000)
	img := testsupport.BuildS43Image([]testsupport.S43Process{p})
	img.Kernel.WriteU64(img.Placed[1000][3].FileObject+0x60, 0xffff_f8ff_0000_0000)
	rows, err := Run(img.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(img.Diagnostics, func(d string) bool { return strings.Contains(d, "FILE_OBJECT.FileName") }) {
		t.Errorf("rows %+v; diagnostics %q", rows, img.Diagnostics)
	}
}

func TestRunKeepsThePIDAskedAndSkipsTheSystemProcess(t *testing.T) {
	sys, a, b := withImages(4), withImages(1000), withImages(1004)
	sys.Name = "System"
	sys.Views[2].File.DeletePending = true
	a.Views[2].File.DeletePending = true
	b.Views[3].File.DeletePending = true
	img := testsupport.BuildS43Image([]testsupport.S43Process{sys, a, b})
	ctx := img.Context()
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []uint64
	for _, r := range rows {
		got = append(got, r.PID)
	}
	if !slices.Equal(got, []uint64{1000, 1004}) {
		t.Errorf("rows of %v: %+v", got, rows)
	}
	if !slices.ContainsFunc(img.Diagnostics, func(d string) bool { return strings.HasSuffix(d, "not examined: 1 system process") }) {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
	ctx = img.Context()
	ctx.Options["pid"] = []uint64{1004}
	out, err := tools.Execute(ctx, Name)
	if err != nil {
		t.Fatal(err)
	}
	if rows := out.([]Row); len(rows) != 1 || rows[0].PID != 1004 || rows[0].Base != dllBase {
		t.Errorf("pid 1004: %+v", rows)
	}
}

func TestAnUnreadVADTreeIsDiagnosedAndRefusedInStrictMode(t *testing.T) {
	img := testsupport.BuildS43Image([]testsupport.S43Process{withImages(1000)})
	ctx := img.Context()
	ctx.Memory = holeAt{ctx.Memory, img.Process(1000).EPROCESS + testsupport.S43VadRoot}
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %v, err %v", rows, err)
	}
	if !slices.ContainsFunc(img.Diagnostics, func(d string) bool { return strings.Contains(d, "not examined: VAD tree not read") }) {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Error("strict mode passed an unread VAD tree")
	}
}

type holeAt struct {
	memory.MemoryReader
	at uint64
}

func (h holeAt) ReadAt(at, size uint64) ([]byte, error) {
	if at <= h.at && h.at < at+size {
		return nil, memory.ErrOutOfBounds
	}
	return h.MemoryReader.ReadAt(at, size)
}

func TestATableWithoutDeletePendingIsRefused(t *testing.T) {
	img := testsupport.BuildS43Image([]testsupport.S43Process{withImages(1000)})
	st, _ := img.Table.Struct("_FILE_OBJECT")
	st.Fields = slices.DeleteFunc(st.Fields, func(f symbols.Field) bool { return f.Name == "DeletePending" })
	img.Table.AddStruct(st)
	if _, err := Run(img.Context()); !errors.Is(err, ErrLayout) {
		t.Errorf("err %v, want ErrLayout", err)
	}
}

func TestOnlyWindowsIsExamined(t *testing.T) {
	ctx := testsupport.BuildS43Image(nil).Context()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Error("a Linux profile was examined")
	}
}

// Arbitrary bytes over an image view's file object: the examiner never
// panics, and DeletePending and the empty name are reported exactly when the
// bytes say so.
func FuzzFileObjectState(f *testing.F) {
	f.Add(make([]byte, testsupport.S19FileObjectSize))
	f.Add([]byte{0x05, 0x00, 0xd8})
	f.Fuzz(func(t *testing.T, raw []byte) {
		raw = raw[:min(len(raw), testsupport.S19FileObjectSize)]
		img := testsupport.BuildS43Image([]testsupport.S43Process{withImages(1000)})
		fo := img.Placed[1000][3].FileObject
		img.Kernel.Write(fo, raw)
		e, err := newExaminer(img.Context())
		if err != nil {
			t.Fatal(err)
		}
		rows, err := e.examine(listed(img, 1000))
		if err != nil {
			t.Fatal(err)
		}
		pending := len(raw) > testsupport.S43FileDeletePending && raw[testsupport.S43FileDeletePending] != 0
		var dll *Row
		for i := range rows {
			if rows[i].Base == dllBase {
				dll = &rows[i]
			}
		}
		if pending != (dll != nil && dll.DeletePending) {
			t.Fatalf("DeletePending byte %v, rows %+v", pending, rows)
		}
		if dll != nil && dll.NameEmpty != slices.Contains(dll.Findings, FindingFileNameEmpty) {
			t.Fatalf("row %+v", dll)
		}
	})
}
