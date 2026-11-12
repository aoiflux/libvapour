package librarycompare

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
)

const (
	appBase   = uint64(0x7ff7_0000_0000)
	dllBase   = uint64(0x7ff7_1000_0000)
	cutBase   = uint64(0x7ff7_2000_0000)
	hideBase  = uint64(0x7ff7_3000_0000)
	dataBase  = uint64(0x7ff7_4000_0000)
	wowBase   = uint64(0x0050_0000)
	extraBase = uint64(0x7ff7_5000_0000)
)

func imageView(start uint64, name string) testsupport.S43View {
	return testsupport.S43View{Start: start, End: start + 0xffff, VadType: testsupport.S43ImageVadType,
		File: &testsupport.S43File{Name: name}}
}

func library(base uint64, name string) testsupport.S56Library {
	return testsupport.S56Library{Base: base, Size: 0x10000, Name: name, FullPath: `C:\x\` + name}
}

func process(pid uint64, name string, views []testsupport.S43View, libs []testsupport.S56Library) testsupport.S66CProcess {
	return testsupport.S66CProcess{
		S43Process: testsupport.S43Process{PID: pid, Name: name, Views: views, FilePointerView: -1},
		Libraries:  libs,
	}
}

func run(t *testing.T, img *testsupport.S43Image, options map[string]any) ([]Module, []string) {
	t.Helper()
	ctx := img.Context()
	for k, v := range options {
		ctx.Options[k] = v
	}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rows, img.Diagnostics
}

func TestEachImageViewIsARowWithTheListsThatHoldItsBase(t *testing.T) {
	cut := library(cutBase, "cut.dll")
	cut.NotInLoad, cut.NotInInit = true, true
	app := library(appBase, "app.exe")
	app.NotInInit = true
	img := testsupport.BuildS66CImage([]testsupport.S66CProcess{process(100, "app.exe",
		[]testsupport.S43View{
			imageView(hideBase, `\Temp\hidden.dll`),
			imageView(appBase, `\app.exe`),
			{Start: dataBase, End: dataBase + 0xfff, Private: true},
			imageView(dllBase, `\Windows\System32\kernel32.dll`),
			imageView(cutBase, `\Temp\cut.dll`),
		},
		[]testsupport.S56Library{app, library(dllBase, "kernel32.dll"), cut})})
	rows, _ := run(t, img, nil)
	want := []Module{
		{PID: 100, Process: "app.exe", Base: appBase, InLoad: true, InMem: true, MappedPath: `\app.exe`},
		{PID: 100, Process: "app.exe", Base: dllBase, InLoad: true, InMem: true, InInit: true, MappedPath: `\Windows\System32\kernel32.dll`},
		{PID: 100, Process: "app.exe", Base: cutBase, InMem: true, MappedPath: `\Temp\cut.dll`},
		{PID: 100, Process: "app.exe", Base: hideBase, MappedPath: `\Temp\hidden.dll`},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %+v, want %d image views", rows, len(want))
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestAProcessWithoutLoaderRecordsSaysTheFlagsMeanNothing(t *testing.T) {
	p := process(200, "noldr.exe", []testsupport.S43View{imageView(appBase, `\noldr.exe`)}, nil)
	p.NoPeb = true
	img := testsupport.BuildS66CImage([]testsupport.S66CProcess{p})
	rows, diags := run(t, img, nil)
	if len(rows) != 1 || !rows[0].LoaderListsEmpty || rows[0].InLoad || rows[0].InMem || rows[0].InInit {
		t.Fatalf("rows = %+v, want one row on no list with LoaderListsEmpty", rows)
	}
	if !contains(diags, "no loader list gave a record: its 1 image views are on no list") {
		t.Errorf("diagnostics %q do not say the lists gave nothing", diags)
	}
}

func TestA32BitRecordMarksItsViewWoW64(t *testing.T) {
	p := process(300, "wow.exe", []testsupport.S43View{imageView(appBase, `\ntdll.dll`), imageView(wowBase, `\SysWOW64\ntdll.dll`)},
		[]testsupport.S56Library{library(appBase, "ntdll.dll")})
	p.Wow64 = []testsupport.S56Library{library(wowBase, "ntdll.dll")}
	img := testsupport.BuildS66CImage([]testsupport.S66CProcess{p})
	rows, _ := run(t, img, nil)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	if r := rows[0]; r.Base != wowBase || !r.Wow64 || !r.InLoad || !r.InMem || !r.InInit {
		t.Errorf("32-bit view row = %+v, want on all three 32-bit lists and Wow64", r)
	}
	if r := rows[1]; r.Base != appBase || r.Wow64 || !r.InLoad {
		t.Errorf("native view row = %+v", r)
	}
}

func TestARecordWithNoImageViewIsReported(t *testing.T) {
	img := testsupport.BuildS66CImage([]testsupport.S66CProcess{process(400, "a.exe",
		[]testsupport.S43View{imageView(appBase, `\a.exe`)},
		[]testsupport.S56Library{library(appBase, "a.exe"), library(extraBase, "manual.dll")})})
	rows, diags := run(t, img, nil)
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want only the image view", rows)
	}
	if !contains(diags, "1 loader records have no image view at their DllBase, the lowest at 0x7ff750000000") {
		t.Errorf("diagnostics %q do not name the record without a view", diags)
	}
}

func TestThePIDSetNarrowsTheProcesses(t *testing.T) {
	img := testsupport.BuildS66CImage([]testsupport.S66CProcess{
		process(500, "a.exe", []testsupport.S43View{imageView(appBase, `\a.exe`)}, []testsupport.S56Library{library(appBase, "a.exe")}),
		process(600, "b.exe", []testsupport.S43View{imageView(appBase, `\b.exe`)}, []testsupport.S56Library{library(appBase, "b.exe")}),
	})
	rows, _ := run(t, img, map[string]any{"pid": uint64(600)})
	if len(rows) != 1 || rows[0].PID != 600 || !rows[0].InLoad {
		t.Fatalf("rows = %+v, want pid 600 only", rows)
	}
}

func TestAVADTreeThatDoesNotReadLeavesItsRecordsWithoutAViewOrFailsStrict(t *testing.T) {
	img := testsupport.BuildS66CImage([]testsupport.S66CProcess{
		process(700, "a.exe", []testsupport.S43View{imageView(appBase, `\a.exe`)}, []testsupport.S56Library{library(appBase, "a.exe")}),
	})
	img.Kernel.WriteU64(img.Procs[0].EPROCESS+testsupport.S43VadRoot, 0xfffff800_0900_0000)
	rows, diags := run(t, img, nil)
	if len(rows) != 0 || !contains(diags, "1 loader records have no image view at their DllBase") {
		t.Fatalf("rows %+v, diagnostics %q", rows, diags)
	}
	ctx := img.Context()
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "VADs do not read") {
		t.Errorf("strict run error = %v", err)
	}
}

func TestANonWindowsProfileIsRefused(t *testing.T) {
	img := testsupport.BuildS66CImage(nil)
	ctx := img.Context()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("err = %v, want ErrNotWindows", err)
	}
}

func TestTheToolIsRegistered(t *testing.T) {
	if _, err := tools.Get(Name); err != nil {
		t.Fatal(err)
	}
}

func contains(diags []string, part string) bool {
	for _, d := range diags {
		if strings.Contains(d, part) {
			return true
		}
	}
	return false
}
