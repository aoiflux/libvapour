package processidentity

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
)

const (
	sKernel = `\Device\HarddiskVolume3\Windows\System32\svchost.exe`
	sImage  = `C:\Windows\System32\svchost.exe`
	sCmd    = `C:\Windows\system32\svchost.exe -k netsvcs -p`
)

func clean(pid uint64) sProcess {
	return sProcess{pid: pid, name: "svchost.exe", kernelPath: sKernel, image: sString{text: sImage}, cmd: sString{text: sCmd}}
}

func runRows(t *testing.T, f *testsupport.ProcessFixture, opts map[string]any) ([]Row, []string) {
	t.Helper()
	ctx := f.Context()
	var diags []string
	ctx.Options["diagnostics"] = &diags
	for k, v := range opts {
		ctx.Options[k] = v
	}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rows, diags
}

func TestALoaderBuiltProcessHasNoFinding(t *testing.T) {
	rows, _ := runRows(t, sFixture(clean(1200)), nil)
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	want := Row{PID: 1200, Process: "svchost.exe", Address: rows[0].Address, KernelPath: sKernel, KernelPathRead: true,
		Parameters: ParametersRead, ImagePath: sImage, ImagePathRead: true, CommandLineRead: true}
	if rows[0] != want {
		t.Errorf("row %+v\nwant %+v", rows[0], want)
	}
}

func TestEachFindingIsRaisedByItsOwnRule(t *testing.T) {
	long := `\Device\HarddiskVolume3\Program Files\App\averyveryverylongname.exe`
	cases := []struct {
		name  string
		p     sProcess
		check func(Row) bool
	}{
		{"short name of another file", sProcess{pid: 8, name: "lsass.exe", kernelPath: sKernel, image: sString{text: sImage}, cmd: sString{text: sCmd}},
			func(r Row) bool { return r.NameDiffers && !r.ImagePathDiffers }},
		{"short name cut at 14 bytes", sProcess{pid: 8, name: "averyveryveryl", kernelPath: long,
			image: sString{text: `C:\Program Files\App\averyveryverylongname.exe`}, cmd: sString{text: "x"}},
			func(r Row) bool { return !r.NameDiffers && !r.ImagePathDiffers }},
		{"short name differs only in case", sProcess{pid: 8, name: "SVCHOST.EXE", kernelPath: sKernel, image: sString{text: sImage}, cmd: sString{text: sCmd}},
			func(r Row) bool { return !r.NameDiffers }},
		{"image path names another file", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: `C:\Windows\System32\notepad.exe`}, cmd: sString{text: sCmd}},
			func(r Row) bool { return r.ImagePathDiffers && !r.ImagePathRewritten }},
		{"image path in another directory", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: `C:\Users\Public\svchost.exe`}, cmd: sString{text: sCmd}},
			func(r Row) bool { return r.ImagePathDiffers }},
		{"image path differs only in case", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: `C:\WINDOWS\system32\SVCHOST.EXE`}, cmd: sString{text: sCmd}},
			func(r Row) bool { return !r.ImagePathDiffers }},
		{"image path buffer outside the block", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: sImage, outside: true}, cmd: sString{text: sCmd}},
			func(r Row) bool { return r.ImagePathRewritten && !r.CommandLineRewritten }},
		{"command line buffer outside the block", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: sImage}, cmd: sString{text: sCmd, outside: true}},
			func(r Row) bool { return r.CommandLineRewritten && !r.ImagePathRewritten }},
		{"shorter text with the old capacity", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: sImage, maximum: 2*len(sImage) + 40}, cmd: sString{text: sCmd}},
			func(r Row) bool { return r.ImagePathRewritten }},
		{"command line capacity changed", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: sImage}, cmd: sString{text: sCmd, maximum: 2 * len(sCmd)}},
			func(r Row) bool { return r.CommandLineRewritten }},
		{"no NUL after the text", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: sImage, noNUL: true, maximum: 2 * len(sImage)}, cmd: sString{text: sCmd}},
			func(r Row) bool { return r.ImagePathRewritten }},
		{"odd length", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: sImage, length: 2*len(sImage) - 1, maximum: 2*len(sImage) + 1}, cmd: sString{text: sCmd}},
			func(r Row) bool { return r.ImagePathRewritten }},
		{"NUL inside the image path", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: `C:\Windows\System32\svchost.exe` + "\x00" + `.txt`}, cmd: sString{text: sCmd}},
			func(r Row) bool { return r.ImagePathRewritten }},
		{"NUL inside the command line is allowed", sProcess{pid: 8, name: "svchost.exe", kernelPath: sKernel,
			image: sString{text: sImage}, cmd: sString{text: "a.exe\x00b\x00c"}},
			func(r Row) bool { return !r.CommandLineRewritten }},
	}
	for _, c := range cases {
		rows, _ := runRows(t, sFixture(c.p), nil)
		if len(rows) != 1 || !c.check(rows[0]) {
			t.Errorf("%s: rows %+v", c.name, rows)
		}
	}
}

func TestMissingRecordsTakeNoPartInTheComparisons(t *testing.T) {
	noAudit := clean(8)
	noAudit.noAudit, noAudit.image.text = true, `C:\other.exe`
	noPeb := clean(12)
	noPeb.noPeb = true
	noParams := clean(16)
	noParams.noParams = true
	rows, _ := runRows(t, sFixture(noAudit, noPeb, noParams), nil)
	if len(rows) != 3 {
		t.Fatalf("rows %+v", rows)
	}
	if r := rows[0]; r.KernelPathRead || r.NameDiffers || r.ImagePathDiffers || !r.ImagePathRead {
		t.Errorf("no audit name: %+v", r)
	}
	for _, r := range rows[1:] {
		if r.Parameters != ParametersAbsent || r.ImagePathRead || r.CommandLineRead || r.ImagePathRewritten {
			t.Errorf("no parameter block: %+v", r)
		}
	}
}

func TestAnUnreadableParameterBlockIsCountedAndStopsStrictMode(t *testing.T) {
	f := sFixture(clean(1200), clean(3000))
	ctx := f.Context()
	testsupport.HoleInProcess(&ctx, f.DirectoryTableBase(3000), sPebVA, sPebVA+0x1000)
	var diags []string
	ctx.Options["diagnostics"] = &diags
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rows[1].Parameters != ParametersUnread || rows[0].Parameters != ParametersRead {
		t.Errorf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "1 processes whose parameter block did not read") {
		t.Errorf("diagnostics %q", diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "parameter block not read") {
		t.Errorf("strict: %v", err)
	}
}

func TestThePIDOptionKeepsOnlyTheProcessesItNames(t *testing.T) {
	rows, _ := runRows(t, sFixture(clean(1200), clean(640), clean(3000)), map[string]any{"pid": "3000,1200"})
	if len(rows) != 2 || rows[0].PID != 1200 || rows[1].PID != 3000 {
		t.Errorf("rows %+v", rows)
	}
}

func TestATableWithoutTheStringsIsRefused(t *testing.T) {
	f := sFixture(clean(1200))
	f.Table.AddStruct(symbolsWithout(t, f, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName", "CommandLine"))
	if _, err := Run(f.Context()); !errors.Is(err, ErrNoProcessString) {
		t.Errorf("Run: %v, want %v", err, ErrNoProcessString)
	}
	f = sFixture(clean(1200))
	f.Table.AddStruct(symbolsWithout(t, f, "_EPROCESS", "SeAuditProcessCreationInfo"))
	rows, diags := runRows(t, f, nil)
	if len(rows) != 1 || rows[0].KernelPathRead || !strings.Contains(strings.Join(diags, "\n"), "SeAuditProcessCreationInfo") {
		t.Errorf("without the audit member: rows %+v diagnostics %q", rows, diags)
	}
}

func TestOnlyWindowsProfilesRun(t *testing.T) {
	ctx := sFixture(clean(1200)).Context()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Error("Run on a Linux profile: no error")
	}
	var _ tools.Context = ctx
}
