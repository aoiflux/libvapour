package servicecandidates

import (
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	paramsVA    = uint64(0x00007ff600200000)
	textVA      = uint64(0x00007ff600300000)
	pebParams   = uint64(0x20)
	commandLine = uint64(0x70)
)

type host struct {
	pid  uint64
	name string
	line string
}

func fixture(t *testing.T, hosts ...host) (tools.Context, *[]string) {
	t.Helper()
	specs := make([]testsupport.FixtureProcess, len(hosts))
	for i, h := range hosts {
		specs[i] = testsupport.FixtureProcess{PID: h.pid, Name: h.name}
	}
	f := testsupport.BuildProcessFixture(specs)
	f.Table.AddStruct(symbols.StructType{Name: "_PEB", Size: 0x400, Fields: []symbols.Field{
		{Name: "Ldr", Offset: testsupport.FixtureLdrOffset}, {Name: "ProcessParameters", Offset: pebParams}}})
	f.Table.AddStruct(symbols.StructType{Name: "_RTL_USER_PROCESS_PARAMETERS", Size: 0x440, Fields: []symbols.Field{
		{Name: "CommandLine", Offset: commandLine, Type: symbols.TypeRef{Name: "_UNICODE_STRING"}}}})
	for _, h := range hosts {
		_, epPA := f.EPROCESS(h.pid)
		raw, _ := f.Memory.ReadAt(epPA+testsupport.FixturePebOffset, 8)
		as := f.Space(h.pid)
		f.Memory.WriteU64(as.MapPage(binary.LittleEndian.Uint64(raw))+pebParams, paramsVA)
		if h.line == "" {
			continue
		}
		paramsPA := as.MapPage(paramsVA)
		var text []byte
		for _, u := range utf16.Encode([]rune(h.line)) {
			text = binary.LittleEndian.AppendUint16(text, u)
		}
		f.Memory.WriteU16(paramsPA+commandLine, uint16(len(text)))
		f.Memory.WriteU16(paramsPA+commandLine+2, uint16(len(text)+2))
		f.Memory.WriteU64(paramsPA+commandLine+testsupport.FixtureUnicodeBufferOffset, textVA)
		f.Memory.WriteAt(as.MapPage(textVA), text)
	}
	ctx := f.Context()
	diags := &[]string{}
	ctx.Options["diagnostics"] = diags
	return ctx, diags
}

func TestServiceHostsNameTheirGroupAndService(t *testing.T) {
	ctx, _ := fixture(t,
		host{1144, "svchost.exe", `C:\Windows\System32\svchost.exe -k NetworkService -s TermService`},
		host{512, "SVCHOST.EXE", `"C:\Windows\system32\svchost.exe" -k DcomLaunch -p`},
		host{600, "notepad.exe", `notepad.exe -k x`},
		host{700, "svchost.exe", `svchost.exe`},
	)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(rows))
	for i, r := range rows {
		got[i] = r.Process + "|" + r.Group + "|" + r.Service
	}
	want := []string{"SVCHOST.EXE|DcomLaunch|", "svchost.exe||", "svchost.exe|NetworkService|TermService"}
	if !slices.Equal(got, want) {
		t.Errorf("rows %q, want %q", got, want)
	}
	if rows[2].PID != 1144 || !strings.Contains(rows[2].CommandLine, "TermService") || rows[2].EPROCESS == 0 {
		t.Errorf("row %+v", rows[2])
	}
}

func TestAHostWhoseCommandLineDoesNotReadIsLeftOut(t *testing.T) {
	ctx, diags := fixture(t, host{8, "svchost.exe", ""})
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 || !slices.ContainsFunc(*diags, func(d string) bool {
		return strings.Contains(d, "pid 8: command line does not read, left out")
	}) {
		t.Errorf("rows %+v err %v diags %q", rows, err, *diags)
	}
}

func TestThePIDSetAndProfile(t *testing.T) {
	ctx, _ := fixture(t, host{8, "svchost.exe", "svchost.exe -k a"}, host{12, "svchost.exe", "svchost.exe -k b"})
	ctx.Options["pid"] = uint64(12)
	if rows, _ := Run(ctx); len(rows) != 1 || rows[0].Group != "b" {
		t.Errorf("rows %+v", rows)
	}
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Error("a linux profile was taken")
	}
}

func TestSplittingACommandLine(t *testing.T) {
	for _, tc := range []struct {
		line string
		want []string
	}{
		{`"C:\Program Files\a.exe" -k "Local Service" x`, []string{`C:\Program Files\a.exe`, "-k", "Local Service", "x"}},
		{"a\t-s  b", []string{"a", "-s", "b"}},
		{`a "say ""hi""" ""`, []string{"a", `say "hi"`, ""}},
		{`"a""b" c`, []string{"ab", "c"}},
		{`a "open`, []string{"a", "open"}},
		{"", nil},
	} {
		if got := splitCommandLine(tc.line); !slices.Equal(got, tc.want) {
			t.Errorf("%q: %q, want %q", tc.line, got, tc.want)
		}
	}
	if argumentAfter([]string{"-k"}, "-k") != "" || argumentAfter([]string{"x", "-K", "g"}, "-k") != "g" {
		t.Error("argumentAfter")
	}
}
