package extract

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEachKindHasOneSpelling(t *testing.T) {
	cases := []struct {
		name Name
		want string
	}{
		{
			Name{Kind: KindRegion, Scope: Process(4), Addresses: []uint64{0x100000, 0x100fff}, Ext: ExtBytes},
			"region.pid4.0x0000000000100000.0x0000000000100fff.bin",
		},
		{
			Name{Kind: KindModule, Scope: Process(6380), Addresses: []uint64{0x7ffb12340000, 0xffff8000deadbeef},
				Labels: []string{`C:\Windows\System32\ntdll.dll`}, Ext: ExtPE},
			"module.pid6380.0x00007ffb12340000.0xffff8000deadbeef.ntdll.dll.pe",
		},
		{
			Name{Kind: KindModule, Scope: Kernel, Addresses: []uint64{0xffffffffc0a00000}, Labels: []string{"nf_tables"}, Ext: ExtELF},
			"module.kernel.0xffffffffc0a00000.nf_tables.elf",
		},
		{
			Name{Kind: KindImage, Scope: Process(1234), Addresses: []uint64{0x7ff600000000, 0xffff9e0812345000}, Ext: ExtPE},
			"image.pid1234.0x00007ff600000000.0xffff9e0812345000.pe",
		},
		{
			Name{Kind: KindProcess, Scope: Process(660), Addresses: []uint64{0xffff9e0812345000}, Labels: []string{"lsass.exe"}, Ext: ExtMinidump},
			"process.pid660.0xffff9e0812345000.lsass.exe.dmp",
		},
		{
			Name{Kind: KindFile, Scope: Kernel, Addresses: []uint64{0xffff8001aaaa0000, 0xffff8002bbbb0000},
				Labels: []string{ViewData, `\Device\HarddiskVolume2\Windows\notepad.exe`}, Ext: ExtBytes},
			"file.kernel.0xffff8001aaaa0000.0xffff8002bbbb0000.data.notepad.exe.bin",
		},
		{
			Name{Kind: KindHive, Scope: Kernel, Addresses: []uint64{0xffffc00012345000}, Labels: []string{`\REGISTRY\MACHINE\SAM`}, Ext: ExtHive},
			"hive.kernel.0xffffc00012345000.SAM.regf",
		},
		{
			Name{Kind: KindInode, Scope: Kernel, Addresses: []uint64{0xffff888003a1c000}, Ext: ExtBytes},
			"inode.kernel.0xffff888003a1c000.bin",
		},
		{
			Name{Kind: KindPageCache, Scope: Kernel, Ext: ExtTarGzip},
			"pagecache.kernel.tar.gz",
		},
		{
			Name{Kind: KindFramebuffer, Scope: Kernel, Addresses: []uint64{0xffff888000100000}, Labels: []string{"hyperv_drmdrmfb"}, Ext: ExtPNG},
			"framebuffer.kernel.0xffff888000100000.hyperv_drmdrmfb.png",
		},
		{
			Name{Kind: KindFramebuffer, Scope: Kernel, Addresses: []uint64{0xffff888000200000}, Labels: []string{"yuv"}, Ext: ExtBytes},
			"framebuffer.kernel.0xffff888000200000.yuv.bin",
		},
		{
			Name{Kind: KindRegion, Scope: Process(8), Width: 4, Addresses: []uint64{0xffffffff80001000, 0}, Ext: ExtBytes},
			"region.pid8.0x80001000.0x00000000.bin",
		},
	}
	for _, c := range cases {
		if got := c.name.String(); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestAHostileLabelStaysOneComponent(t *testing.T) {
	cases := map[string]string{
		`..\..\Windows\evil.dll`: "evil.dll",
		"a/b":                    "b",
		"C:evil":                 "C_evil",
		"evil\x00.dll":           "evil_.dll",
		"a b\nc":                 "a_b_c",
		"\u00e9vil.dll":          "_vil.dll",
		"COM\u00b9":              "COM_",
		"":                       "",
	}
	for in, want := range cases {
		if got := Label(in); got != want {
			t.Errorf("Label(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("x", 200)
	if got := Label(long); len(got) != maxLabelBytes || !strings.HasSuffix(got, "~") {
		t.Errorf("a 200-byte label became %d bytes %q; want %d ending in ~", len(got), got, maxLabelBytes)
	}
}

func TestAnEmptyLabelLeavesNoGap(t *testing.T) {
	n := Name{Kind: KindProcess, Scope: Process(1), Addresses: []uint64{1}, Labels: []string{"", "/"}, Ext: ExtMinidump}
	if got, want := n.String(), "process.pid1.0x0000000000000001.dmp"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTheFilesystemBoundaryRefusesUnsafeNames(t *testing.T) {
	cases := map[string]string{
		"NUL.dmp":       "_NUL.dmp",
		"con":           "_con",
		"lpt9.x.bin":    "_lpt9.x.bin",
		"COM0.bin":      "_COM0.bin",
		".hidden":       "_.hidden",
		"-rf":           "_-rf",
		"trailing.":     "trailing_",
		"a b.raw":       "a_b.raw",
		"COM10.bin":     "COM10.bin",
		"null.sys":      "null.sys",
		"..":            "__",
		"timeline.body": "timeline.body",
	}
	for in, want := range cases {
		got, err := safeName(in)
		if err != nil || got != want {
			t.Errorf("safeName(%q) = %q, %v; want %q", in, got, err, want)
		}
		if again, _ := safeName(got); again != got {
			t.Errorf("safeName is not idempotent on %q: %q", got, again)
		}
	}
	if _, err := safeName(""); !errors.Is(err, errEmptyName) {
		t.Errorf("empty name: %v, want errEmptyName", err)
	}
	if _, err := safeName(strings.Repeat("a", maxNameBytes+1)); err == nil {
		t.Error("a 256-byte name was accepted")
	}
}

func TestDeviceNamesAreRecognisedInAnyPath(t *testing.T) {
	for _, p := range []string{`\??\C:\NUL`, "CONIN$", "conout$.txt", "NUL  .dmp", "LPT\u00b3", "aux.c"} {
		if !IsDeviceName(p) {
			t.Errorf("IsDeviceName(%q) = false", p)
		}
	}
	for _, p := range []string{`\SystemRoot\System32\ntoskrnl.exe`, "COM10", "LPT", "console.dll", " NUL"} {
		if IsDeviceName(p) {
			t.Errorf("IsDeviceName(%q) = true", p)
		}
	}
}

func TestCreateNewKeepsAHostileNameInTheDirectory(t *testing.T) {
	dir := t.TempDir()
	name := Name{Kind: KindModule, Scope: Kernel, Addresses: []uint64{0x1000}, Labels: []string{`..\..\..\evil.dll`}, Ext: ExtPE}.String()
	f, err := CreateNew(dir, name)
	if err != nil {
		t.Fatalf("CreateNew: %v", err)
	}
	f.Close()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("directory holds %v (err %v); want only %s", entries, err, name)
	}
}

func TestCreateNewNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	name := "region.pid4.0x0000000000100000.0x0000000000100fff.bin"
	f, err := CreateNew(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("original")
	f.Close()
	if _, err := CreateNew(dir, name); !errors.Is(err, ErrArtifactExists) {
		t.Fatalf("second CreateNew: %v, want ErrArtifactExists", err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, name)); string(data) != "original" {
		t.Errorf("existing artifact changed to %q", data)
	}
}

func TestCreateNewMakesMissingDirectories(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	f, err := CreateNew(dir, "x.bin")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := os.Stat(dir); err != nil {
		t.Error(err)
	}
}

func TestCreateUniqueStopsAtTheAttemptLimit(t *testing.T) {
	dir := t.TempDir()
	var got []string
	for range 3 {
		f, name, err := CreateUnique(dir, "frame.png", 3)
		if err != nil {
			t.Fatalf("after %v: %v", got, err)
		}
		f.Close()
		got = append(got, name)
	}
	if strings.Join(got, " ") != "frame.png frame-1.png frame-2.png" {
		t.Errorf("names %v", got)
	}
	if _, _, err := CreateUnique(dir, "frame.png", 3); !errors.Is(err, ErrArtifactExists) || !strings.Contains(err.Error(), "NameAttempts (3)") {
		t.Fatalf("fourth file: %v", err)
	}
}

func FuzzNamesStayPortable(f *testing.F) {
	for _, s := range []string{"", `..\x`, `\??\C:\NUL`, "a\x00b", "\u00e9", strings.Repeat("y", 300)} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		name := Name{Kind: KindFile, Scope: Process(1), Addresses: []uint64{1, 2}, Labels: []string{a, b}, Ext: ExtBytes}.String()
		if len(name) > maxNameBytes {
			t.Fatalf("%d bytes", len(name))
		}
		for _, r := range name {
			if !isPortable(r) {
				t.Fatalf("%q holds %q", name, r)
			}
		}
		if IsDeviceName(name) || name[0] == '.' || name[0] == '-' {
			t.Fatalf("unsafe %q", name)
		}
		if got, err := safeName(name); err != nil || got != name {
			t.Fatalf("safeName changed a built name: %q -> %q, %v", name, got, err)
		}
		if _, err := safeName(a); err == nil {
			got, _ := safeName(a)
			if strings.ContainsAny(got, `\/:`) {
				t.Fatalf("safeName(%q) = %q", a, got)
			}
		}
	})
}
