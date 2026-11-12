package libvapour

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/symbols/linuxkernel"
	lt "github.com/aoiflux/libvapour/symbols/linuxkernel/linuxtest"
)

// The capture of linuxtest maps its arrays page at ArraysVA plus the shift
// from a 4-level table at PML4; the banner sits in that page past the
// kallsyms arrays, and the note below the arrays page.
const (
	lxShift     = 0x1000000
	lxBannerOff = 0x8000
	lxNoteAt    = 0x100000
	lxDamagedAt = 0x80000
	// A stored pointer outside the kernel image window (S75 L10), which
	// does not move.
	lxStoredPointer = 0xffffea0000000000
)

var lxBanner = []byte("Linux version 6.17.0-s76 (builder@host) (gcc) #1 SMP\n\x00")

func lxCapture(damaged bool) []byte {
	buf := lt.Capture(lxShift, nil, nil)
	copy(buf[lt.ArraysPA+lxBannerOff:], lxBanner)
	lt.PutNote(buf, lxNoteAt, "OSRELEASE=6.17.0-s76\n"+lt.LayoutKeys(lxShift)+lt.KallsymsKeys(lxShift))
	if damaged {
		lt.PutNote(buf, lxDamagedAt, "OSRELEASE=6.17.0-s76\nGARBAGE\n")
	}
	return buf
}

func lxTable(banner []byte, stext uint64) symbols.Declaration {
	return symbols.Declaration{PointerWidth: 8, LinuxBanner: banner, Addresses: []symbols.Address{
		{Name: "linux_banner", Address: lt.ArraysVA + lxBannerOff},
		{Name: "_stext", Address: stext},
		{Name: "vmemmap_base", Address: lxStoredPointer},
	}}
}

func openLinux(t *testing.T, capture []byte, d symbols.Declaration, cfg OpenConfig) (*Session, error) {
	t.Helper()
	image := filepath.Join(t.TempDir(), "linux.raw")
	if err := os.WriteFile(image, capture, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.SymbolsPath = writeTable(t, d)
	s, err := OpenLinuxMemory(image, cfg)
	if err == nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	return s, err
}

func TestALinuxSessionMovesOnlyTheKernelImage(t *testing.T) {
	s, err := openLinux(t, lxCapture(false), lxTable(lxBanner, lt.KernelBase), OpenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := s.Context()
	if root, _ := ctx.KernelDTB(); root != lt.PML4 {
		t.Errorf("kernel root 0x%x", root)
	}
	if _, ok := ctx.KernelBase(); ok {
		t.Error("a Linux session set a kernel base")
	}
	if want := linuxkernel.PagingMode(autoload.VMCoreInfoLayout{}).Name(); ctx.PagingMode() != want {
		t.Errorf("paging mode %q, want %q", ctx.PagingMode(), want)
	}
	banner, err := ctx.Symbols.LookupSymbol("linux_banner")
	if err != nil || banner.Address != lt.ArraysVA+lxBannerOff+lxShift {
		t.Errorf("linux_banner at 0x%x, %v", banner.Address, err)
	}
	if p, _ := ctx.Symbols.LookupSymbol("vmemmap_base"); p.Address != lxStoredPointer {
		t.Errorf("stored pointer moved to 0x%x", p.Address)
	}
	space, err := ctx.ProcessSpace(lt.PML4 | 0x7)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := space.ReadAt(banner.Address, 13); err != nil || string(got) != "Linux version" {
		t.Errorf("banner through a process space = %q, %v", got, err)
	}
	if !hasNote(s.Diagnostics(), "linux 6.17.0-s76", "banner matches", "VMCOREINFO symbols agree") {
		t.Errorf("notes %q", s.Diagnostics())
	}
}

func TestALinuxSessionRefusesATableThatIsNotTheKernels(t *testing.T) {
	other := []byte(strings.Replace(string(lxBanner), "#1", "#2", 1))
	for name, d := range map[string]symbols.Declaration{
		"another banner":   lxTable(other, lt.KernelBase),
		"no banner":        lxTable(nil, lt.KernelBase),
		"_stext elsewhere": lxTable(lxBanner, lt.KernelBase+0x1000),
	} {
		if _, err := openLinux(t, lxCapture(false), d, OpenConfig{}); err == nil || !strings.Contains(err.Error(), "does not match the kernel") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestALinuxRootGivenMustBeVMCoreInfos(t *testing.T) {
	d := lxTable(lxBanner, lt.KernelBase)
	if _, err := openLinux(t, lxCapture(false), d, OpenConfig{KernelCR3: lt.PML4 | 0x18}); err != nil {
		t.Errorf("root with flag bits: %v", err)
	}
	if _, err := openLinux(t, lxCapture(false), d, OpenConfig{KernelCR3: lt.PML5}); err == nil || !strings.Contains(err.Error(), "was given") {
		t.Errorf("another root: %v", err)
	}
}

func TestADamagedVMCoreInfoCopyFailsOnlyAStrictSession(t *testing.T) {
	d := lxTable(lxBanner, lt.KernelBase)
	s, err := openLinux(t, lxCapture(true), d, OpenConfig{CollectDiagnostics: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasNote(s.Diagnostics(), "0x80000") {
		t.Errorf("damaged copy not reported: %q", s.Diagnostics())
	}
	var damage *autoload.VMCoreInfoDamageError
	if _, err := openLinux(t, lxCapture(true), d, OpenConfig{Strict: true}); !errors.As(err, &damage) {
		t.Errorf("strict session: %v", err)
	}
}

func TestACaptureWithoutVMCoreInfoIsNotALinuxKernel(t *testing.T) {
	if _, err := openLinux(t, make([]byte, 1<<20), lxTable(lxBanner, lt.KernelBase), OpenConfig{}); !errors.Is(err, linuxkernel.ErrNoVMCoreInfo) {
		t.Errorf("no note: %v", err)
	}
}
