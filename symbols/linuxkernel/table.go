package linuxkernel

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/symbols/generator"
)

// __START_KERNEL_map and KERNEL_IMAGE_SIZE with KASLR configured: the window
// the kernel image is linked and randomised within.
const (
	kernelMapStart = 0xffffffff80000000
	kernelMapSize  = 1 << 30
)

func InKernelImage(address uint64) bool {
	return address >= kernelMapStart && address-kernelMapStart < kernelMapSize
}

var ErrNoBanner = errors.New("linuxkernel: table holds no linux_banner constant")

// The kernel's own banner at the table's linux_banner checks the table and the
// KASLR shift at once. SYMBOL() values outside the image window, such as
// mem_section, are stored pointers rather than symbol addresses, and are not
// compared.
func (k Kernel) CheckTable(running symbols.SymbolTable, banner []byte) (int, error) {
	if len(banner) == 0 {
		return 0, ErrNoBanner
	}
	at, err := running.LookupSymbol("linux_banner")
	if err != nil {
		return 0, fmt.Errorf("linuxkernel: table holds no linux_banner symbol: %w", err)
	}
	read, _, err := autoload.ReadLinuxBanner(k.Space, at.Address, k.Limits)
	if err != nil {
		return 0, fmt.Errorf("linuxkernel: linux_banner at 0x%x: no kernel banner: %w", at.Address, err)
	}
	if !bytes.Equal(bytes.TrimSuffix(read, []byte{0}), bytes.TrimSuffix(banner, []byte{0})) {
		return 0, fmt.Errorf("linuxkernel: table banner %q differs from kernel banner %q", printable(banner), printable(read))
	}
	agreed := 0
	for _, e := range k.VMCoreInfo.Entries {
		name, ok := strings.CutPrefix(e.Key, "SYMBOL(")
		if !ok {
			continue
		}
		if name, ok = strings.CutSuffix(name, ")"); !ok || e.Cut || e.Int == nil || !e.Int.IsUint64() {
			continue
		}
		want := e.Int.Uint64()
		if !InKernelImage(want) {
			continue
		}
		s, err := running.LookupSymbol(name)
		if err != nil {
			continue
		}
		if s.Address != want {
			return agreed, fmt.Errorf("linuxkernel: %s at 0x%x in VMCOREINFO, 0x%x in the table shifted by 0x%x",
				name, want, s.Address, k.Layout.VirtualShift)
		}
		agreed++
	}
	return agreed, nil
}

func printable(b []byte) string {
	return strings.TrimRight(string(b), "\n\x00")
}

func (k Kernel) AssembledTable(name string) (*symbols.Table, generator.LinuxReport, error) {
	d, report, err := k.Declaration()
	if err != nil {
		return nil, report, fmt.Errorf("linuxkernel: assemble table: %w", err)
	}
	table, err := symbols.BuildWith(name, d, symbols.ReadOptions{MaxTableEntries: k.Limits.MaxTableEntries})
	if err != nil {
		return nil, report, fmt.Errorf("linuxkernel: build table: %w", err)
	}
	return table, report, nil
}
