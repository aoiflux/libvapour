package libvapour

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/windows/network"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

// The kernel's own NtBuildNumber is preferred; the KUSER_SHARED_DATA copy is
// taken only when the same page reads NT 10.0, the version of every measured
// layout, so a page that is not the shared data is not taken for a build
// (S76 4.7).
func tcpipLayout(b winkernel.Build) (symbols.SymbolTable, error) {
	var tried []string
	if b.KernelErr == nil {
		t, err := network.LayoutForBuild(b.Kernel)
		if err == nil {
			return t, nil
		}
		tried = append(tried, fmt.Sprintf("kernel build %d: %v", b.Kernel, err))
	} else {
		tried = append(tried, fmt.Sprintf("kernel build: %v", b.KernelErr))
	}
	switch {
	case b.VersionErr != nil:
		tried = append(tried, fmt.Sprintf("shared build: %v", b.VersionErr))
	case b.Major != 10 || b.Minor != 0:
		tried = append(tried, fmt.Sprintf("shared build: nt version %d.%d is not 10.0", b.Major, b.Minor))
	case b.SharedErr != nil:
		tried = append(tried, fmt.Sprintf("shared build: %v", b.SharedErr))
	default:
		t, err := network.LayoutForBuild(b.Shared)
		if err == nil {
			return t, nil
		}
		tried = append(tried, fmt.Sprintf("shared build %d: %v", b.Shared, err))
	}
	return nil, fmt.Errorf("libvapour: no measured tcpip layout: %s", strings.Join(tried, "; "))
}
