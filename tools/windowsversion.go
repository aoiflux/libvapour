package tools

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools/winkernel"
)

// Object headers before Windows 8 have no InfoMask and no build before it
// was measured, so a scan there would find nothing instead of failing.
var ErrPoolScanUnsupportedBuild = errors.New("tools: pool scan needs windows 8 or later")

const (
	windows8Major = 6
	windows8Minor = 2
	windows8Build = 9200
)

func (c Context) RequirePoolScanBuild(tool string) error {
	if c.Memory == nil || c.Symbols == nil {
		return nil
	}
	b := winkernel.ReadBuild(tool, c.Memory, c.Symbols)
	// A zero major is a page of zeros: no Windows version is below 5.0.
	versionRead := b.VersionErr == nil && b.Major != 0
	buildRead := b.KernelErr == nil && b.Kernel != 0
	var older bool
	switch {
	case versionRead:
		older = b.Major < windows8Major || b.Major == windows8Major && b.Minor < windows8Minor
	case buildRead:
		older = b.Kernel < windows8Build
	default:
		reason := b.Missing()
		if reason == nil {
			reason = winkernel.ErrBuildUnread
		}
		c.AddDiagnostic("%s: windows build unread; pool scan not gated by build: %v", tool, reason)
		return nil
	}
	if !older {
		return nil
	}
	version, build := "unread", "unread"
	if versionRead {
		version = fmt.Sprintf("%d.%d", b.Major, b.Minor)
	}
	if buildRead {
		build = fmt.Sprint(b.Kernel)
	}
	err := fmt.Errorf("%s: windows %s build %s: %w", tool, version, build, ErrPoolScanUnsupportedBuild)
	c.AddDiagnostic("%v", err)
	return err
}
