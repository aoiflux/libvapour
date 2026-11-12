//go:build windows

package ownerfiletest

import (
	"testing"

	"golang.org/x/sys/windows"
)

// BUILTIN\Users (BU) gets read access that files created inside inherit; the
// list stays unprotected so the parent's entries apply too.
func openUp(t testing.TB, dir string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:(A;OICI;FR;;;BU)")
	if err != nil {
		t.Fatalf("ownerfiletest: open descriptor: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("ownerfiletest: open descriptor list: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("ownerfiletest: open up %s: %v", dir, err)
	}
}
