package ownerfiletest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aoiflux/libvapour/internal/ownerfile"
)

// A test of privacy proves nothing in a directory whose plain files are
// already private, so the directory is opened up and a plain file in it is
// checked to be readable by others before the test uses it.
func LooseDir(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	openUp(t, dir)
	probe := filepath.Join(dir, "probe.txt")
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatalf("ownerfiletest: write %s: %v", probe, err)
	}
	if err := os.Chmod(probe, 0o644); err != nil {
		t.Fatalf("ownerfiletest: chmod %s: %v", probe, err)
	}
	private, err := ownerfile.IsPrivate(probe)
	if err != nil {
		t.Fatalf("ownerfiletest: read access of %s: %v", probe, err)
	}
	if private {
		t.Fatalf("ownerfiletest: a plain file in %s is already private", dir)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatalf("ownerfiletest: remove %s: %v", probe, err)
	}
	return dir
}
