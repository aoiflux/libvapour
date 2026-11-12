//go:build !windows

package extract

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnArtifactIsReadableByItsOwnerAlone(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "out", "nested")
	f, err := CreateNew(dir, "process.pid660.0xffff9e0812345000.lsass.exe.dmp")
	if err != nil {
		t.Fatalf("CreateNew: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "process.pid660.0xffff9e0812345000.lsass.exe.dmp"))
	if err != nil {
		t.Fatalf("stat the artifact: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("artifact mode = %#o, want 0600", got)
	}
	for _, d := range []string{dir, filepath.Dir(dir)} {
		di, err := os.Stat(d)
		if err != nil {
			t.Fatalf("stat %s: %v", d, err)
		}
		if got := di.Mode().Perm(); got != 0o700 {
			t.Errorf("created directory %s mode = %#o, want 0700", d, got)
		}
	}
}
