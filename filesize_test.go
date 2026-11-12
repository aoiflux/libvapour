package libvapour

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const maxRepositoryFileSize = 20 * 1000 * 1000

func TestNoRepositoryFileExceeds20MB(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	top, err := exec.Command(git, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skip("not a git work tree")
	}
	root := string(bytes.TrimSpace(top))
	cmd := exec.Command(git, "--no-optional-locks", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	seen := map[string]bool{}
	for name := range bytes.SplitSeq(out, []byte{0}) {
		if len(name) == 0 || seen[string(name)] {
			continue
		}
		seen[string(name)] = true
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(string(name))))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if info.Mode().IsRegular() && info.Size() > maxRepositoryFileSize {
			t.Errorf("%s is %d bytes, limit %d", name, info.Size(), maxRepositoryFileSize)
		}
	}
	if len(seen) == 0 {
		t.Fatal("git listed no files")
	}
}
