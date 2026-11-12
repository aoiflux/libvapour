//go:build !windows

package ownerfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aoiflux/libvapour/internal/ownerfile"
)

func TestModesAreOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	if err := ownerfile.MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "f")
	write(t, ownerfile.CreateNew, file, "x")
	for p, want := range map[string]os.FileMode{dir: 0o700, file: 0o600} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got&^want != 0 {
			t.Errorf("%s mode %o, want within %o", p, got, want)
		}
	}
	if err := os.Chmod(file, 0o640); err != nil {
		t.Fatal(err)
	}
	write(t, ownerfile.Create, file, "y")
	if info, _ := os.Stat(file); info.Mode().Perm() != 0o600 {
		t.Errorf("Create left mode %o", info.Mode().Perm())
	}
}

func TestIsPrivateLooksAtGroupAndOtherBits(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for mode, want := range map[os.FileMode]bool{0o600: true, 0o700: true, 0o400: true, 0o640: false, 0o604: false, 0o610: false, 0o601: false} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		if got, err := ownerfile.IsPrivate(file); err != nil || got != want {
			t.Errorf("mode %o: %v %v, want %v", mode, got, err, want)
		}
	}
}

func TestCreateNewRefusesASymbolicLink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "target"), link); err != nil {
		t.Skip(err)
	}
	if f, err := ownerfile.CreateNew(link); err == nil {
		f.Close()
		t.Error("CreateNew followed a dangling link")
	}
	if _, err := os.Lstat(filepath.Join(dir, "target")); err == nil {
		t.Error("the link's target was created")
	}
}
