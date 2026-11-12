package ownerfile_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/aoiflux/libvapour/internal/ownerfile"
	"github.com/aoiflux/libvapour/internal/ownerfile/ownerfiletest"
)

func write(t *testing.T, open func(string) (*os.File, error), path, text string) {
	t.Helper()
	f, err := open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if _, err := io.WriteString(f, text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != text {
		t.Fatalf("%s holds %q (%v), want %q", path, got, err, text)
	}
}

func private(t *testing.T, path string) {
	t.Helper()
	ok, err := ownerfile.IsPrivate(path)
	if err != nil || !ok {
		t.Errorf("%s private %v (%v)", path, ok, err)
	}
}

func TestEverythingCreatedIsPrivateInAnOpenDirectory(t *testing.T) {
	dir := ownerfiletest.LooseDir(t)
	nested := filepath.Join(dir, "x", "y", "z")
	if err := ownerfile.MkdirAll(nested); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(nested, "fresh.bin")
	write(t, ownerfile.CreateNew, fresh, "fresh")
	earlier := filepath.Join(dir, "earlier.txt")
	if err := os.WriteFile(earlier, []byte("a longer earlier text"), 0o644); err != nil {
		t.Fatal(err)
	}
	write(t, ownerfile.Create, earlier, "later")
	replaced := filepath.Join(nested, "replaced.txt")
	write(t, ownerfile.Create, replaced, "one")
	write(t, ownerfile.Create, replaced, "two")
	for _, p := range []string{filepath.Join(dir, "x"), filepath.Join(dir, "x", "y"), nested, fresh, earlier, replaced} {
		private(t, p)
	}
}

func TestCreateNewRefusesWhatExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taken")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := ownerfile.CreateNew(path); !errors.Is(err, os.ErrExist) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("CreateNew on an existing file: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "keep" {
		t.Errorf("existing file changed to %q", got)
	}
}

func TestMkdirAllKeepsWhatExists(t *testing.T) {
	dir := ownerfiletest.LooseDir(t)
	if err := ownerfile.MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	if ok, _ := ownerfile.IsPrivate(dir); ok {
		t.Error("an existing open directory was narrowed")
	}
	file := filepath.Join(dir, "plain")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ownerfile.MkdirAll(filepath.Join(file, "below")); err == nil {
		t.Error("a directory below a file was created")
	}
	if err := ownerfile.MkdirAll(file); err == nil {
		t.Error("a file was taken as a directory")
	}
}

func TestCreateOpensADeviceAsItIs(t *testing.T) {
	f, err := ownerfile.Create(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("discarded"); err != nil {
		t.Error(err)
	}
	f.Close()
	if ok, _ := ownerfile.IsPrivate(os.DevNull); ok {
		t.Errorf("%s was made private", os.DevNull)
	}
}

func TestIsPrivateOfAMissingPathIsAnError(t *testing.T) {
	if _, err := ownerfile.IsPrivate(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("no error")
	}
}
