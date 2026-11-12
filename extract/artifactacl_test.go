package extract

import (
	"path/filepath"
	"testing"

	"github.com/aoiflux/libvapour/internal/ownerfile"
	"github.com/aoiflux/libvapour/internal/ownerfile/ownerfiletest"
)

func TestAnArtifactIsOpenToItsOwnerAlone(t *testing.T) {
	const name = "process.pid660.0xffff9e0812345000.lsass.exe.dmp"
	create := func(t *testing.T, dir string) {
		t.Helper()
		f, err := CreateNew(dir, name)
		if err != nil {
			t.Fatalf("CreateNew: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
	assertPrivate := func(t *testing.T, paths ...string) {
		t.Helper()
		for _, p := range paths {
			private, err := ownerfile.IsPrivate(p)
			if err != nil {
				t.Fatalf("IsPrivate(%s): %v", p, err)
			}
			if !private {
				t.Errorf("%s is open to another account", p)
			}
		}
	}

	t.Run("in directories CreateNew creates", func(t *testing.T) {
		dir := filepath.Join(ownerfiletest.LooseDir(t), "out", "nested")
		create(t, dir)
		assertPrivate(t, filepath.Join(dir, name), dir, filepath.Dir(dir))
	})
	t.Run("in a directory that is already there", func(t *testing.T) {
		dir := ownerfiletest.LooseDir(t)
		create(t, dir)
		assertPrivate(t, filepath.Join(dir, name))
	})
}
