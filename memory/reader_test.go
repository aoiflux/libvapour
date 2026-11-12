package memory

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func tempFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capture.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFileReaderServesExactSpans(t *testing.T) {
	data := pattern(10000, 3)
	r, err := NewFileMemoryReader(tempFile(t, data))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Size() != 10000 || !r.ImmutableSnapshot() || !IsImmutableSnapshot(r) {
		t.Fatalf("size %d immutable %v", r.Size(), r.ImmutableSnapshot())
	}
	got, err := r.ReadAt(9000, 1000)
	if err != nil || !bytes.Equal(got, data[9000:]) {
		t.Fatalf("tail read: %v", err)
	}
	if _, err := r.ReadAt(9001, 1000); !errors.Is(err, ErrOutOfBounds) {
		t.Errorf("read past the end: %v", err)
	}
	if _, err := r.ReadAt(^uint64(0), 2); !errors.Is(err, ErrOutOfBounds) {
		t.Errorf("wrapping read: %v", err)
	}
	if _, err := r.ReadAt(0, math.MaxUint64); !errors.Is(err, ErrSizeOverflow) {
		t.Errorf("oversized read: %v", err)
	}
	if b, err := r.ReadAt(1<<40, 0); err != nil || len(b) != 0 {
		t.Errorf("empty read: %v", err)
	}
}

func TestFileReaderRefusesWhatIsNotAFile(t *testing.T) {
	if _, err := NewFileMemoryReader(t.TempDir()); err == nil {
		t.Error("a directory opened")
	}
	if _, err := NewFileMemoryReader(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing path opened")
	}
	if _, err := NewFileMemoryReaderFromFile(nil); err == nil {
		t.Error("a nil file opened")
	}
}

type liveSource struct{ image }

func (liveSource) ImmutableSnapshot() bool { return false }

func TestOnlyAReaderThatSaysSoIsImmutable(t *testing.T) {
	if !IsImmutableSnapshot(image{1}) || IsImmutableSnapshot(liveSource{}) {
		t.Error("snapshot claim not followed")
	}
	if IsImmutableSnapshot(NewFallbackReader(image{1})) {
		t.Error("a reader without the method counted as immutable")
	}
}
