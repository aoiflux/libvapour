//go:build !windows

package ownerfiletest

import (
	"os"
	"testing"
)

func openUp(t testing.TB, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("ownerfiletest: chmod %s: %v", dir, err)
	}
}
