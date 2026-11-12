package extract

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aoiflux/libvapour/internal/ownerfile"
)

// An existing file is never replaced: it may be an artefact from an earlier
// run, and replacing it destroys evidence.
var ErrArtifactExists = errors.New("extract: artifact already exists")

var errEmptyName = errors.New("extract: empty artifact name")

const maxNameBytes = 255

// Checked on every host, not only on Windows: a result set written on one
// host may be opened on another.
func IsDeviceName(path string) bool {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		path = path[i+1:]
	}
	stem, _, _ := strings.Cut(path, ".")
	stem = strings.ToUpper(strings.TrimRight(stem, " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if !strings.HasPrefix(stem, "COM") && !strings.HasPrefix(stem, "LPT") {
		return false
	}
	switch strings.TrimPrefix(strings.TrimPrefix(stem, "COM"), "LPT") {
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
		return true
	}
	return false
}

// safeName is applied at the filesystem boundary even to names built by
// Name, because a caller may pass a string of its own.
func safeName(name string) (string, error) {
	out := portable(name)
	if out == "" {
		return "", errEmptyName
	}
	if out[0] == '.' || out[0] == '-' || IsDeviceName(out) {
		out = "_" + out
	}
	if strings.HasSuffix(out, ".") {
		out = strings.TrimRight(out, ".") + "_"
	}
	if len(out) > maxNameBytes {
		return "", fmt.Errorf("extract: artifact name is %d bytes, over %d", len(out), maxNameBytes)
	}
	return out, nil
}

// The artefact, and any directory created for it, is private to the current
// user: a dump of lsass or a SAM hive can hold credentials. On Windows a mode
// restricts nothing, so internal/ownerfile sets a protected access list.
func CreateNew(dir, name string) (*os.File, error) {
	clean, err := safeName(name)
	if err != nil {
		return nil, err
	}
	if dir != "" {
		if err := ownerfile.MkdirAll(dir); err != nil {
			return nil, fmt.Errorf("extract: create output directory %q: %w", dir, err)
		}
	}
	path := filepath.Join(dir, clean)
	f, err := ownerfile.CreateNew(path)
	if errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("%w: %s", ErrArtifactExists, path)
	}
	if err != nil {
		return nil, fmt.Errorf("extract: create artifact %s: %w", path, err)
	}
	return f, nil
}

func CreateUnique(dir, name string, attempts int) (*os.File, string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	candidate := name
	for n := 1; ; n++ {
		clean, err := safeName(candidate)
		if err != nil {
			return nil, "", err
		}
		f, err := CreateNew(dir, candidate)
		if err == nil {
			return f, clean, nil
		}
		if !errors.Is(err, ErrArtifactExists) {
			return nil, clean, err
		}
		if n >= attempts {
			return nil, clean, fmt.Errorf("%w; %d further names were taken too, NameAttempts (%d) in all", err, n-1, attempts)
		}
		candidate = fmt.Sprintf("%s-%d%s", stem, n, ext)
	}
}

func RemoveArtifact(dir, name string) error {
	clean, err := safeName(name)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, clean)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("extract: remove partial artifact %s: %w", clean, err)
	}
	return nil
}
