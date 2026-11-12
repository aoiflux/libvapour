package processidentity

import (
	"errors"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/tools/any/processlist"
)

var ErrNoRoot = errors.New("processidentity: process has no page-table root")

// The kernel keeps at most the array length less its terminator (S43 M7).
const shortNameBytes = processlist.WindowsImageNameLength - 1

const terminatorBytes = 2

func lastComponent(path string) string {
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		return path[i+1:]
	}
	return path
}

func asciiFold(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func nameDiffers(name, kernelPath string) bool {
	file := lastComponent(kernelPath)
	if name == "" || file == "" {
		return false
	}
	if len(file) > shortNameBytes {
		file = file[:shortNameBytes]
	}
	return asciiFold(name) != asciiFold(file)
}

// volumeTail strips the volume: a drive letter from a Win32 path, the device
// name from an NT path (S68 M4).
func volumeTail(path string) (string, bool) {
	switch {
	case len(path) >= 3 && path[1] == ':' && path[2] == '\\':
		return path[2:], true
	case strings.HasPrefix(path, `\Device\`):
		rest := path[len(`\Device\`):]
		if i := strings.IndexByte(rest, '\\'); i > 0 {
			return rest[i:], true
		}
	}
	return "", false
}

func pathsDiffer(imagePath, kernelPath string) bool {
	if imagePath == "" || kernelPath == "" {
		return false
	}
	a, okA := volumeTail(imagePath)
	b, okB := volumeTail(kernelPath)
	if !okA || !okB {
		a, b = lastComponent(imagePath), lastComponent(kernelPath)
	}
	return !strings.EqualFold(a, b)
}

// The process parameter block is built in one allocation, each string placed
// inside it with a NUL after its text and a capacity of exactly that NUL more
// (S68 M5, M6). A string replaced after creation loses one of these.
func rewritten(s counted, params, blockEnd uint64, commandLine bool) bool {
	if s.Length == 0 && s.Buffer == 0 {
		return false
	}
	if s.Length%2 != 0 || uint32(s.MaximumLength) != uint32(s.Length)+terminatorBytes {
		return true
	}
	if blockEnd > params && (s.Buffer < params || s.Buffer+uint64(s.MaximumLength) > blockEnd) {
		return true
	}
	n := int(s.Length / 2)
	if n < len(s.units) && s.units[n] != 0 {
		return true
	}
	// Some command lines carry NUL-separated arguments (S68 M6); an image path
	// never does.
	if !commandLine && slices.Contains(s.units[:min(n, len(s.units))], 0) {
		return true
	}
	return false
}
