package processhollowing

import (
	"fmt"
	"strings"
)

type namedPath struct {
	source string
	path   string
}

// Device and volume prefixes differ between the three names by design (a view
// names its file below the volume, the audit name above it), so only the last
// component is compared.
func lastComponent(path string) string {
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		return path[i+1:]
	}
	return path
}

func lastComponentsDiffer(names []namedPath) (string, bool) {
	if len(names) < 2 {
		return "", false
	}
	first := lastComponent(names[0].path)
	differ := false
	for _, n := range names[1:] {
		if !strings.EqualFold(first, lastComponent(n.path)) {
			differ = true
		}
	}
	if !differ {
		return "", false
	}
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s %q", n.source, n.path))
	}
	return strings.Join(parts, ", "), true
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// ImageFileName holds the first capacity bytes of the file's last component;
// its encoding is not documented, so names outside ASCII are not compared.
func imageFileNameMatches(imageFileName, component string, capacity int) bool {
	if !ascii(imageFileName) || !ascii(component) || capacity <= 0 {
		return true
	}
	if len(component) > capacity {
		component = component[:capacity]
	}
	return strings.EqualFold(imageFileName, component)
}
