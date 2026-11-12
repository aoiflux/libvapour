package generator

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// The kernel loads vmlinux BTF only when every struct, union, enum, typedef,
// member and constant name passes this test (btf_name_valid_identifier), so
// a name that fails it was not written by the kernel's build.
func identifier(name string, maxBytes int) bool {
	if name == "" || len(name) > maxBytes {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '_' || c == '.' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// INT and FLOAT names are not held to the identifier rule ("long unsigned
// int" has spaces), only to being text a table can write.
func scalarName(name string, maxBytes int) bool {
	if name == "" || len(name) > maxBytes || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

const (
	nameOpen   = "{"
	nameClose  = "}"
	nameSep    = ","
	nameElided = "..."
	suffixMark = "~"
	// Room kept under MaxNameBytes for a suffix of up to seven digits.
	suffixRoom = len(suffixMark) + 7
)

// '{' cannot appear in an identifier, so a name built here never equals a
// name the kernel wrote.
func memberListName(keyword string, names []string, maxBytes int) string {
	budget := max(maxBytes-suffixRoom, len(keyword)+len(nameOpen)+len(nameElided)+len(nameClose))
	var b strings.Builder
	b.WriteString(keyword)
	b.WriteString(nameOpen)
	for i, n := range names {
		sep := ""
		if i > 0 {
			sep = nameSep
		}
		rest := len(nameClose)
		if i < len(names)-1 {
			rest = len(nameSep) + len(nameElided) + len(nameClose)
		}
		if b.Len()+len(sep)+len(n)+rest > budget {
			if i > 0 {
				b.WriteString(nameSep)
			}
			b.WriteString(nameElided)
			break
		}
		b.WriteString(sep)
		b.WriteString(n)
	}
	b.WriteString(nameClose)
	return b.String()
}

func suffixed(name string, n int) string {
	return name + suffixMark + strconv.Itoa(n)
}
