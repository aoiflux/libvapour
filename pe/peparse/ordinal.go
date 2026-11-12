package peparse

// 32-bit and 64-bit builds of one library number their exports apart, so the
// importer's width picks the table. Library names compare without ASCII case,
// as Windows matches them.
func OrdinalName(dll string, pe32Plus bool, ordinal uint16) (name string, ok bool) {
	names := ordinalNames32
	if pe32Plus {
		names = ordinalNames64
	}
	name, ok = names[foldASCII(dll)][ordinal]
	return name, ok
}

func HasOrdinalTable(dll string) bool {
	folded := foldASCII(dll)
	_, wide := ordinalNames64[folded]
	_, narrow := ordinalNames32[folded]
	return wide || narrow
}

func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
