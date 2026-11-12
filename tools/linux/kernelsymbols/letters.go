package kernelsymbols

// The classes follow the kernel's own letter assignment for module symbols
// (elf_type); the core image's letters come from the build's link map, which
// uses the same letters, upper-case for global symbols.
var letterClass = map[byte]string{
	't': "code",
	'r': "read-only data",
	'd': "writable data",
	'g': "small writable data",
	'b': "zero-filled data",
	's': "small zero-filled data",
	'a': "absolute or per-CPU value",
	'U': "undefined",
	'v': "weak object",
	'w': "weak symbol",
	'n': "debugging information",
	'?': "unclassified",
}

func Describe(letter byte) string {
	if c, ok := letterClass[letter]; ok {
		return c
	}
	if 'A' <= letter && letter <= 'Z' {
		return letterClass[letter-'A'+'a']
	}
	return ""
}
