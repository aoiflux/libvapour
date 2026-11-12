package processenvironment

import (
	"strings"
	"testing"
)

func FuzzWindowsBlock(f *testing.F) {
	f.Add(utf16Block("=C:=C:\\", "A=1", ""))
	f.Add([]byte{0x41})
	f.Fuzz(func(t *testing.T, raw []byte) {
		b := splitWindowsBlock(raw)
		for _, v := range b.vars {
			if v.name == "" || strings.Contains(v.name[1:], "=") {
				t.Fatalf("name %q", v.name)
			}
		}
	})
}

func FuzzLinuxArea(f *testing.F) {
	f.Add([]byte("A=1\x00B\x00\x00=c\x00"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		a := splitLinuxArea(raw)
		for _, v := range a.vars {
			if v.name == "" || strings.Contains(v.name, "=") {
				t.Fatalf("name %q", v.name)
			}
		}
	})
}
