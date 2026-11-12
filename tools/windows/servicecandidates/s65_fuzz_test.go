package servicecandidates

import (
	"strings"
	"testing"
)

func FuzzCommandLine(f *testing.F) {
	f.Add(`"C:\a b\svchost.exe" -k "x y" -s z`)
	f.Fuzz(func(t *testing.T, line string) {
		args := splitCommandLine(line)
		if strings.Contains(line, `"`) {
			return
		}
		for _, a := range args {
			if strings.ContainsAny(a, " \t") || a == "" {
				t.Fatalf("argument %q of %q", a, line)
			}
		}
	})
}
