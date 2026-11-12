package libvapour

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)

func TestVersionIsASemanticVersion(t *testing.T) {
	if !semver.MatchString(Version) {
		t.Fatalf("Version = %q, want MAJOR.MINOR.PATCH", Version)
	}
}

func TestTheReadmeStatesTheVersion(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read the README: %v", err)
	}
	want := "libvapour is at **v" + Version + "**."
	if !strings.Contains(string(data), want) {
		t.Fatalf("README lacks %q; update its Project status line", want)
	}
}
