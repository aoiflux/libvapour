package tools

import (
	"regexp"
	"strings"
	"testing"
)

func TestPatternOption(t *testing.T) {
	if re, err := opts().PatternOption("k", true); re != nil || err != nil {
		t.Errorf("absent: %v %v", re, err)
	}
	if re, err := opts("k", "").PatternOption("k", false); re != nil || err != nil {
		t.Errorf("empty: %v %v", re, err)
	}
	re, err := opts("k", `lsass\.exe$`).PatternOption("k", false)
	if err != nil || !re.MatchString("lsass.exe") || re.MatchString("LSASS.EXE") {
		t.Errorf("case-sensitive: %v %v", re, err)
	}
	re, err = opts("k", `lsass\.exe$`).PatternOption("k", true)
	if err != nil || !re.MatchString("LSASS.EXE") {
		t.Errorf("case-folded: %v %v", re, err)
	}
	_, err = opts("k", 3).PatternOption("k", false)
	wantWrongForm(t, "pattern type", err, "k")
}

func TestABackReferenceIsNotRE2(t *testing.T) {
	_, err := opts("k", `(a)\1`).PatternOption("k", true)
	wantWrongForm(t, "back-reference", err, "k")
	if err != nil && (!strings.Contains(err.Error(), `"(a)\\1"`) || strings.Contains(err.Error(), "(?i)(a)")) {
		t.Errorf("%v: the message must quote the examiner's text without the flag", err)
	}
}

func FuzzPatternOption(f *testing.F) {
	for _, s := range []string{"", "a", `(a)\1`, "[", "(?i)x", `\p{Greek}`} {
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, text string, fold bool) {
		re, err := opts("k", text).PatternOption("k", fold)
		if err != nil {
			wantWrongForm(t, "fuzz", err, "k")
			return
		}
		if text == "" {
			if re != nil {
				t.Fatal("empty text gave a pattern")
			}
			return
		}
		if _, plain := regexp.Compile(text); plain != nil && !fold {
			t.Fatalf("%q accepted but does not compile", text)
		}
	})
}
