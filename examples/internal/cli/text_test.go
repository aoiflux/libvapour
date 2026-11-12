package cli

import (
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// unescape is the reading the output promises: \\, \t, \n, \r, \xHH (one
// byte), \uHHHH and \UHHHHHHHH (one character); any other backslash is itself.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		next := s[i+1]
		if c, ok := map[byte]byte{'\\': '\\', 't': '\t', 'n': '\n', 'r': '\r'}[next]; ok {
			b.WriteByte(c)
			i++
			continue
		}
		digits := map[byte]int{'x': 2, 'u': 4, 'U': 8}[next]
		if digits > 0 && isHex(s[i+2:], digits) {
			v, _ := strconv.ParseUint(s[i+2:i+2+digits], 16, 32)
			if next == 'x' {
				b.WriteByte(byte(v))
			} else {
				b.WriteRune(rune(v))
			}
			i += 1 + digits
			continue
		}
		b.WriteByte('\\')
	}
	return b.String()
}

func checkText(t *testing.T, s string) {
	t.Helper()
	out := Text(s)
	for i := 0; i < len(out); i++ {
		if out[i] < 0x20 || out[i] > 0x7e {
			t.Fatalf("Text(%q) = %q holds byte %#x", s, out, out[i])
		}
	}
	if back := unescape(out); back != s {
		t.Fatalf("Text(%q) = %q reads back as %q", s, out, back)
	}
	for _, m := range markers {
		if strings.HasSuffix(out, m) {
			t.Fatalf("Text(%q) = %q ends in the marker %s", s, out, m)
		}
	}
}

func TestTextEscapesWhatATerminalWouldActOn(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Windows\System32\cmd.exe`: `C:\Windows\System32\cmd.exe`,
		"evil\x1b[2J":                 `evil\x1b[2J`,
		" lsass.exe ":                 `\x20lsass.exe\x20`,
		"a b":                         "a b",
		"tab\there\r\n":               `tab\there\r\n`,
		"\xff\xfe":                    `\xff\xfe`,
		"\x7f":                        `\x7f`,
		"文档":                          `\u6587\u6863`,
		"\U0001f600":                  `\U0001f600`,
		"\ufffd":                      `\ufffd`,
		`C:\temp`:                     `C:\\temp`,
		"C:\temp":                     `C:\temp`,
		`\x41`:                        `\\x41`,
		`\xg1`:                        `\xg1`,
		`end\`:                        `end\`,
		"x" + Unreadable:              `x\x3cunreadable>`,
		"<unreadable> later":          "<unreadable> later",
		"":                            "",
	} {
		if got := Text(in); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
		checkText(t, in)
	}
}

func TestDifferentStringsPrintDifferently(t *testing.T) {
	for _, pair := range [][2]string{
		{"lsass.exe", "lsass.exe "},
		{"svchost.exe", "svchost\u2024exe"},
		{`a\\tb`, "a\\\tb"},
		{`\`, `\\`},
		{`evil\x1b`, "evil\x1b"},
	} {
		if Text(pair[0]) == Text(pair[1]) {
			t.Errorf("%q and %q print alike as %q", pair[0], pair[1], Text(pair[0]))
		}
	}
}

func FuzzText(f *testing.F) {
	for _, seed := range []string{"", `C:\temp`, "C:\temp", `\\`, `\x41`, `\u00e9`, `\U0001F600`, " a ", `\ `,
		"x" + RestUnreadable, `\` + Unreadable, "\xed\xa0\x80", "文档"} {
		f.Add(seed)
	}
	f.Fuzz(checkText)
}

func TestCellsSayWhatDidNotRead(t *testing.T) {
	for _, tc := range []struct {
		got, want string
	}{
		{Cell("cmd.exe", false), "cmd.exe"},
		{Cell("", true), Unreadable},
		{Cell("C:\\Win", true), "C:\\Win" + RestUnreadable},
		{Decimal(uint64(4), false), "4"},
		{Decimal(true, true), Unreadable},
		{Hex(0x1000, false), "0x1000"},
		{Hex(0, true), Unreadable},
		{Time(time.Time{}, false), "-"},
		{Time(time.Date(2026, 5, 26, 20, 50, 39, 5, time.FixedZone("x", 3600)), false), "2026-05-26T19:50:39Z"},
		{Time(time.Now(), true), Unreadable},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
	for _, m := range markers {
		if Cell(m, false) == m || !utf8.ValidString(Cell(m, false)) {
			t.Errorf("the value %q prints as the marker", m)
		}
	}
}
