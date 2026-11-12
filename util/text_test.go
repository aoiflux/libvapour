package util

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf16"
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const rc = "\uFFFD"

func TestUTF8ReplacementFollowsTheUnicodeSubstitutionTables(t *testing.T) {
	for _, c := range []struct {
		table, in, want string
	}{
		{"3-8 non-shortest forms", "C0 AF E0 80 BF F0 81 82 41", strings.Repeat(rc, 8) + "A"},
		{"3-9 surrogates", "ED A0 80 ED BF BF ED AF 41", strings.Repeat(rc, 8) + "A"},
		{"3-10 other", "F4 91 92 93 FF 41 80 BF 42", strings.Repeat(rc, 5) + "A" + rc + rc + "B"},
		{"3-11 truncated", "E1 80 E2 F0 91 92 F1 BF 41", strings.Repeat(rc, 4) + "A"},
		{"well-formed passes", "41 C3 A9 E2 82 AC F0 9F 98 80", "Aé€😀"},
		{"NUL is kept", "41 00 42", "A\x00B"},
	} {
		if got := DecodeUTF8Replace(hexBytes(t, c.in)); got != c.want {
			t.Errorf("table %s: %q, want %q", c.table, got, c.want)
		}
		if got := ReplaceInvalidUTF8(string(hexBytes(t, c.in))); got != c.want {
			t.Errorf("table %s via string: %q, want %q", c.table, got, c.want)
		}
	}
}

func TestDecodeUTF8ZCutsAtTheFirstNUL(t *testing.T) {
	if got := DecodeUTF8Z([]byte("init\x00garbage")); got != "init" {
		t.Errorf("%q", got)
	}
	if got := DecodeUTF8Z([]byte{0xE2, 0x82, 0x00, 'x'}); got != rc {
		t.Errorf("a sequence cut by NUL: %q, want one U+FFFD", got)
	}
	if got := DecodeUTF8Z([]byte("no terminator")); got != "no terminator" {
		t.Errorf("%q", got)
	}
}

func utf16le(units ...uint16) []byte {
	var b []byte
	for _, u := range units {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

func TestUTF16DecodingOfPairsAndIllFormedUnits(t *testing.T) {
	pair := utf16.Encode([]rune("😀"))
	for _, c := range []struct {
		name string
		in   []byte
		full string
		z    string
	}{
		{"BMP text", utf16le('C', ':', '\\'), `C:\`, `C:\`},
		{"surrogate pair", utf16le(pair[0], pair[1]), "😀", "😀"},
		{"lone high surrogate", utf16le(0xD800, 'a'), rc + "a", rc + "a"},
		{"lone low surrogate", utf16le('a', 0xDC00), "a" + rc, "a" + rc},
		{"embedded NUL", utf16le('a', 0, 'b'), "a\x00b", "a"},
		{"odd final byte", append(utf16le('a'), 'b'), "a" + rc, "a" + rc},
		{"high surrogate then odd byte", append(utf16le('a', 0xD83D), 0x00), "a" + rc, "a" + rc},
		{"low surrogate then odd byte", append(utf16le(0xDC00), 0x00), rc + rc, rc + rc},
		{"NUL before odd byte", append(utf16le('a', 0), 'x'), "a\x00" + rc, "a"},
		{"empty", nil, "", ""},
	} {
		if got := DecodeUTF16LE(c.in); got != c.full {
			t.Errorf("%s: DecodeUTF16LE %q, want %q", c.name, got, c.full)
		}
		if got := DecodeUTF16LEZ(c.in); got != c.z {
			t.Errorf("%s: DecodeUTF16LEZ %q, want %q", c.name, got, c.z)
		}
	}
}

func TestCountedTextDropsTheTerminatorAndShowsInnerNULs(t *testing.T) {
	for in, want := range map[string]string{
		"cmd.exe\x00":    "cmd.exe",
		"a\x00b\x00\x00": "a" + VisibleNUL + "b",
		"\x00hidden":     VisibleNUL + "hidden",
		`\Sessions\0\`:   `\Sessions\0\`,
		"":               "",
		"\x00\x00":       "",
	} {
		if got := CountedText(in); got != want {
			t.Errorf("CountedText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := DecodeCountedUTF16LE(utf16le('a', 0, 'b', 0)); got != "a"+VisibleNUL+"b" {
		t.Errorf("DecodeCountedUTF16LE: %q", got)
	}
}
