package cli

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Unreadable     = "<unreadable>"
	RestUnreadable = "<rest unreadable>"
	EmptyCmdline   = "<empty>"
	NoName         = "<no name>"
	Unbacked       = "<unbacked>"
	NotListed      = "<not listed>"
)

var markers = []string{Unreadable, RestUnreadable, EmptyCmdline, NoName, Unbacked, NotListed}

// The output is printable ASCII that reads back to the same bytes, so no byte
// from an image reaches the terminal as a control and two different names
// never print alike. Edge spaces are escaped because "lsass.exe " must not pass
// for "lsass.exe", and a trailing marker's "<" so image data never prints as a
// marker.
func Text(s string) string {
	pieces := make([]string, 0, len(s))
	for i := 0; i < len(s); {
		piece, n := escape(s, i)
		pieces = append(pieces, piece)
		i += n
	}
	var b strings.Builder
	for i, piece := range pieces {
		if piece == `\` && escapeFollows(pieces[i+1:]) {
			piece = `\\`
		}
		b.WriteString(piece)
	}
	return b.String()
}

func escape(s string, i int) (string, int) {
	r, n := utf8.DecodeRuneInString(s[i:])
	switch {
	case r == utf8.RuneError && n == 1:
		return fmt.Sprintf(`\x%02x`, s[i]), 1
	case r == ' ' && (i == 0 || i == len(s)-1):
		return `\x20`, 1
	case r == '<' && slices.Contains(markers, s[i:]):
		return `\x3c`, 1
	case r == '\t':
		return `\t`, 1
	case r == '\n':
		return `\n`, 1
	case r == '\r':
		return `\r`, 1
	case r >= 0x20 && r < 0x7f:
		return s[i : i+1], 1
	case r < 0x80:
		return fmt.Sprintf(`\x%02x`, r), 1
	case r < 0x10000:
		return fmt.Sprintf(`\u%04x`, r), n
	}
	return fmt.Sprintf(`\U%08x`, r), n
}

// A backslash is doubled only when the text after it would read as an
// escape; elsewhere it stands for itself, so Windows paths stay readable.
func escapeFollows(rest []string) bool {
	var next strings.Builder
	for _, p := range rest {
		if next.Len() >= 9 {
			break
		}
		next.WriteString(p)
	}
	after := next.String()
	if after == "" {
		return false
	}
	switch after[0] {
	case '\\', 't', 'n', 'r':
		return true
	case 'x':
		return isHex(after[1:], 2)
	case 'u':
		return isHex(after[1:], 4)
	case 'U':
		return isHex(after[1:], 8)
	}
	return false
}

func isHex(s string, n int) bool {
	if len(s) < n {
		return false
	}
	for i := range n {
		if !strings.ContainsRune("0123456789abcdefABCDEF", rune(s[i])) {
			return false
		}
	}
	return true
}

func Cell(s string, unreadable bool) string {
	switch {
	case !unreadable:
		return Text(s)
	case s == "":
		return Unreadable
	}
	return Text(s) + RestUnreadable
}

func Decimal[T uint32 | uint64 | int64 | bool](v T, unreadable bool) string {
	if unreadable {
		return Unreadable
	}
	return fmt.Sprint(v)
}

func Time(t time.Time, unreadable bool) string {
	switch {
	case unreadable:
		return Unreadable
	case t.IsZero():
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func Hex(v uint64, unreadable bool) string {
	if unreadable {
		return Unreadable
	}
	return fmt.Sprintf("0x%x", v)
}
