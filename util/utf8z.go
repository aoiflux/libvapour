package util

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// A NUL byte is a whole one-byte character in UTF-8, never part of another, so
// cutting at it before decoding splits no sequence.
func DecodeUTF8Z(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return DecodeUTF8Replace(b)
}

// Each maximal subpart of an ill-formed sequence becomes one U+FFFD, the
// Unicode recommended practice, so a sequence cut short reads as one damaged
// character rather than one per byte.
func DecodeUTF8Replace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var out strings.Builder
	out.Grow(len(b))
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n <= 1 {
			n = maximalSubpartLen(b)
		}
		out.WriteRune(r)
		b = b[n:]
	}
	return out.String()
}

func ReplaceInvalidUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return DecodeUTF8Replace([]byte(s))
}

// Well-formed UTF-8 byte sequences: the lead byte fixes the length and the
// range of the second byte; every later byte is 80..BF.
type utf8Lead struct {
	trailing           int
	secondLo, secondHi byte
}

func leadOf(c byte) (utf8Lead, bool) {
	switch {
	case c >= 0xC2 && c <= 0xDF:
		return utf8Lead{1, 0x80, 0xBF}, true
	case c == 0xE0:
		return utf8Lead{2, 0xA0, 0xBF}, true
	case c == 0xED:
		return utf8Lead{2, 0x80, 0x9F}, true
	case c >= 0xE1 && c <= 0xEF:
		return utf8Lead{2, 0x80, 0xBF}, true
	case c == 0xF0:
		return utf8Lead{3, 0x90, 0xBF}, true
	case c == 0xF4:
		return utf8Lead{3, 0x80, 0x8F}, true
	case c >= 0xF1 && c <= 0xF3:
		return utf8Lead{3, 0x80, 0xBF}, true
	}
	return utf8Lead{}, false
}

// Only called where b does not start with a well-formed sequence.
func maximalSubpartLen(b []byte) int {
	lead, ok := leadOf(b[0])
	if !ok {
		return 1
	}
	n := 1
	for n <= lead.trailing && n < len(b) {
		lo, hi := byte(0x80), byte(0xBF)
		if n == 1 {
			lo, hi = lead.secondLo, lead.secondHi
		}
		if b[n] < lo || b[n] > hi {
			break
		}
		n++
	}
	return n
}
