package symbols

import (
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// A strict reader of the JSON subset the table format uses (RFC 8259): every
// value is read into the type the format gives it, so a key written twice, a
// null, a fraction or an exponent is refused rather than read as something
// else.
type scanner struct {
	data []byte
	pos  int
}

type scanError struct {
	at  int
	msg string
}

func (e *scanError) Error() string { return fmt.Sprintf("at byte %d: %s", e.at, e.msg) }

func (s *scanner) fail(format string, args ...any) error {
	return &scanError{at: s.pos, msg: fmt.Sprintf(format, args...)}
}

func (s *scanner) space() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

func (s *scanner) peek() byte {
	s.space()
	if s.pos >= len(s.data) {
		return 0
	}
	return s.data[s.pos]
}

func (s *scanner) want(c byte, what string) error {
	if s.peek() != c {
		return s.fail("want %s", what)
	}
	s.pos++
	return nil
}

// Calls field once per key. A key seen twice is refused before field sees it.
func (s *scanner) object(field func(key string) error) error {
	if err := s.want('{', "an object"); err != nil {
		return err
	}
	var seen []string
	if s.peek() == '}' {
		s.pos++
		return nil
	}
	for {
		key, err := s.str()
		if err != nil {
			return err
		}
		for _, k := range seen {
			if k == key {
				return s.fail("key %q written twice", key)
			}
		}
		seen = append(seen, key)
		if err := s.want(':', "a colon after the key"); err != nil {
			return err
		}
		if err := field(key); err != nil {
			return err
		}
		switch s.peek() {
		case ',':
			s.pos++
		case '}':
			s.pos++
			return nil
		default:
			return s.fail("want a comma or the end of the object")
		}
	}
}

func (s *scanner) array(item func() error) error {
	if err := s.want('[', "a list"); err != nil {
		return err
	}
	if s.peek() == ']' {
		s.pos++
		return nil
	}
	for {
		if err := item(); err != nil {
			return err
		}
		switch s.peek() {
		case ',':
			s.pos++
		case ']':
			s.pos++
			return nil
		default:
			return s.fail("want a comma or the end of the list")
		}
	}
}

func (s *scanner) str() (string, error) {
	if s.peek() != '"' {
		return "", s.fail("want a string")
	}
	s.pos++
	start := s.pos
	for s.pos < len(s.data) {
		c := s.data[s.pos]
		switch {
		case c == '"':
			raw := s.data[start:s.pos]
			if !utf8.Valid(raw) {
				return "", s.fail("string is not UTF-8")
			}
			s.pos++
			return string(raw), nil
		case c == '\\':
			return s.escapedString(start)
		case c < 0x20:
			return "", s.fail("control character 0x%02x in a string", c)
		}
		s.pos++
	}
	return "", s.fail("string has no end")
}

func (s *scanner) escapedString(start int) (string, error) {
	out := append([]byte(nil), s.data[start:s.pos]...)
	for s.pos < len(s.data) {
		c := s.data[s.pos]
		switch {
		case c == '"':
			if !utf8.Valid(out) {
				return "", s.fail("string is not UTF-8")
			}
			s.pos++
			return string(out), nil
		case c < 0x20:
			return "", s.fail("control character 0x%02x in a string", c)
		case c != '\\':
			out = append(out, c)
			s.pos++
			continue
		}
		if s.pos+1 >= len(s.data) {
			return "", s.fail("string has no end")
		}
		e := s.data[s.pos+1]
		s.pos += 2
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, err := s.hex4()
			if err != nil {
				return "", err
			}
			if utf16.IsSurrogate(r) {
				if r >= 0xdc00 || s.pos+1 >= len(s.data) || s.data[s.pos] != '\\' || s.data[s.pos+1] != 'u' {
					return "", s.fail("unpaired surrogate \\u%04x", r)
				}
				s.pos += 2
				low, err := s.hex4()
				if err != nil {
					return "", err
				}
				if r = utf16.DecodeRune(r, low); r == utf8.RuneError {
					return "", s.fail("unpaired surrogate")
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			return "", s.fail("unknown escape \\%c", e)
		}
	}
	return "", s.fail("string has no end")
}

func (s *scanner) hex4() (rune, error) {
	if s.pos+4 > len(s.data) {
		return 0, s.fail("short \\u escape")
	}
	v, err := strconv.ParseUint(string(s.data[s.pos:s.pos+4]), 16, 16)
	if err != nil {
		return 0, s.fail("bad \\u escape")
	}
	s.pos += 4
	return rune(v), nil
}

// The digits of an integer: an optional minus, then 0 or a digit string with
// no leading zero, and no fraction or exponent after it.
func (s *scanner) integer() (negative bool, digits []byte, err error) {
	s.space()
	start := s.pos
	if s.pos < len(s.data) && s.data[s.pos] == '-' {
		negative = true
		s.pos++
	}
	first := s.pos
	for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
		s.pos++
	}
	digits = s.data[first:s.pos]
	switch {
	case len(digits) == 0:
		s.pos = start
		return false, nil, s.fail("want an integer")
	case len(digits) > 1 && digits[0] == '0':
		return false, nil, s.fail("integer with a leading zero")
	case s.pos < len(s.data) && (s.data[s.pos] == '.' || s.data[s.pos] == 'e' || s.data[s.pos] == 'E'):
		return false, nil, s.fail("number is not an integer")
	}
	return negative, digits, nil
}

func (s *scanner) unsigned() (uint64, error) {
	negative, digits, err := s.integer()
	if err != nil {
		return 0, err
	}
	if negative {
		return 0, s.fail("negative number where the format has an unsigned one")
	}
	v, err := strconv.ParseUint(string(digits), 10, 64)
	if err != nil {
		return 0, s.fail("%s is past 64 bits", digits)
	}
	return v, nil
}

func (s *scanner) signed() (int64, error) {
	negative, digits, err := s.integer()
	if err != nil {
		return 0, err
	}
	text := string(digits)
	if negative {
		text = "-" + text
	}
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, s.fail("%s is past 64 signed bits", text)
	}
	return v, nil
}

func (s *scanner) boolean() (bool, error) {
	s.space()
	switch {
	case s.literal("true"):
		return true, nil
	case s.literal("false"):
		return false, nil
	}
	return false, s.fail("want true or false")
}

func (s *scanner) literal(word string) bool {
	if len(s.data)-s.pos >= len(word) && string(s.data[s.pos:s.pos+len(word)]) == word {
		s.pos += len(word)
		return true
	}
	return false
}

// Steps over one value of any shape, so that a file in another layout can be
// told apart from a broken table. Nesting is bounded because each level is a
// call.
const maxSkipDepth = 256

func (s *scanner) skip(depth int) error {
	if depth > maxSkipDepth {
		return s.fail("values nest deeper than %d", maxSkipDepth)
	}
	switch c := s.peek(); {
	case c == '{':
		return s.object(func(string) error { return s.skip(depth + 1) })
	case c == '[':
		return s.array(func() error { return s.skip(depth + 1) })
	case c == '"':
		_, err := s.str()
		return err
	case c == '-' || c >= '0' && c <= '9':
		s.pos++
		for s.pos < len(s.data) && bytesIn(s.data[s.pos], "0123456789.eE+-") {
			s.pos++
		}
		return nil
	case s.literal("true"), s.literal("false"), s.literal("null"):
		return nil
	}
	return s.fail("want a value")
}

func bytesIn(c byte, set string) bool {
	for i := 0; i < len(set); i++ {
		if set[i] == c {
			return true
		}
	}
	return false
}

var errTrailing = errors.New("data follows the table")
