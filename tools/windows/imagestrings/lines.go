package imagestrings

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

type Line struct {
	Number int
	Offset uint64
	Text   string
}

type Rejected struct {
	Number int
	Reason string
}

var ErrTooManyLines = errors.New("imagestrings: strings file has more lines than the row limit")

func ParseLine(raw []byte) (offset uint64, text string, reason string) {
	if n := len(raw); n > 0 && raw[n-1] == '\r' {
		raw = raw[:n-1]
	}
	i := 0
	for i < len(raw) && isBlank(raw[i]) {
		i++
	}
	digits := i
	for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
		i++
	}
	switch {
	case i == digits:
		return 0, "", "no decimal offset"
	case i == len(raw) || !isBlank(raw[i]):
		return 0, "", "no blank after the offset"
	case i+1 == len(raw):
		return 0, "", "no string after the offset"
	}
	v, err := strconv.ParseUint(string(raw[digits:i]), 10, 64)
	if err != nil {
		return 0, "", "offset does not fit 64 bits"
	}
	return v, decodeText(raw[i+1:]), ""
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }

// A strings listing may hold bytes of any single-byte code page; Latin-1 keeps
// every byte as one rune, so nothing is lost when the text is not UTF-8.
func decodeText(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func ReadLines(r io.Reader, maxLineBytes int64, maxLines int) ([]Line, []Rejected, error) {
	br := bufio.NewReader(r)
	var lines []Line
	var rejected []Rejected
	for n := 1; ; n++ {
		raw, overlong, err := readLine(br, maxLineBytes)
		if err == io.EOF && len(raw) == 0 && !overlong {
			return lines, rejected, nil
		}
		if err != nil && err != io.EOF {
			return lines, rejected, fmt.Errorf("line %d: %w", n, err)
		}
		switch {
		case overlong:
			rejected = append(rejected, Rejected{Number: n, Reason: fmt.Sprintf("longer than %d bytes", maxLineBytes)})
		case len(raw) == 0:
		default:
			off, text, reason := ParseLine(raw)
			if reason != "" {
				rejected = append(rejected, Rejected{Number: n, Reason: reason})
				break
			}
			if len(lines) == maxLines {
				return lines, rejected, fmt.Errorf("line %d: %w (%d)", n, ErrTooManyLines, maxLines)
			}
			lines = append(lines, Line{Number: n, Offset: off, Text: text})
		}
		if err == io.EOF {
			return lines, rejected, nil
		}
	}
}

func readLine(br *bufio.Reader, maxBytes int64) ([]byte, bool, error) {
	var line []byte
	overlong := false
	for {
		part, err := br.ReadSlice('\n')
		if !overlong {
			if int64(len(line)+len(part)) > maxBytes+1 {
				overlong, line = true, nil
			} else {
				line = append(line, part...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if n := len(line); n > 0 && line[n-1] == '\n' {
			line = line[:n-1]
		}
		return line, overlong, err
	}
}
