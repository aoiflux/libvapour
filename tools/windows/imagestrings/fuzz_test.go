package imagestrings

import (
	"bytes"
	"strconv"
	"testing"
	"unicode/utf8"
)

func FuzzParseLine(f *testing.F) {
	f.Add([]byte("4096 hello"))
	f.Add([]byte("  12\tx\r"))
	f.Add([]byte("99999999999999999999 big"))
	f.Add([]byte{'1', ' ', 0xff})
	f.Fuzz(func(t *testing.T, line []byte) {
		off, text, reason := ParseLine(line)
		if reason != "" {
			return
		}
		if text == "" || !utf8.ValidString(text) {
			t.Fatalf("%q gave text %q", line, text)
		}
		if !bytes.Contains(line, []byte(strconv.FormatUint(off, 10))) && off != 0 {
			t.Fatalf("%q gave offset %d not in the line", line, off)
		}
		lines, _, err := ReadLines(bytes.NewReader(append(append([]byte{}, line...), '\n')), 1<<20, 1)
		if bytes.IndexByte(line, '\n') < 0 && (err != nil || len(lines) != 1 || lines[0].Offset != off || lines[0].Text != text) {
			t.Fatalf("%q: ReadLines %+v %v disagrees with ParseLine", line, lines, err)
		}
	})
}
