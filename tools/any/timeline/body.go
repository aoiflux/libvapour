package timeline

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/extract"
)

type bodyColumn int

const (
	accessColumn bodyColumn = iota
	modifyColumn
	statusColumn
	birthColumn
)

var columnOf = map[Event]bodyColumn{
	Accessed: accessColumn,
	Launched: accessColumn,
	Ran:      accessColumn,
	Modified: modifyColumn,
	Written:  modifyColumn,
	Exited:   modifyColumn,
	Unloaded: modifyColumn,
	Changed:  statusColumn,
	Created:  birthColumn,
	Loaded:   birthColumn,
	Booted:   birthColumn,
	Entered:  birthColumn,
	Linked:   birthColumn,
}

func BodyName(e Entry) string {
	var b strings.Builder
	b.WriteString(e.Tool)
	b.WriteByte(' ')
	b.WriteString(string(e.Event))
	b.WriteByte(' ')
	b.WriteString(e.Field)
	b.WriteString(": ")
	b.WriteString(e.Subject)
	switch {
	case e.Address != 0:
		fmt.Fprintf(&b, " at 0x%x", e.Address)
	case e.Physical != 0:
		fmt.Fprintf(&b, " physical 0x%x", e.Physical)
	}
	return escapeBodyText(b.String())
}

// The separator and line breaks would split the line; other control bytes
// and invalid UTF-8 are written as hex so the file stays UTF-8 text.
func escapeBodyText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1, r < 0x20, r == 0x7f, r == '|':
			fmt.Fprintf(&b, `\x%02x`, s[i])
			size = 1
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func BodyLine(e Entry) (string, bool) {
	// Second 0 would read as "no time".
	if e.Time.IsZero() || BeforeEpoch(e.Time) || e.Time.Unix() == 0 {
		return "", false
	}
	col, ok := columnOf[e.Event]
	if !ok {
		return "", false
	}
	var times [4]string
	for i := range times {
		times[i] = "0"
	}
	times[col] = strconv.FormatInt(e.Time.Unix(), 10)
	return "0|" + BodyName(e) + "|0|0|0|0|0|" + strings.Join(times[:], "|"), true
}

type bodyWrite struct {
	name    string
	lines   int
	skipped int
}

func writeBody(dir string, entries []Entry, limit uint64, attempts int) (bodyWrite, error) {
	f, name, err := extract.CreateUnique(dir, BodyfileName, attempts)
	if err != nil {
		return bodyWrite{}, fmt.Errorf("body file: %w", err)
	}
	w := bodyWrite{name: name}
	bw := bufio.NewWriter(f)
	var written uint64
	for _, e := range entries {
		line, ok := BodyLine(e)
		if !ok {
			w.skipped++
			continue
		}
		if written += uint64(len(line)) + 1; limit != 0 && written > limit {
			err = fmt.Errorf("%w: more than %d bytes", ErrBodyTooLarge, limit)
			break
		}
		if _, err = bw.WriteString(line + "\n"); err != nil {
			break
		}
		w.lines++
	}
	if err == nil {
		err = bw.Flush()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		if rerr := extract.RemoveArtifact(dir, name); rerr != nil {
			err = errors.Join(err, rerr)
		}
		return bodyWrite{}, fmt.Errorf("body file %s: %w", name, err)
	}
	return w, nil
}
