package symbols

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// Writes d in the layout FORMAT.md fixes, so that one table always gives the
// same bytes and two tables can be compared with a diff.
func Encode(w io.Writer, d Declaration) error {
	if err := d.check(); err != nil {
		return err
	}
	if err := d.checkText(); err != nil {
		return err
	}
	var b writer
	b.declaration(d)
	if _, err := w.Write(b.buf); err != nil {
		return fmt.Errorf("symbols: write table: %w", err)
	}
	return nil
}

type writer struct{ buf []byte }

func (w *writer) raw(s string) { w.buf = append(w.buf, s...) }

func (w *writer) num(v uint64) { w.buf = strconv.AppendUint(w.buf, v, 10) }

const hexDigits = "0123456789abcdef"

// RFC 8259 section 7: the quote, the backslash and control characters are
// escaped; everything else, UTF-8 included, is written as it is.
func (w *writer) str(s string) {
	w.buf = append(w.buf, '"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			w.buf = append(w.buf, '\\', c)
		case c == '\n':
			w.buf = append(w.buf, '\\', 'n')
		case c == '\t':
			w.buf = append(w.buf, '\\', 't')
		case c == '\r':
			w.buf = append(w.buf, '\\', 'r')
		case c < 0x20:
			w.buf = append(w.buf, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			w.buf = append(w.buf, c)
		}
	}
	w.buf = append(w.buf, '"')
}

func (w *writer) key(first bool, name string) {
	if !first {
		w.raw(", ")
	}
	w.str(name)
	w.raw(": ")
}

func (w *writer) declaration(d Declaration) {
	w.raw("{\n  \"vsym\": ")
	w.num(FormatVersion)
	w.raw(",\n  \"pointer_width\": ")
	w.num(uint64(d.PointerWidth))
	if p := d.WindowsPDB; p != nil {
		w.raw(",\n  \"windows_pdb\": {")
		w.key(true, "guid")
		w.str(strings.ToUpper(p.GUID))
		w.key(false, "age")
		w.num(uint64(p.Age))
		if p.Database != "" {
			w.key(false, "file")
			w.str(p.Database)
		}
		w.raw("}")
	}
	if d.LinuxBanner != nil {
		w.raw(",\n  \"linux_banner\": ")
		w.str(string(d.LinuxBanner))
	}
	if d.Scalars != nil {
		list(w, "scalars", byName(d.Scalars, func(s Scalar) string { return s.Name }), true, w.scalar)
	}
	list(w, "records", byName(d.Records, func(r Record) string { return r.Name }), false, w.record)
	list(w, "enumerations", byName(d.Enumerations, func(e EnumType) string { return e.Name }), false, w.enumeration)
	list(w, "addresses", byName(d.Addresses, func(a Address) string { return a.Name }), false, w.address)
	w.raw("\n}\n")
}

func byName[T any](items []T, name func(T) string) []T {
	out := slices.Clone(items)
	slices.SortStableFunc(out, func(a, b T) int { return strings.Compare(name(a), name(b)) })
	return out
}

func list[T any](w *writer, key string, items []T, always bool, entry func(T)) {
	if len(items) == 0 && !always {
		return
	}
	w.raw(",\n  ")
	w.str(key)
	if len(items) == 0 {
		w.raw(": []")
		return
	}
	w.raw(": [\n")
	for i, item := range items {
		w.raw("    ")
		entry(item)
		if i < len(items)-1 {
			w.raw(",")
		}
		w.raw("\n")
	}
	w.raw("  ]")
}

func (w *writer) scalar(s Scalar) {
	w.raw("{")
	w.key(true, "name")
	w.str(s.Name)
	w.key(false, "width")
	w.num(s.Width)
	w.key(false, "kind")
	w.str(string(s.Kind))
	if s.Signed {
		w.key(false, "signed")
		w.raw("true")
	}
	if s.BigEndian {
		w.key(false, "big_endian")
		w.raw("true")
	}
	w.raw("}")
}

func (w *writer) record(r Record) {
	w.raw("{")
	w.key(true, "name")
	w.str(r.Name)
	if r.Width != 0 {
		w.key(false, "width")
		w.num(r.Width)
	}
	if len(r.Members) > 0 {
		w.key(false, "members")
		w.raw("[\n")
		for i, m := range r.Members {
			w.raw("      {")
			first := true
			if m.Name != "" {
				w.key(true, "name")
				w.str(m.Name)
				first = false
			}
			w.key(first, "offset")
			w.num(m.Offset)
			if m.Embeds != "" {
				w.key(false, "embeds")
				w.str(m.Embeds)
			} else {
				w.key(false, "type")
				w.str(formatTypeRef(m.Type))
			}
			w.raw("}")
			if i < len(r.Members)-1 {
				w.raw(",")
			}
			w.raw("\n")
		}
		w.raw("    ]")
	}
	w.raw("}")
}

func (w *writer) enumeration(e EnumType) {
	w.raw("{")
	w.key(true, "name")
	w.str(e.Name)
	if e.Size != 0 {
		w.key(false, "width")
		w.num(e.Size)
	}
	if len(e.Values) > 0 {
		values := slices.Clone(e.Values)
		sortConstants(values)
		w.key(false, "constants")
		w.raw("[")
		for i, v := range values {
			if i > 0 {
				w.raw(", ")
			}
			w.raw("{")
			w.key(true, "name")
			w.str(v.Name)
			w.key(false, "value")
			w.buf = strconv.AppendInt(w.buf, v.Value, 10)
			w.raw("}")
		}
		w.raw("]")
	}
	w.raw("}")
}

func (w *writer) address(a Address) {
	w.raw("{")
	w.key(true, "name")
	w.str(a.Name)
	w.key(false, "address")
	w.raw(`"0x`)
	w.buf = strconv.AppendUint(w.buf, a.Address, 16)
	w.raw(`"`)
	if a.Type != nil {
		w.key(false, "type")
		w.str(formatTypeRef(*a.Type))
	}
	w.raw("}")
}
