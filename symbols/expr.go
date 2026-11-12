package symbols

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The format's own bound on one expression. Real types nest a few levels; the
// bound keeps a crafted table from handing every reader a chain of millions.
const MaxTypeOperators = 32

type operator int

const (
	opNone operator = iota
	opPointer
	opArray
	opBitfield
)

func (r TypeRef) isArray() bool { return r.IsArray || r.ArrayLength > 0 }

func (r TypeRef) operators() (op operator, n int) {
	if r.IsPointer {
		op, n = opPointer, n+1
	}
	if r.isArray() {
		op, n = opArray, n+1
	}
	if r.BitLength > 0 {
		op, n = opBitfield, n+1
	}
	return op, n
}

// An operator level built in code may leave Element nil and give only the
// inner name.
func (r TypeRef) inner() TypeRef {
	if r.Element != nil {
		return *r.Element
	}
	return TypeRef{Name: r.Name}
}

func escapedFirst(c byte) bool { return c == '*' || c == '[' || c == '@' || c == '\\' }

func escapedName(name string) string {
	if name != "" && escapedFirst(name[0]) {
		return `\` + name
	}
	return name
}

func checkTypeRef(ref TypeRef) error {
	for depth := 0; ; depth++ {
		_, n := ref.operators()
		switch {
		case n > 1:
			return errors.New("one level of the type is more than one of a pointer, an array and a bitfield")
		case ref.BitLength == 0 && ref.BitOffset != 0:
			return fmt.Errorf("bit offset %d with a bit length of 0", ref.BitOffset)
		case n == 0 && ref.Element != nil:
			return fmt.Errorf("type %q is not a pointer, array or bitfield but has an element", ref.Name)
		case n == 0:
			return nil
		case depth == MaxTypeOperators:
			return fmt.Errorf("type has more than %d operators", MaxTypeOperators)
		case ref.Element == nil:
			return nil
		}
		ref = *ref.Element
	}
}

func formatTypeRef(ref TypeRef) string {
	var b strings.Builder
	for {
		op, _ := ref.operators()
		switch op {
		case opPointer:
			b.WriteByte('*')
		case opArray:
			b.WriteByte('[')
			b.WriteString(strconv.FormatUint(ref.ArrayLength, 10))
			b.WriteByte(']')
		case opBitfield:
			b.WriteByte('@')
			b.WriteString(strconv.Itoa(int(ref.BitOffset)))
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(int(ref.BitLength)))
			b.WriteByte(' ')
		}
		if op == opNone || ref.Element == nil {
			b.WriteString(escapedName(ref.Name))
			return b.String()
		}
		ref = *ref.Element
	}
}

type exprLevel struct {
	op             operator
	count          uint64
	offset, length uint8
}

func parseTypeExpression(s string) (TypeRef, error) {
	var levels []exprLevel
	rest := s
	for rest != "" && rest[0] != '\\' && escapedFirst(rest[0]) {
		if len(levels) == MaxTypeOperators {
			return TypeRef{}, fmt.Errorf("type %q has more than %d operators", s, MaxTypeOperators)
		}
		var lv exprLevel
		var err error
		switch rest[0] {
		case '*':
			lv.op, rest = opPointer, rest[1:]
		case '[':
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return TypeRef{}, fmt.Errorf("type %q: [ without ]", s)
			}
			lv.op = opArray
			if lv.count, err = decimal(rest[1:end], 1<<64-1); err != nil {
				return TypeRef{}, fmt.Errorf("type %q: element count: %w", s, err)
			}
			rest = rest[end+1:]
		case '@':
			end := strings.IndexByte(rest, ' ')
			if end < 0 {
				return TypeRef{}, fmt.Errorf("type %q: bitfield without a space before its storage type", s)
			}
			o, l, ok := strings.Cut(rest[1:end], ":")
			if !ok {
				return TypeRef{}, fmt.Errorf("type %q: bitfield is not @offset:length", s)
			}
			offset, err := decimal(o, 255)
			if err != nil {
				return TypeRef{}, fmt.Errorf("type %q: bit offset: %w", s, err)
			}
			length, err := decimal(l, 255)
			if err != nil || length == 0 {
				return TypeRef{}, fmt.Errorf("type %q: bit length %q is not 1 to 255", s, l)
			}
			lv.op, lv.offset, lv.length = opBitfield, uint8(offset), uint8(length)
			rest = rest[end+1:]
		}
		levels = append(levels, lv)
	}
	name := rest
	if escaped, ok := strings.CutPrefix(rest, `\`); ok {
		if escaped == "" || !escapedFirst(escaped[0]) {
			return TypeRef{}, fmt.Errorf(`type %q: \ before a name that needs no escape`, s)
		}
		name = escaped
	}
	ref := TypeRef{Name: name}
	for i := len(levels) - 1; i >= 0; i-- {
		element := ref
		ref = TypeRef{Name: name, Element: &element}
		switch lv := levels[i]; lv.op {
		case opPointer:
			ref.IsPointer = true
		case opArray:
			ref.IsArray, ref.ArrayLength = true, lv.count
		case opBitfield:
			ref.BitOffset, ref.BitLength = lv.offset, lv.length
		}
	}
	return ref, nil
}

func decimal(s string, limit uint64) (uint64, error) {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("%q is not a decimal count", s)
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("%q is not a decimal count", s)
		}
		d := uint64(c - '0')
		if v > (limit-d)/10 {
			return 0, fmt.Errorf("%s is past %d", s, limit)
		}
		v = v*10 + d
	}
	return v, nil
}
