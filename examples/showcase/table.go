package main

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/examples/internal/cli"
)

const (
	redactedCell = "[redacted]"
	bytesShown   = 32
	nestingShown = 4
	absentCell   = "-"
)

// Matched against the end of a field name: the project names virtual
// addresses ...Address and physical ones ...Physical, and EPROCESS and
// ETHREAD fields hold the address of that kernel object.
var hexSuffixes = []string{
	"Address", "Addr", "Physical", "Offset", "Base", "Start", "End", "Size", "Flags", "Mask", "EPROCESS", "ETHREAD",
}

const unreadableSuffix = "Unreadable"

type table struct {
	header []string
	rows   [][]string
	hidden []string
}

type column struct {
	name   string
	path   []int
	flag   []int
	group  int
	hex    bool
	secret bool
}

var (
	timeType     = reflect.TypeFor[time.Time]()
	stringerType = reflect.TypeFor[fmt.Stringer]()
	errorType    = reflect.TypeFor[error]()
)

func tabulate(result any, secrets []string) table {
	v := reflect.ValueOf(result)
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && !isLeaf(v.Type()) {
		if v.IsNil() {
			return table{}
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return table{}
	}
	switch {
	case (v.Kind() == reflect.Slice || v.Kind() == reflect.Array) && v.Type().Elem().Kind() != reflect.Uint8:
		return tabulateList(v, secrets)
	case v.Kind() == reflect.Map:
		return tabulateMap(v)
	case v.Kind() == reflect.Struct && !isLeaf(v.Type()):
		one := reflect.New(reflect.SliceOf(v.Type())).Elem()
		return tabulateList(reflect.Append(one, v), secrets)
	}
	return table{header: []string{"Value"}, rows: [][]string{{render(v, false, 0)}}}
}

func tabulateList(v reflect.Value, secrets []string) table {
	row := v.Type().Elem()
	for row.Kind() == reflect.Pointer {
		row = row.Elem()
	}
	if row.Kind() != reflect.Struct || isLeaf(row) {
		t := table{header: []string{"Value"}}
		for i := range v.Len() {
			t.rows = append(t.rows, []string{render(v.Index(i), false, 0)})
		}
		return t
	}
	children := childField(row)
	var records []reflect.Value
	seen := map[uintptr]bool{}
	var walk func(list reflect.Value)
	walk = func(list reflect.Value) {
		for i := range list.Len() {
			r := list.Index(i)
			if r.Kind() == reflect.Pointer {
				// A tree read from an image can loop back on itself.
				if r.IsNil() || seen[r.Pointer()] {
					continue
				}
				seen[r.Pointer()] = true
				r = r.Elem()
			}
			records = append(records, r)
			if children >= 0 {
				walk(r.Field(children))
			}
		}
	}
	walk(v)

	cols := dropEmptyGroups(columnsOf(row, secrets), records)
	t := table{}
	for _, c := range cols {
		t.header = append(t.header, c.name)
		if c.secret {
			t.hidden = append(t.hidden, c.name)
		}
	}
	for _, r := range records {
		t.rows = append(t.rows, cells(r, cols))
	}
	return t
}

// One row type can carry a group of fields per platform; a group that is
// zero in every row is the other platform's, and would print only zeros.
func dropEmptyGroups(cols []column, records []reflect.Value) []column {
	used := map[int]bool{}
	for _, c := range cols {
		if c.group < 0 || used[c.group] {
			continue
		}
		for _, r := range records {
			if f := r.Field(c.group); !f.IsZero() {
				used[c.group] = true
				break
			}
		}
	}
	kept := cols[:0]
	for _, c := range cols {
		if c.group < 0 || used[c.group] {
			kept = append(kept, c)
		}
	}
	return kept
}

func tabulateMap(v reflect.Value) table {
	t := table{header: []string{"Key", "Value"}}
	for _, k := range v.MapKeys() {
		t.rows = append(t.rows, []string{render(k, false, 0), render(v.MapIndex(k), false, 0)})
	}
	slices.SortFunc(t.rows, func(a, b []string) int { return strings.Compare(a[0], b[0]) })
	return t
}

func isLeaf(t reflect.Type) bool {
	return t == timeType || t.Implements(stringerType) || t.Implements(errorType)
}

func childField(row reflect.Type) int {
	for i := range row.NumField() {
		f := row.Field(i)
		if !f.IsExported() || f.Type.Kind() != reflect.Slice {
			continue
		}
		e := f.Type.Elem()
		if e == row || (e.Kind() == reflect.Pointer && e.Elem() == row) {
			return i
		}
	}
	return -1
}

func columnsOf(row reflect.Type, secrets []string) []column {
	var cols []column
	children := childField(row)
	var add func(t reflect.Type, prefix string, path []int, depth int)
	add = func(t reflect.Type, prefix string, path []int, depth int) {
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() || (depth == 0 && i == children) {
				continue
			}
			at := append(slices.Clone(path), i)
			inner := f.Type
			if inner.Kind() == reflect.Pointer {
				inner = inner.Elem()
			}
			if inner.Kind() == reflect.Struct && !isLeaf(inner) && !isLeaf(f.Type) && depth < nestingShown {
				p := prefix
				if !f.Anonymous {
					p = prefix + f.Name + "."
				}
				add(inner, p, at, depth+1)
				continue
			}
			group := -1
			if depth > 0 {
				group = at[0]
			}
			cols = append(cols, column{
				name:   prefix + f.Name,
				path:   at,
				group:  group,
				hex:    hexName(f.Name),
				secret: depth == 0 && slices.Contains(secrets, f.Name),
			})
		}
	}
	add(row, "", nil, 0)

	kept := cols[:0]
	for _, c := range cols {
		base, isFlag := strings.CutSuffix(c.name, unreadableSuffix)
		if isFlag && base != "" {
			if i := slices.IndexFunc(cols, func(o column) bool { return o.name == base }); i >= 0 {
				cols[i].flag = c.path
				continue
			}
		}
		kept = append(kept, c)
	}
	return kept
}

func hexName(name string) bool {
	return slices.ContainsFunc(hexSuffixes, func(s string) bool { return strings.HasSuffix(name, s) })
}

func cells(row reflect.Value, cols []column) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = cell(row, c)
	}
	return out
}

func cell(row reflect.Value, c column) string {
	if c.secret {
		return redactedCell
	}
	v, err := row.FieldByIndexErr(c.path)
	if err != nil {
		return absentCell
	}
	if c.flag != nil {
		if f, err := row.FieldByIndexErr(c.flag); err == nil && f.Kind() == reflect.Bool && f.Bool() {
			if v.Kind() == reflect.String {
				return cli.Cell(v.String(), true)
			}
			return cli.Unreadable
		}
	}
	return render(v, c.hex, 0)
}

func render(v reflect.Value, hex bool, depth int) string {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		if v.IsNil() {
			return absentCell
		}
		if isLeaf(v.Type()) && v.CanInterface() {
			break
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return absentCell
	}
	if depth > nestingShown {
		return "..."
	}
	if v.Kind() == reflect.Struct && isLeaf(v.Type()) && v.IsZero() {
		return absentCell
	}
	if v.CanInterface() {
		switch x := v.Interface().(type) {
		case time.Time:
			return cli.Time(x, false)
		case error:
			return cli.Text(x.Error())
		case fmt.Stringer:
			return cli.Text(x.String())
		}
	}
	switch v.Kind() {
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if hex {
			return "0x" + strconv.FormatUint(v.Uint(), 16)
		}
		return strconv.FormatUint(v.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'g', -1, 64)
	case reflect.String:
		return cli.Text(v.String())
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return bytesCell(v)
		}
		items := make([]string, v.Len())
		for i := range v.Len() {
			items[i] = render(v.Index(i), hex, depth+1)
		}
		return "[" + strings.Join(items, ", ") + "]"
	case reflect.Map:
		items := make([]string, 0, v.Len())
		for _, k := range v.MapKeys() {
			items = append(items, render(k, false, depth+1)+"="+render(v.MapIndex(k), false, depth+1))
		}
		slices.Sort(items)
		return "{" + strings.Join(items, ", ") + "}"
	case reflect.Struct:
		var items []string
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if f.IsExported() {
				items = append(items, f.Name+"="+render(v.Field(i), hexName(f.Name), depth+1))
			}
		}
		return "{" + strings.Join(items, " ") + "}"
	}
	return absentCell
}

func bytesCell(v reflect.Value) string {
	n := v.Len()
	shown := min(n, bytesShown)
	var b strings.Builder
	fmt.Fprintf(&b, "%d bytes", n)
	if shown > 0 {
		b.WriteByte(' ')
		for i := range shown {
			fmt.Fprintf(&b, "%02x", byte(v.Index(i).Uint()))
		}
		if n > shown {
			b.WriteString("...")
		}
	}
	return b.String()
}
