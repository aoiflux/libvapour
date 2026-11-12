package symbols

import (
	"bytes"
	"reflect"
	"testing"
)

// A table that reads is written, and what is written reads back the same.
func FuzzDecodeDeclaration(f *testing.F) {
	f.Add([]byte(written))
	f.Add([]byte(listTableForFuzz))
	f.Add([]byte(`{"vsym": 1, "pointer_width": 4, "scalars": []}`))
	f.Add([]byte(`{"base_types": {"int": {"size": 4}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := DecodeDeclaration(data)
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := Encode(&out, d); err != nil {
			t.Fatalf("read but not written: %v", err)
		}
		again, err := DecodeDeclaration(out.Bytes())
		if err != nil {
			t.Fatalf("written but not read: %v\n%s", err, out.Bytes())
		}
		var twice bytes.Buffer
		if err := Encode(&twice, again); err != nil || !bytes.Equal(twice.Bytes(), out.Bytes()) {
			t.Fatalf("a second write differs (%v)", err)
		}
		table, err := BuildWith("fuzz", d, ReadOptions{MaxTableEntries: 1 << 12})
		if err != nil {
			return
		}
		for _, r := range d.Records {
			if st, err := table.Struct(r.Name); err == nil {
				_, _ = table.ReadStruct(flat{data: make([]byte, 64)}, r.Name, 0)
				_, _ = table.SizeOf(r.Name)
				for _, fl := range st.Fields {
					_, _ = table.FieldSize(r.Name, fl.Name)
				}
			}
		}
	})
}

const listTableForFuzz = `{"vsym": 1, "pointer_width": 8, "records": [{"name": "a", "members": [{"offset": 0, "embeds": "b"}, {"name": "x", "offset": 1, "type": "@1:2 [3]*b"}]}, {"name": "b", "width": 4, "members": [{"name": "y", "offset": 0, "type": "\\@z"}]}], "enumerations": [{"name": "e", "constants": [{"name": "c", "value": -1}]}], "addresses": [{"name": "s", "address": "0xff", "type": "[2]e"}]}`

// An expression that parses is written back as it was, and passes the check
// that guards writing.
func FuzzTypeExpression(f *testing.F) {
	for _, s := range []string{"", "*", "*_LIST_ENTRY", "[16]unsigned char", "@0:3 unsigned long", `\*x`, "[0]x", "*[4]@1:2 y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := parseTypeExpression(s)
		if err != nil {
			return
		}
		if err := checkTypeRef(r); err != nil {
			t.Fatalf("%q parses but fails the check: %v", s, err)
		}
		if got := formatTypeRef(r); got != s {
			t.Fatalf("%q written back as %q", s, got)
		}
		again, err := parseTypeExpression(formatTypeRef(r))
		if err != nil || !reflect.DeepEqual(again, r) {
			t.Fatalf("%q reads back differently", s)
		}
		_, _ = exprWidth(r, 8, func(string) (uint64, error) { return 4, nil })
	})
}
