package symbols

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const written = `{
  "vsym": 1,
  "pointer_width": 8,
  "windows_pdb": {"guid": "0D960CE103763A6097E839406D8B369F", "age": 3, "file": "ntkrnlmp.pdb"},
  "linux_banner": "a\"b\\c\n\t\r\u0001é<&>",
  "scalars": [
    {"name": "be", "width": 4, "kind": "integer", "big_endian": true},
    {"name": "int", "width": 4, "kind": "integer", "signed": true}
  ],
  "records": [
    {"name": "_A", "width": 16, "members": [
      {"name": "Flink", "offset": 8, "type": "*_A"},
      {"name": "Bits", "offset": 0, "type": "@1:3 int"},
      {"offset": 4, "embeds": "_B"},
      {"name": "u1", "offset": 12, "embeds": "_B"}
    ]},
    {"name": "_B"},
    {"name": "_C", "members": [
      {"name": "*odd", "offset": 0, "type": "[0]\\*odd"}
    ]}
  ],
  "enumerations": [
    {"name": "_E", "width": 4, "constants": [{"name": "Low", "value": -9223372036854775808}, {"name": "A", "value": 1}, {"name": "B", "value": 1}]},
    {"name": "_F"}
  ],
  "addresses": [
    {"name": "Head", "address": "0x5a1b30", "type": "_A"},
    {"name": "Top", "address": "0xffffffffffffffff"},
    {"name": "Zero", "address": "0x0"}
  ]
}
`

func TestATableIsWrittenInTheFormatsLayout(t *testing.T) {
	d, err := DecodeDeclaration([]byte(written))
	if err != nil {
		t.Fatal(err)
	}
	slicesReverse(d.Records)
	slicesReverse(d.Addresses)
	var out bytes.Buffer
	if err := Encode(&out, d); err != nil {
		t.Fatal(err)
	}
	if out.String() != written {
		t.Errorf("written:\n%s\nwant:\n%s", out.String(), written)
	}
	again, err := DecodeDeclaration(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	slicesReverse(again.Records)
	slicesReverse(again.Addresses)
	if !reflect.DeepEqual(again, d) {
		t.Errorf("read back differently:\n%+v\n%+v", again, d)
	}
	if d.WindowsPDB.Database != "ntkrnlmp.pdb" || d.WindowsPDB.Age != 3 || string(d.LinuxBanner) != "a\"b\\c\n\t\r\x01é<&>" {
		t.Errorf("%+v %q", d.WindowsPDB, d.LinuxBanner)
	}
}

func slicesReverse[T any](s []T) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func TestEmptyListsAndAbsentKeys(t *testing.T) {
	var out bytes.Buffer
	if err := Encode(&out, Declaration{PointerWidth: 4, Scalars: []Scalar{}}); err != nil {
		t.Fatal(err)
	}
	const want = "{\n  \"vsym\": 1,\n  \"pointer_width\": 4,\n  \"scalars\": []\n}\n"
	if out.String() != want {
		t.Errorf("%q", out.String())
	}
	d, err := DecodeDeclaration(out.Bytes())
	if err != nil || d.Scalars == nil || len(d.Scalars) != 0 {
		t.Errorf("an empty scalar list is kept apart from none: %+v %v", d, err)
	}
	d, err = DecodeDeclaration([]byte(`{"vsym": 1, "pointer_width": 8}`))
	if err != nil || d.Scalars != nil || d.WindowsPDB != nil || d.LinuxBanner != nil {
		t.Errorf("%+v %v", d, err)
	}
	out.Reset()
	if err := Encode(&out, Declaration{PointerWidth: 8, Records: []Record{{Name: "bad\xff"}}}); err == nil {
		t.Error("a name that is not UTF-8 was written")
	}
	if err := Encode(&out, Declaration{PointerWidth: 3}); err == nil {
		t.Error("a bad declaration was written")
	}
	if err := Encode(failingWriter{}, Declaration{PointerWidth: 8}); err == nil {
		t.Error("a write error was lost")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("full") }

func TestAMalformedTableIsRefused(t *testing.T) {
	head := `{"vsym": 1, "pointer_width": 8, `
	for why, text := range map[string]string{
		"format 2":          `{"vsym": 2}`,
		"pointer width 2":   `{"vsym": 1, "pointer_width": 2}`,
		`"pointer_width"`:   `{"vsym": 1}`,
		"unknown key":       head + `"extra": 1}`,
		"written twice":     `{"vsym": 1, "vsym": 1, "pointer_width": 8}`,
		"follows":           `{"vsym": 1, "pointer_width": 8} {}`,
		"not an integer":    `{"vsym": 1, "pointer_width": 8.0}`,
		"leading zero":      `{"vsym": 1, "pointer_width": 08}`,
		"negative":          head + `"records": [{"name": "r", "width": -1}]}`,
		"past 64 bits":      head + `"records": [{"name": "r", "width": 18446744073709551616}]}`,
		"signed bits":       head + `"enumerations": [{"name": "e", "constants": [{"name": "a", "value": 9223372036854775808}]}]}`,
		"want a string":     head + `"linux_banner": null}`,
		"want true":         head + `"scalars": [{"name": "s", "width": 1, "kind": "char", "signed": 1}]}`,
		"kind":              head + `"scalars": [{"name": "s", "width": 1}]}`,
		"upper-case":        head + `"windows_pdb": {"guid": "0d960ce103763a6097e839406d8b369f", "age": 1}}`,
		`"age"`:             head + `"windows_pdb": {"guid": "0D960CE103763A6097E839406D8B369F"}}`,
		"32 bits":           head + `"windows_pdb": {"guid": "0D960CE103763A6097E839406D8B369F", "age": 4294967296}}`,
		`"file"`:            head + `"windows_pdb": {"guid": "0D960CE103763A6097E839406D8B369F", "age": 1, "file": ""}}`,
		"banner is empty":   head + `"linux_banner": ""}`,
		`"offset"`:          head + `"records": [{"name": "r", "members": [{"name": "a", "type": "int"}]}]}`,
		"both":              head + `"records": [{"name": "r", "members": [{"name": "a", "offset": 0, "type": "int", "embeds": "r"}]}]}`,
		"neither":           head + `"records": [{"name": "r", "members": [{"name": "a", "offset": 0}]}]}`,
		`no "name"`:         head + `"records": [{"name": "r", "members": [{"offset": 0, "type": "int"}]}]}`,
		`empty "embeds"`:    head + `"records": [{"name": "r", "members": [{"offset": 0, "embeds": ""}]}]}`,
		"bit length":        head + `"records": [{"name": "r", "members": [{"name": "a", "offset": 0, "type": "@0:0 int"}]}]}`,
		"named twice":       head + `"records": [{"name": "r"}, {"name": "r"}]}`,
		"lower-case hex":    head + `"addresses": [{"name": "a", "address": "0x0A"}]}`,
		"no leading zero":   head + `"addresses": [{"name": "a", "address": "0x01"}]}`,
		"within 64 bits":    head + `"addresses": [{"name": "a", "address": "0x10000000000000000"}]}`,
		`"address"`:         head + `"addresses": [{"name": "a"}]}`,
		"not UTF-8":         head + "\"linux_banner\": \"\xff\"}",
		"control character": head + "\"linux_banner\": \"a\nb\"}",
		"unpaired":          head + `"linux_banner": "\ud800x"}`,
		"unknown escape":    head + `"linux_banner": "\q"}`,
		"no end":            head + `"linux_banner": "abc`,
		"want a comma":      head + `"records": [{"name": "r"} {"name": "s"}]}`,
		"in a member":       head + `"records": [{"name": "r", "members": [{"name": "a", "offset": 0, "type": "int", "x": 1}]}]}`,
	} {
		_, err := DecodeDeclaration([]byte(text))
		if err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v", why, err)
		}
		if err != nil && errors.Is(err, ErrNotVsym) {
			t.Errorf("%s: a broken table called no table: %v", why, err)
		}
	}
	if d, err := DecodeDeclaration([]byte(head + `"linux_banner": "é😀\/"}`)); err != nil || string(d.LinuxBanner) != "é😀/" {
		t.Errorf("escapes: %q %v", d.LinuxBanner, err)
	}
}

func TestAFileInAnotherLayoutIsNotATable(t *testing.T) {
	for _, text := range []string{
		``, `[]`, `not json`, `{"metadata": {"format": "6.2.0"}, "base_types": {"int": {"size": 4, "x": [1, 2.5e3, true, null]}}}`,
		`{"base_types": {`, `{}`,
	} {
		if _, err := Read("other", []byte(text)); !errors.Is(err, ErrNotVsym) {
			t.Errorf("%q: %v, want ErrNotVsym", text, err)
		}
	}
	deep := strings.Repeat(`{"a": `, maxSkipDepth+2) + "1" + strings.Repeat("}", maxSkipDepth+2)
	if _, err := Decode("deep", []byte(`{"x": `+deep+`}`)); !errors.Is(err, ErrNotVsym) {
		t.Errorf("deep: %v", err)
	}
}

func TestReadingAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.vsym")
	if err := os.WriteFile(path, []byte(written), 0o644); err != nil {
		t.Fatal(err)
	}
	table, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := table.Field("_A", "Bits"); err != nil || f.Type.BitLength != 3 {
		t.Errorf("%+v %v", f, err)
	}
	if _, err := ReadFileWith(path, ReadOptions{MaxTableFile: int64(len(written)) - 1}); !errors.Is(err, ErrTableTooLarge) {
		t.Errorf("size limit: %v", err)
	}
	if _, err := ReadFileWith(path, ReadOptions{MaxTableFile: int64(len(written))}); err != nil {
		t.Errorf("at the limit: %v", err)
	}
	if _, err := ReadFile(filepath.Join(dir, "absent.vsym")); err == nil {
		t.Error("absent file read")
	}
	for _, opts := range []ReadOptions{{MaxTableFile: -1}, {MaxTableFile: 1<<32 + 1}, {MaxTableEntries: -1}, {MaxTableEntries: 1 << 31}} {
		if _, err := ReadFileWith(path, opts); err == nil {
			t.Errorf("%+v accepted", opts)
		}
	}
	if o, err := (ReadOptions{}).Resolved(); err != nil || o.MaxTableFile != MaxTableFile || o.MaxTableEntries == 0 {
		t.Errorf("defaults %+v %v", o, err)
	}
}
