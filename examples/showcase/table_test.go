package main

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/examples/internal/cli"
)

type sampleGroup struct {
	Count int64
	Label string
}

type SampleShared struct {
	Shared uint32
}

type sampleRow struct {
	PID            uint64
	ObjectAddress  uint64
	Name           string
	NameUnreadable bool
	Size           uint64
	SizeUnreadable bool
	When           time.Time
	Addr           netip.Addr
	Failure        error
	Data           []byte
	Tags           []string
	Other          sampleGroup
	Empty          sampleGroup
	SampleShared
	hidden string
}

func column0(t table, name string) int { return slices.Index(t.header, name) }

func TestFieldsBecomeColumnsInOrder(t *testing.T) {
	tb := tabulate([]sampleRow{{PID: 4, Other: sampleGroup{Count: 1}, SampleShared: SampleShared{Shared: 2}, hidden: "x"}}, nil)
	want := []string{"PID", "ObjectAddress", "Name", "Size", "When", "Addr", "Failure", "Data", "Tags", "Other.Count", "Other.Label", "Shared"}
	if !slices.Equal(tb.header, want) {
		t.Fatalf("header %q, want %q", tb.header, want)
	}
}

func TestAnUnreadableFlagMarksItsField(t *testing.T) {
	tb := tabulate([]sampleRow{
		{Name: "lsass.exe", NameUnreadable: true, Size: 0x10, SizeUnreadable: true},
		{Name: "", NameUnreadable: true},
		{Name: "smss.exe", Size: 0x20},
	}, nil)
	name, size := column0(tb, "Name"), column0(tb, "Size")
	got := []string{tb.rows[0][name], tb.rows[0][size], tb.rows[1][name], tb.rows[2][name], tb.rows[2][size]}
	want := []string{"lsass.exe" + cli.RestUnreadable, cli.Unreadable, cli.Unreadable, "smss.exe", "0x20"}
	if !slices.Equal(got, want) {
		t.Fatalf("cells %q, want %q", got, want)
	}
}

func TestAddressesPrintInHexAndIdentifiersInDecimal(t *testing.T) {
	tb := tabulate([]sampleRow{{PID: 1234, ObjectAddress: 0xffff8000}}, nil)
	if got := tb.rows[0][column0(tb, "PID")]; got != "1234" {
		t.Errorf("PID %q", got)
	}
	if got := tb.rows[0][column0(tb, "ObjectAddress")]; got != "0xffff8000" {
		t.Errorf("ObjectAddress %q", got)
	}
}

func TestAbsentValuesPrintAsADash(t *testing.T) {
	tb := tabulate([]sampleRow{{Other: sampleGroup{Count: 1}}}, nil)
	for _, name := range []string{"When", "Addr", "Failure"} {
		if got := tb.rows[0][column0(tb, name)]; got != absentCell {
			t.Errorf("%s %q, want %q", name, got, absentCell)
		}
	}
}

func TestValuesPrintByType(t *testing.T) {
	when := time.Date(2026, 5, 26, 20, 43, 43, 0, time.FixedZone("x", 3600))
	tb := tabulate([]sampleRow{{
		When:    when,
		Addr:    netip.MustParseAddr("10.0.0.1"),
		Failure: errors.New("bad\tbyte"),
		Tags:    []string{"a", "b"},
	}}, nil)
	row := tb.rows[0]
	checks := map[string]string{
		"When":    "2026-05-26T19:43:43Z",
		"Addr":    "10.0.0.1",
		"Failure": `bad\tbyte`,
		"Tags":    "[a, b]",
	}
	for name, want := range checks {
		if got := row[column0(tb, name)]; got != want {
			t.Errorf("%s %q, want %q", name, got, want)
		}
	}
}

func TestBytesShowTheirLengthAndAPrefix(t *testing.T) {
	data := make([]byte, bytesShown+8)
	for i := range data {
		data[i] = byte(i)
	}
	tb := tabulate([]sampleRow{{Data: data}}, nil)
	got := tb.rows[0][column0(tb, "Data")]
	want := "40 bytes " + hex.EncodeToString(data[:bytesShown]) + "..."
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := bytesCell(reflectValue([]byte{})); got != "0 bytes" {
		t.Fatalf("empty: %q", got)
	}
}

func TestAGroupZeroInEveryRowIsLeftOut(t *testing.T) {
	tb := tabulate([]sampleRow{{PID: 1}, {PID: 2}}, nil)
	for _, name := range tb.header {
		if strings.HasPrefix(name, "Other.") || strings.HasPrefix(name, "Empty.") || name == "Shared" {
			t.Errorf("column %s kept though zero in every row", name)
		}
	}
	tb = tabulate([]sampleRow{{PID: 1}, {PID: 2, Other: sampleGroup{Label: "x"}}}, nil)
	if column0(tb, "Other.Count") < 0 || column0(tb, "Empty.Count") >= 0 {
		t.Errorf("header %q: want Other kept and Empty left out", tb.header)
	}
}

type node struct {
	Name     string
	Children []*node
}

func TestChildRowsFollowTheirParentOnce(t *testing.T) {
	leaf := &node{Name: "c"}
	b := &node{Name: "b", Children: []*node{leaf}}
	a := &node{Name: "a", Children: []*node{b, nil}}
	leaf.Children = []*node{a}
	tb := tabulate([]*node{a, {Name: "d"}}, nil)
	var names []string
	for _, r := range tb.rows {
		names = append(names, r[0])
	}
	if !slices.Equal(names, []string{"a", "b", "c", "d"}) || !slices.Equal(tb.header, []string{"Name"}) {
		t.Fatalf("rows %q header %q", names, tb.header)
	}
}

func TestSecretFieldsPrintRedacted(t *testing.T) {
	tb := tabulate([]sampleRow{{Name: "x", Data: []byte("hunter2")}}, []string{"Data", "Name"})
	for _, name := range []string{"Data", "Name"} {
		if got := tb.rows[0][column0(tb, name)]; got != redactedCell {
			t.Errorf("%s %q", name, got)
		}
	}
	if !slices.Equal(tb.hidden, []string{"Name", "Data"}) {
		t.Errorf("hidden %q", tb.hidden)
	}
}

func TestResultsOtherThanAListOfRows(t *testing.T) {
	cases := []struct {
		name   string
		result any
		header []string
		rows   [][]string
	}{
		{"nil", nil, nil, nil},
		{"nil pointer", (*sampleRow)(nil), nil, nil},
		{"scalar", uint64(7), []string{"Value"}, [][]string{{"7"}}},
		{"bytes", []byte{1}, []string{"Value"}, [][]string{{"1 bytes 01"}}},
		{"strings", []string{"a", "b"}, []string{"Value"}, [][]string{{"a"}, {"b"}}},
		{"map", map[string]int{"b": 2, "a": 1}, []string{"Key", "Value"}, [][]string{{"a", "1"}, {"b", "2"}}},
		{"struct", &node{Name: "n"}, []string{"Name"}, [][]string{{"n"}}},
	}
	for _, c := range cases {
		tb := tabulate(c.result, nil)
		if !slices.Equal(tb.header, c.header) || !slices.EqualFunc(tb.rows, c.rows, slices.Equal) {
			t.Errorf("%s: header %q rows %q", c.name, tb.header, tb.rows)
		}
	}
}

func FuzzCellsArePrintableASCII(f *testing.F) {
	f.Add("lsass.exe", []byte{0, 9, 10}, "k", "v\r\n")
	f.Fuzz(func(t *testing.T, name string, data []byte, key, value string) {
		type row struct {
			Name           string
			NameUnreadable bool
			Data           []byte
			Values         map[string]string
			Items          []sampleGroup
		}
		tb := tabulate([]row{{Name: name, NameUnreadable: len(data)%2 == 1, Data: data,
			Values: map[string]string{key: value}, Items: []sampleGroup{{Label: value}}}}, nil)
		for _, c := range tb.rows[0] {
			for i := range len(c) {
				if c[i] < 0x20 || c[i] > 0x7e {
					t.Fatalf("cell %q holds byte 0x%02x", c, c[i])
				}
			}
		}
	})
}
