package credentialtruecrypt

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	listHead    = uint64(0xfffff800_0000_1000)
	rangeStart  = uint64(0xfffff800_0000_2000)
	entryBase   = uint64(0xfffff800_0010_0000)
	imageBase   = uint64(0xfffff800_0100_0000)
	imageStride = uint64(0x0010_0000)
	textRVA     = uint64(0x1000)
	dataRVA     = uint64(0x2000)
	// MappedPELfanew + signature + file header + optional header.
	sectionTable = uint64(0x80 + 4 + 20 + 240)
)

func table() *symbols.Table {
	t := symbols.NewTable("s66-c", 8)
	f := func(name string, off uint64, typ string) symbols.Field {
		return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: typ}}
	}
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 16, Fields: []symbols.Field{f("Flink", 0, "_LIST_ENTRY"), f("Blink", 8, "_LIST_ENTRY")}})
	t.AddStruct(symbols.StructType{Name: "_UNICODE_STRING", Size: 16, Fields: []symbols.Field{
		f("Length", 0, "unsigned short"), f("MaximumLength", 2, "unsigned short"), f("Buffer", 8, "wchar_t")}})
	t.AddStruct(symbols.StructType{Name: "_KLDR_DATA_TABLE_ENTRY", Size: 0xa0, Fields: []symbols.Field{
		f("InLoadOrderLinks", 0, "_LIST_ENTRY"), f("DllBase", 0x30, "void"), f("SizeOfImage", 0x40, "unsigned int"),
		f("FullDllName", 0x48, "_UNICODE_STRING"), f("BaseDllName", 0x58, "_UNICODE_STRING")}})
	t.AddSymbol(symbols.Symbol{Name: "PsLoadedModuleList", Address: listHead})
	t.AddSymbol(symbols.Symbol{Name: "MmSystemRangeStart", Address: rangeStart})
	return t
}

type driver struct {
	name string
	text []byte
	data []byte
}

func counted(s string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(s)))
	return append(append(b, s...), 0)
}

// Each driver's image is the mapped fixture PE with .data made writable data.
func build(drivers ...driver) (*testsupport.S43Memory, *[]string, tools.Context) {
	m := testsupport.NewS43Memory()
	m.WriteU64(rangeStart, 0xffff8000_0000_0000)
	prev := listHead
	for i, d := range drivers {
		entry := entryBase + uint64(i)*0x1000
		base := imageBase + uint64(i)*imageStride
		img := testsupport.BuildMappedPE(base)
		binary.LittleEndian.PutUint32(img[sectionTable+40+36:], 0xC0000040)
		copy(img[textRVA:], d.text)
		copy(img[dataRVA:], d.data)
		m.Write(base, img)
		m.WriteU64(prev, entry)
		m.WriteU64(entry+8, prev)
		prev = entry
		m.WriteU64(entry+0x30, base)
		m.WriteU32(entry+0x40, uint32(len(img)))
		name := utf16LE(d.name)
		m.Write(entry+0x800, name)
		for _, at := range []uint64{0x48, 0x58} {
			m.WriteU16(entry+at, uint16(len(name)))
			m.WriteU16(entry+at+2, uint16(len(name)))
			m.WriteU64(entry+at+8, entry+0x800)
		}
	}
	m.WriteU64(prev, listHead)
	m.WriteU64(listHead+8, prev)
	var diags []string
	ctx := tools.Context{Memory: m, Symbols: table(), Profile: profiles.WindowsX64Profile{},
		Options: map[string]any{"diagnostics": &diags}}
	return m, &diags, ctx
}

func utf16LE(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

func TestCountedTextInAWritableSectionIsFound(t *testing.T) {
	data := append(make([]byte, 8), counted("correct horse")...)
	data = append(data, make([]byte, 3)...)
	data = append(data, counted("abc")...)
	_, _, ctx := build(driver{name: "TrueCrypt.sys", data: data, text: counted("in code")})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := Passphrase{Offset: imageBase + dataRVA + 8, Length: 13, Password: "correct horse", Section: ".data"}
	if len(rows) != 1 || rows[0] != want {
		t.Fatalf("rows = %+v, want only %+v (3 bytes is under the minimum; .text is not writable)", rows, want)
	}
}

func TestTheMinimumLengthOptionAndItsRange(t *testing.T) {
	_, _, ctx := build(driver{name: "truecrypt.sys", data: counted("abc")})
	ctx.Options[OptionMinLength] = uint64(3)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].Password != "abc" {
		t.Fatalf("rows %+v err %v, want abc", rows, err)
	}
	for _, bad := range []any{uint64(0), uint64(MaxLength + 1)} {
		ctx.Options[OptionMinLength] = bad
		if _, err := Run(ctx); !errors.Is(err, ErrMinLength) {
			t.Errorf("min length %v: err = %v, want ErrMinLength", bad, err)
		}
	}
	ctx.Options[OptionMinLength] = "five"
	if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("text min length: err = %v, want ErrOptionType", err)
	}
}

func TestEveryLoadedCopyOfTheDriverIsScannedAndNoOtherDriver(t *testing.T) {
	_, _, ctx := build(
		driver{name: "truecrypt.sys", data: counted("first one")},
		driver{name: "other.sys", data: counted("not this")},
		driver{name: "truecrypt.sys", data: counted("second one")},
	)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Password != "first one" || rows[1].Password != "second one" ||
		rows[1].Offset != imageBase+2*imageStride+dataRVA {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestNoDriverIsNoRows(t *testing.T) {
	_, diags, ctx := build(driver{name: "other.sys", data: counted("not this")})
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 || len(*diags) != 0 {
		t.Fatalf("rows %+v err %v diagnostics %q", rows, err, *diags)
	}
}

func TestHeadersThatDoNotReadAreReportedOrFailStrict(t *testing.T) {
	m, diags, ctx := build(driver{name: "truecrypt.sys"})
	m.Unmap(imageBase)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 || !strings.Contains(strings.Join(*diags, "\n"), "PE headers do not read") {
		t.Fatalf("rows %+v err %v diagnostics %q", rows, err, *diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Error("strict run accepted unreadable headers")
	}
}

func TestAnUnreadPageIsScannedAsZeroAndSaidSo(t *testing.T) {
	m, diags, ctx := build(driver{name: "truecrypt.sys", data: counted("kept text")})
	m.Unmap(imageBase + dataRVA)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 || !strings.Contains(strings.Join(*diags, "\n"), "do not read and are scanned as zero") {
		t.Fatalf("rows %+v err %v diagnostics %q", rows, err, *diags)
	}
}

func TestANonWindowsProfileIsRefused(t *testing.T) {
	_, _, ctx := build()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("err = %v", err)
	}
}

func TestFindCountedRules(t *testing.T) {
	for _, c := range []struct {
		name string
		data []byte
		want []Counted
	}{
		{"terminated", counted("hello"), []Counted{{0, "hello"}}},
		{"no terminator", append(binary.LittleEndian.AppendUint32(nil, 5), "hellox"...), nil},
		{"control byte", counted("he\x01lo"), nil},
		{"high byte", counted("he\xe9lo"), nil},
		{"unaligned", append([]byte{0, 0}, counted("hello")...), nil},
		{"runs past the end", binary.LittleEndian.AppendUint32(nil, 5), nil},
		{"two in a row", append(append(counted("hello"), 0, 0), counted("world")...), []Counted{{0, "hello"}, {12, "world"}}},
	} {
		got := FindCounted(c.data, 4, MaxLength)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
			}
		}
	}
	if got := FindCounted(counted(strings.Repeat("a", MaxLength+1)), 4, MaxLength); len(got) != 0 {
		t.Errorf("text over MaxLength found: %+v", got)
	}
}

func TestTheToolIsRegistered(t *testing.T) {
	if _, err := tools.Get(Name); err != nil {
		t.Fatal(err)
	}
}
