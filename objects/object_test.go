package objects

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
)

type flat []byte

func (f flat) ReadAt(offset, size uint64) ([]byte, error) {
	if offset > uint64(len(f)) || size > uint64(len(f))-offset {
		return nil, fmt.Errorf("0x%x bytes at 0x%x: past the end", size, offset)
	}
	return f[offset : offset+size], nil
}

func (f flat) Size() uint64 { return uint64(len(f)) }

type short struct{ flat }

func (s short) ReadAt(offset, size uint64) ([]byte, error) {
	b, err := s.flat.ReadAt(offset, size)
	if err != nil || len(b) == 0 {
		return b, err
	}
	return b[:len(b)-1], nil
}

func tableOf(t testing.TB, width int) *symbols.Table {
	t.Helper()
	doc := strings.ReplaceAll(`{
  "vsym": 1,
  "pointer_width": WIDTH,
  "scalars": [
    {"name": "unsigned char", "width": 1, "kind": "integer"},
    {"name": "unsigned short", "width": 2, "kind": "integer"},
    {"name": "unsigned long", "width": 4, "kind": "integer"},
    {"name": "unsigned long long", "width": 8, "kind": "integer"}
  ],
  "records": [
    {"name": "_INNER", "width": 8, "members": [
      {"name": "Low", "offset": 0, "type": "unsigned long"},
      {"name": "High", "offset": 4, "type": "unsigned long"}
    ]},
    {"name": "_OUTER", "width": 64, "members": [
      {"name": "Byte", "offset": 0, "type": "unsigned char"},
      {"name": "Word", "offset": 2, "type": "unsigned short"},
      {"name": "Long", "offset": 4, "type": "unsigned long"},
      {"name": "Quad", "offset": 8, "type": "unsigned long long"},
      {"name": "Flags", "offset": 16, "type": "@3:5 unsigned long"},
      {"name": "Self", "offset": 24, "type": "*_OUTER"},
      {"name": "Indirect", "offset": 32, "type": "**_OUTER"},
      {"name": "Routine", "offset": 40, "type": "*"},
      {"name": "Inner", "offset": 48, "type": "_INNER"},
      {"name": "Name", "offset": 56, "type": "[4]unsigned char"},
      {"name": "Tail", "offset": 64, "type": "[0]unsigned char"}
    ]}
  ]
}`, "WIDTH", fmt.Sprint(width))
	table, err := symbols.Decode("test", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func image() flat {
	mem := make(flat, 0x200)
	for i := range mem {
		mem[i] = 0xee
	}
	mem[0x100] = 0x11
	binary.LittleEndian.PutUint16(mem[0x102:], 0x2233)
	binary.LittleEndian.PutUint32(mem[0x104:], 0x44556677)
	binary.LittleEndian.PutUint64(mem[0x108:], 0x8899aabbccddeeff)
	binary.LittleEndian.PutUint32(mem[0x110:], 0b1011_0101_000)
	binary.LittleEndian.PutUint64(mem[0x118:], 0x100)
	binary.LittleEndian.PutUint64(mem[0x120:], 0x118)
	binary.LittleEndian.PutUint64(mem[0x128:], 0)
	binary.LittleEndian.PutUint32(mem[0x130:], 7)
	binary.LittleEndian.PutUint32(mem[0x134:], 9)
	copy(mem[0x138:], "abcd")
	copy(mem[0x140:], "tail bytes")
	return mem
}

func TestEachIntegerIsReadAtItsOwnWidth(t *testing.T) {
	o := New(image(), tableOf(t, 8), "_OUTER", 0x100)
	for _, tc := range []struct {
		member string
		want   uint64
	}{
		{"Byte", 0x11},
		{"Word", 0x2233},
		{"Long", 0x44556677},
		{"Quad", 0x8899aabbccddeeff},
		{"Flags", 0b10101},
		{"Self", 0x100},
	} {
		got, err := o.Uint64(tc.member)
		if err != nil || got != tc.want {
			t.Errorf("Uint64(%s) = %#x, %v; want %#x", tc.member, got, err, tc.want)
		}
		if tc.member == "Quad" || tc.member == "Self" {
			if _, err := o.Uint32(tc.member); err == nil {
				t.Errorf("Uint32(%s) read an 8-byte member", tc.member)
			}
			continue
		}
		got32, err := o.Uint32(tc.member)
		if err != nil || uint64(got32) != tc.want {
			t.Errorf("Uint32(%s) = %#x, %v; want %#x", tc.member, got32, err, tc.want)
		}
	}
}

func TestOnlyIntegersReadAsIntegers(t *testing.T) {
	o := New(image(), tableOf(t, 8), "_OUTER", 0x100)
	for _, name := range []string{"Inner", "Name", "Tail"} {
		if _, err := o.Uint64(name); err == nil {
			t.Errorf("Uint64(%s) read a member that is not an integer", name)
		}
	}
	_, err := o.Uint64("Missing")
	var unknown symbols.UnknownFieldError
	if !errors.As(err, &unknown) {
		t.Errorf("a missing member gave %v, want the table's UnknownFieldError", err)
	}
}

func TestAPointerLeadsToTheTypeItNames(t *testing.T) {
	o := New(image(), tableOf(t, 8), "_OUTER", 0x100)
	next, err := o.Pointer("Self")
	if err != nil || next.TypeName != "_OUTER" || next.Offset != 0x100 {
		t.Fatalf("Pointer(Self) = %+v, %v", next, err)
	}
	for _, name := range []string{"Indirect", "Routine", "Long", "Inner"} {
		if _, err := o.Pointer(name); err == nil {
			t.Errorf("Pointer(%s) gave an object", name)
		}
	}
}

func TestANullPointerIsItsOwnError(t *testing.T) {
	mem := image()
	binary.LittleEndian.PutUint64(mem[0x118:], 0)
	_, err := New(mem, tableOf(t, 8), "_OUTER", 0x100).Pointer("Self")
	if !errors.Is(err, ErrNullPointer) {
		t.Errorf("a zero pointer gave %v, want ErrNullPointer", err)
	}
	if err == nil || !strings.Contains(err.Error(), "_OUTER.Self at 0x118") {
		t.Errorf("the error %q does not name the member and its address", err)
	}
}

func TestAPointerIsAsWideAsTheTablesPointers(t *testing.T) {
	mem := image()
	binary.LittleEndian.PutUint64(mem[0x118:], 0xdeadbeef_00000100)
	o := New(mem, tableOf(t, 4), "_OUTER", 0x100)
	next, err := o.Pointer("Self")
	if err != nil || next.Offset != 0x100 {
		t.Errorf("a 4-byte pointer read as %#x, %v; want 0x100", next.Offset, err)
	}
	if v, err := o.Uint32("Self"); err != nil || v != 0x100 {
		t.Errorf("Uint32 of a 4-byte pointer = %#x, %v", v, err)
	}
}

func TestStructStaysInPlace(t *testing.T) {
	o := New(image(), tableOf(t, 8), "_OUTER", 0x100)
	inner, err := o.Struct("Inner")
	if err != nil || inner.TypeName != "_INNER" || inner.Offset != 0x130 {
		t.Fatalf("Struct(Inner) = %+v, %v", inner, err)
	}
	if v, err := inner.Uint32("High"); err != nil || v != 9 {
		t.Errorf("_INNER.High = %d, %v; want 9", v, err)
	}
	for _, name := range []string{"Self", "Long", "Name"} {
		if _, err := o.Struct(name); err == nil {
			t.Errorf("Struct(%s) gave an object", name)
		}
	}
}

func TestBytesStayInsideTheMember(t *testing.T) {
	o := New(image(), tableOf(t, 8), "_OUTER", 0x100)
	if b, err := o.Bytes("Name", 4); err != nil || string(b) != "abcd" {
		t.Errorf("Bytes(Name, 4) = %q, %v", b, err)
	}
	if _, err := o.Bytes("Name", 5); err == nil {
		t.Error("Bytes read past a 4-byte member")
	}
	if b, err := o.Bytes("Tail", 10); err != nil || string(b) != "tail bytes" {
		t.Errorf("Bytes of a trailing array = %q, %v", b, err)
	}
	if b, err := o.Bytes("Name", 0); err != nil || len(b) != 0 {
		t.Errorf("Bytes(Name, 0) = %q, %v", b, err)
	}
	if _, err := New(short{image()}, tableOf(t, 8), "_OUTER", 0x100).Bytes("Name", 4); err == nil {
		t.Error("a short read was taken as the member")
	}
}

func TestReadsThatCannotHappenAreRefused(t *testing.T) {
	table := tableOf(t, 8)
	if _, err := New(nil, table, "_OUTER", 0).Uint32("Long"); !errors.Is(err, errNoSource) {
		t.Errorf("no reader gave %v", err)
	}
	if _, err := New(image(), nil, "_OUTER", 0).Uint32("Long"); !errors.Is(err, errNoSource) {
		t.Errorf("no table gave %v", err)
	}
	if _, err := New(image(), table, "_OUTER", ^uint64(0)-2).Uint32("Long"); err == nil {
		t.Error("a member past the top of the address space was read")
	}
	if _, err := New(image(), table, "_OUTER", 0x1fc).Uint64("Quad"); err == nil {
		t.Error("a member past the image's end was read")
	}
}

func FuzzObjectReads(f *testing.F) {
	f.Add([]byte(image()[0x100:0x180]), uint64(0), uint64(4))
	f.Add([]byte{1, 2, 3}, uint64(0), uint64(2))
	f.Add([]byte{}, ^uint64(0), ^uint64(0))
	table := tableOf(f, 8)
	f.Fuzz(func(t *testing.T, data []byte, at, length uint64) {
		o := New(flat(data), table, "_OUTER", at)
		if v, err := o.Uint32("Long"); err == nil {
			if at+8 > uint64(len(data)) || binary.LittleEndian.Uint32(data[at+4:]) != v {
				t.Fatalf("Uint32(Long) = %#x from %x at %d", v, data, at)
			}
		}
		if b, err := o.Bytes("Name", length); err == nil && (length > 4 || uint64(len(b)) != length) {
			t.Fatalf("Bytes(Name, %d) gave %d bytes", length, len(b))
		}
		_, _ = o.Uint64("Flags")
		_, _ = o.Pointer("Self")
		_, _ = o.Struct("Inner")
	})
}
