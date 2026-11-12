package linuxkern_test

import (
	"bytes"
	"errors"
	"testing"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

func FuzzReadString(f *testing.F) {
	f.Add([]byte("init\x00"), uint16(0xffc), uint16(16), false)
	f.Add([]byte("abcdefgh"), uint16(0), uint16(8), true)
	f.Add([]byte{0xff, 0xfe, 'a'}, uint16(0xffe), uint16(300), false)
	f.Fuzz(func(t *testing.T, data []byte, at, count uint16, hole bool) {
		const base = 0xffff888000000000
		mem := kerntest.NewMemory()
		mem.Map(base, 0x3000)
		mem.Write(base+uint64(at), data)
		if hole {
			mem.Unmap(base + 0x1000)
		}
		s, err := linuxkern.ReadString(mem, base+uint64(at), uint64(count))
		if err != nil {
			if count != 0 && !errors.Is(err, linuxkern.ErrStringUnread) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if !utf8.ValidString(s) || bytes.IndexByte([]byte(s), 0) >= 0 {
			t.Fatalf("%q: invalid text or a NUL", s)
		}
		if n := utf8.RuneCountInString(s); n > int(count) {
			t.Fatalf("%d runes from at most %d bytes", n, count)
		}
	})
}

type fuzzTable struct {
	field symbols.Field
	width uint64
}

func (fuzzTable) Name() string       { return "fuzz" }
func (fuzzTable) PointerSize() uint8 { return 8 }
func (fuzzTable) Struct(name string) (symbols.StructType, error) {
	return symbols.StructType{}, symbols.UnknownTypeError{TypeName: name}
}
func (t fuzzTable) Field(typ, name string) (symbols.Field, error) { return t.field, nil }
func (fuzzTable) LookupSymbol(name string) (symbols.Symbol, error) {
	return symbols.Symbol{}, errors.New("fuzz: no symbols")
}
func (fuzzTable) ReadUint32(memory.MemoryReader, uint64) (uint32, error) {
	return 0, errors.New("fuzz")
}
func (fuzzTable) ReadUint64(memory.MemoryReader, uint64) (uint64, error) {
	return 0, errors.New("fuzz")
}
func (fuzzTable) ReadPointer(memory.MemoryReader, uint64) (uint64, error) {
	return 0, errors.New("fuzz")
}
func (fuzzTable) ReadStruct(memory.MemoryReader, string, uint64) (symbols.StructInstance, error) {
	return symbols.StructInstance{}, errors.New("fuzz")
}
func (t fuzzTable) FieldSize(typ, name string) (uint64, error) { return t.width, nil }

func FuzzIntegerMember(f *testing.F) {
	f.Add(uint8(4), uint8(3), uint8(4), "unsigned int", false, []byte{0xff, 0xff, 0xff, 0xff})
	f.Add(uint8(1), uint8(2), uint8(4), "signed char", false, []byte{0x3c})
	f.Add(uint8(8), uint8(0), uint8(0), "long int", false, []byte{1, 2, 3, 4, 5, 6, 7, 0x80})
	f.Add(uint8(0), uint8(0), uint8(0), "pointer", true, []byte{1})
	f.Fuzz(func(t *testing.T, width, bitOff, bitLen uint8, name string, ptr bool, data []byte) {
		field := symbols.Field{Name: "m", Offset: 0,
			Type: symbols.TypeRef{Name: name, IsPointer: ptr, BitOffset: bitOff, BitLength: bitLen}}
		in, err := linuxkern.IntegerMember(fuzzTable{field: field, width: uint64(width)}, "s", field, 0)
		if err != nil {
			if !errors.Is(err, linuxkern.ErrNotInteger) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if in.Width == 0 || in.Width > 8 || uint64(in.BitOffset)+uint64(in.BitLength) > 8*in.Width {
			t.Fatalf("accepted %+v", in)
		}
		mem := kerntest.NewMemory()
		mem.Write(0x1000, data)
		mem.Map(0x1000, 8)
		raw, err := in.Read(mem, 0x1000)
		if err != nil {
			return
		}
		bits := 8 * in.Width
		if in.BitLength > 0 {
			bits = uint64(in.BitLength)
		}
		if bits < 64 && raw>>bits != 0 {
			t.Fatalf("%#x has bits above its %d", raw, bits)
		}
		v := in.Value(raw)
		if !in.Signed && uint64(v) != raw {
			t.Fatalf("unsigned value %d from %#x", v, raw)
		}
		if in.Signed && bits < 64 && (v < -(1<<(bits-1)) || v >= 1<<(bits-1)) {
			t.Fatalf("signed value %d outside %d bits", v, bits)
		}
	})
}
