package btf_test

import (
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols/btf"
	"github.com/aoiflux/libvapour/symbols/btf/btftest"
)

// oneOfEach writes one record of every kind and returns the kinds by id.
func oneOfEach(order binary.ByteOrder) ([]byte, []btf.Kind) {
	b := btftest.New()
	b.Order = order
	sint := b.Int("int", 4, btf.IntSigned)
	ptr := b.Ptr(sint)
	arr := b.Array(sint, sint, 4)
	st := b.Struct("pair", 8, btftest.Member{Name: "a", Type: sint}, btftest.Member{Name: "b", Type: sint, BitOffset: 32})
	un := b.Union("either", 4, btftest.Member{Name: "x", Type: sint}, btftest.Member{Name: "flag", Type: sint, BitSize: 1})
	en := b.Enum("colour", 4, true, btftest.Value{Name: "RED", Value: 0xffffffff}, btftest.Value{Name: "BLUE", Value: 2})
	fwd := b.Fwd("later", true)
	td := b.Typedef("pair_t", st)
	vol := b.Volatile(sint)
	cst := b.Const(sint)
	rst := b.Restrict(ptr)
	proto := b.FuncProto(sint, btftest.Param{Name: "n", Type: sint}, btftest.Param{})
	fn := b.Func("count", proto)
	v := b.Var("counter", sint, 1)
	ds := b.Datasec(".data..percpu", 64, [3]uint32{v, 8, 4})
	fl := b.Float("double", 8)
	tag := b.DeclTag("user", st, 1)
	tt := b.TypeTag("percpu", sint)
	e64 := b.Enum64("wide", 8, false, btftest.Value{Name: "BIG", Value: 1 << 40})
	_ = []uint32{arr, un, en, fwd, td, vol, cst, rst, fn, ds, fl, tag, tt, e64}
	return b.Bytes(), []btf.Kind{0, btf.KindInt, btf.KindPtr, btf.KindArray, btf.KindStruct, btf.KindUnion, btf.KindEnum,
		btf.KindFwd, btf.KindTypedef, btf.KindVolatile, btf.KindConst, btf.KindRestrict, btf.KindFuncProto, btf.KindFunc,
		btf.KindVar, btf.KindDatasec, btf.KindFloat, btf.KindDeclTag, btf.KindTypeTag, btf.KindEnum64}
}

func TestEveryKindReadsInEitherByteOrder(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		data, kinds := oneOfEach(order)
		spec, err := btf.Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", order, err)
		}
		if spec.ByteOrder != order || len(spec.Types) != len(kinds) {
			t.Fatalf("%s: %d types in %s", order, len(spec.Types), spec.ByteOrder)
		}
		for id, k := range kinds {
			if spec.Types[id].Kind != k {
				t.Errorf("%s: type %d is %s, want %s", order, id, spec.Types[id].Kind, k)
			}
		}
		ty := spec.Types
		if i := ty[1]; i.Name != "int" || i.Size != 4 || i.IntEncoding != btf.IntSigned || i.IntBits != 32 || i.IntOffset != 0 {
			t.Errorf("int %+v", i)
		}
		if a := ty[3]; a.ArrayElem != 1 || a.ArrayIndex != 1 || a.ArrayCount != 4 || a.Size != 0 {
			t.Errorf("array %+v", a)
		}
		if s := ty[4]; s.KindFlag || !reflect.DeepEqual(s.Members, []btf.Member{{Name: "a", Type: 1}, {Name: "b", Type: 1, BitOffset: 32}}) {
			t.Errorf("struct %+v", s)
		}
		if u := ty[5]; !u.KindFlag || u.Members[1] != (btf.Member{Name: "flag", Type: 1, BitSize: 1}) {
			t.Errorf("union with a bitfield %+v", u)
		}
		if e := ty[6]; !e.KindFlag || e.Values[0] != (btf.EnumValue{Name: "RED", Value: 0xffffffff}) {
			t.Errorf("enum %+v: a 32-bit value is kept as its pattern", e)
		}
		if f := ty[7]; f.Name != "later" || !f.KindFlag {
			t.Errorf("fwd %+v", f)
		}
		if p := ty[12]; p.Ref != 1 || !reflect.DeepEqual(p.Params, []btf.Param{{Name: "n", Type: 1}, {}}) {
			t.Errorf("proto %+v", p)
		}
		if f := ty[13]; f.Ref != 12 || f.Linkage != 1 {
			t.Errorf("func %+v", f)
		}
		if v := ty[14]; v.Ref != 1 || v.Linkage != 1 {
			t.Errorf("var %+v", v)
		}
		if d := ty[15]; d.Size != 64 || d.Vars[0] != (btf.VarSecInfo{Type: 14, Offset: 8, Size: 4}) {
			t.Errorf("datasec %+v", d)
		}
		if d := ty[17]; d.Ref != 4 || d.Component != 1 {
			t.Errorf("decl tag %+v", d)
		}
		if e := ty[19]; e.Values[0].Value != 1<<40 || e.Size != 8 {
			t.Errorf("enum64 %+v", e)
		}
	}
}

func put32(b []byte, at int, v uint32) []byte {
	out := append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(out[at:], v)
	return out
}

func TestTheHeaderAndSectionsAreTheKernelsLayout(t *testing.T) {
	data, _ := oneOfEach(binary.LittleEndian)
	typeLen := binary.LittleEndian.Uint32(data[12:])
	cases := map[string]struct {
		data []byte
		want error
	}{
		"short":              {data[:20], btf.ErrHeader},
		"magic":              {append([]byte{0x12, 0x34}, data[2:]...), btf.ErrHeader},
		"version":            {append(append([]byte(nil), data[:2]...), append([]byte{2}, data[3:]...)...), btf.ErrHeader},
		"flags":              {append(append([]byte(nil), data[:3]...), append([]byte{1}, data[4:]...)...), btf.ErrHeader},
		"hdr_len short":      {put32(data, 4, 20), btf.ErrHeader},
		"hdr_len past end":   {put32(data, 4, uint32(len(data)+1)), btf.ErrHeader},
		"type section moved": {put32(data, 8, 4), btf.ErrSections},
		"no types":           {put32(put32(data, 12, 0), 16, 0), btf.ErrSections},
		"gap before strings": {put32(data, 16, typeLen+4), btf.ErrSections},
		"strings short":      {put32(data, 20, binary.LittleEndian.Uint32(data[20:])-1), btf.ErrSections},
		"trailing bytes":     {append(append([]byte(nil), data...), 0), btf.ErrSections},
		"first string":       {append(append([]byte(nil), data[:24+typeLen]...), append([]byte{'x'}, data[25+typeLen:]...)...), btf.ErrStrings},
		"last string":        {append(append([]byte(nil), data[:len(data)-1]...), 'x'), btf.ErrStrings},
	}
	for name, tc := range cases {
		if _, err := btf.Parse(tc.data); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	long := append(append(append([]byte(nil), data[:24]...), 0, 0, 0, 0), data[24:]...)
	long = put32(long, 4, 28)
	if _, err := btf.Parse(long); err != nil {
		t.Errorf("a longer header of zeros: %v", err)
	}
	long[25] = 1
	if _, err := btf.Parse(long); !errors.Is(err, btf.ErrHeader) {
		t.Errorf("a longer header with a set byte: %v", err)
	}
}

func TestARecordBreakingItsKindsRulesIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		build func(*btftest.Builder)
		want  error
	}{
		"kind 0":            {func(b *btftest.Builder) { b.Raw("", btftest.Info(0, 0, false), 0) }, btf.ErrRecord},
		"kind 20":           {func(b *btftest.Builder) { b.Raw("", btftest.Info(20, 0, false), 0) }, btf.ErrRecord},
		"unused info bits":  {func(b *btftest.Builder) { b.Raw("", btftest.Info(2, 0, false)|1<<16, 1) }, btf.ErrRecord},
		"int encoding":      {func(b *btftest.Builder) { b.Raw("i", btftest.Info(1, 0, false), 4, 3<<24|32) }, btf.ErrRecord},
		"int bits":          {func(b *btftest.Builder) { b.Raw("i", btftest.Info(1, 0, false), 4, 33) }, btf.ErrRecord},
		"int past 128 bits": {func(b *btftest.Builder) { b.Raw("i", btftest.Info(1, 0, false), 32, 0x80<<16|0x80) }, btf.ErrRecord},
		"int unused bits":   {func(b *btftest.Builder) { b.Raw("i", btftest.Info(1, 0, false), 4, 1<<28|32) }, btf.ErrRecord},
		"array with size":   {func(b *btftest.Builder) { b.Raw("", btftest.Info(3, 0, false), 4, 0, 0, 1) }, btf.ErrRecord},
		"fwd with type":     {func(b *btftest.Builder) { b.Raw("f", btftest.Info(7, 0, false), 1) }, btf.ErrRecord},
		"members cut short": {func(b *btftest.Builder) { b.Raw("s", btftest.Info(4, 2, false), 4, 0, 0, 0) }, btf.ErrRecord},
		"dangling pointer":  {func(b *btftest.Builder) { b.Ptr(9) }, btf.ErrReference},
		"dangling member":   {func(b *btftest.Builder) { b.Struct("s", 4, btftest.Member{Name: "m", Type: 5}) }, btf.ErrReference},
		"dangling element":  {func(b *btftest.Builder) { b.Array(1, 7, 1) }, btf.ErrReference},
		"dangling param":    {func(b *btftest.Builder) { b.FuncProto(0, btftest.Param{Type: 3}) }, btf.ErrReference},
		"dangling var":      {func(b *btftest.Builder) { b.Datasec(".d", 4, [3]uint32{6, 0, 4}) }, btf.ErrReference},
	} {
		b := btftest.New()
		b.Int("int", 4, btf.IntSigned)
		tc.build(b)
		if _, err := btf.Parse(b.Bytes()); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	b := btftest.New()
	b.Int("int", 4, btf.IntSigned)
	data := b.Bytes()
	data = put32(data, 24, 0x1000)
	if _, err := btf.Parse(data); !errors.Is(err, btf.ErrRecord) {
		t.Errorf("name offset past the strings: %v", err)
	}
}

type mapped struct {
	at   uint64
	data []byte
}

func (m mapped) ReadAt(offset, size uint64) ([]byte, error) {
	if offset < m.at || offset-m.at > uint64(len(m.data)) || size > uint64(len(m.data))-(offset-m.at) {
		return nil, memory.ErrUnmapped
	}
	return append([]byte(nil), m.data[offset-m.at:offset-m.at+size]...), nil
}

func (mapped) Size() uint64 { return math.MaxUint64 }

func TestTheKernelsSpanIsReadWhole(t *testing.T) {
	data, kinds := oneOfEach(binary.LittleEndian)
	const at = 0xffffffff82000000
	m := mapped{at: at, data: data}
	raw, spec, err := btf.ReadKernel(m, at, at+uint64(len(data)), limits.Limits{})
	if err != nil || len(raw) != len(data) || len(spec.Types) != len(kinds) {
		t.Fatalf("ReadKernel: %d bytes, %v", len(raw), err)
	}
	for name, span := range map[string][2]uint64{
		"empty":     {at, at},
		"backwards": {at + 8, at},
		"too long":  {at, at + 1<<20},
		"past":      {at, at + uint64(len(data)) + 1},
	} {
		if _, _, err := btf.ReadKernel(m, span[0], span[1], limits.Limits{MaxKernelImageBytes: 1 << 19}); !errors.Is(err, btf.ErrKernelSpan) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := btf.ReadKernel(m, at, at+uint64(len(data))-1, limits.Limits{}); !errors.Is(err, btf.ErrSections) {
		t.Errorf("a span one byte short: %v", err)
	}
}

func TestKindNamesAreTheHeadersSuffixes(t *testing.T) {
	if btf.KindFuncProto.String() != "FUNC_PROTO" || btf.KindEnum64.String() != "ENUM64" || btf.Kind(25).String() != "kind 25" {
		t.Error("kind names")
	}
}
