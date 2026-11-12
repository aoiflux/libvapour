package btf_test

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/symbols/btf"
)

// A blob that parses names only types it holds, starts with void, and gives
// each kind only the fields its record carries.
func FuzzParse(f *testing.F) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		data, _ := oneOfEach(order)
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		spec, err := btf.Parse(data)
		if err != nil {
			return
		}
		last := uint32(len(spec.Types) - 1)
		if len(spec.Types) < 2 || spec.Types[0].Kind != btf.KindUnknown {
			t.Fatalf("%d types, first %s", len(spec.Types), spec.Types[0].Kind)
		}
		for id, ty := range spec.Types[1:] {
			if ty.Kind == btf.KindUnknown || ty.Kind > btf.KindEnum64 || ty.Ref > last || ty.ArrayElem > last || ty.ArrayIndex > last {
				t.Fatalf("type %d: %+v", id+1, ty)
			}
			for _, m := range ty.Members {
				if m.Type > last || !ty.KindFlag && m.BitSize != 0 || m.BitSize > 0xff || m.BitOffset > 0xffffff && ty.KindFlag {
					t.Fatalf("type %d member %+v", id+1, m)
				}
			}
			if ty.Kind != btf.KindStruct && ty.Kind != btf.KindUnion && len(ty.Members) > 0 ||
				ty.Kind != btf.KindEnum && ty.Kind != btf.KindEnum64 && len(ty.Values) > 0 {
				t.Fatalf("type %d of kind %s holds another kind's fields", id+1, ty.Kind)
			}
			if ty.Kind == btf.KindInt && (int(ty.IntOffset)+int(ty.IntBits)+7)/8 > int(ty.Size) {
				t.Fatalf("int %d: %d bits at %d in %d bytes", id+1, ty.IntBits, ty.IntOffset, ty.Size)
			}
		}
	})
}
