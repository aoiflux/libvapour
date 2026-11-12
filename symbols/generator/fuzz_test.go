package generator

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/btf"
	"github.com/aoiflux/libvapour/symbols/btf/btftest"
)

func fuzzSeeds() [][]byte {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	u32 := b.Int("unsigned int", 4, 0)
	anon := b.Union("", 8, btftest.Member{Name: "a", Type: i32}, btftest.Member{Name: "b", Type: b.Ptr(0)})
	fwd := b.Fwd("node", false)
	e := b.Enum("", 4, true, btftest.Value{Name: "E_A", Value: 0xffffffff})
	b.Typedef("mode_t", e)
	b.Typedef("u32", u32)
	b.Struct("rec", 32, btftest.Member{Name: "x", Type: i32},
		btftest.Member{Name: "bits", Type: u32, BitOffset: 32, BitSize: 5},
		btftest.Member{Type: anon, BitOffset: 64},
		btftest.Member{Name: "next", Type: b.Ptr(fwd), BitOffset: 128},
		btftest.Member{Name: "arr", Type: b.Array(u32, i32, 2), BitOffset: 192})
	b.Datasec(percpuSection, 8, [3]uint32{b.Var("v", i32, 1), 0, 4})
	return [][]byte{b.Bytes(), btftest.New().Bytes()}
}

// Whatever BTF parses, the generator gives a table that builds.
func FuzzTypesFromBTF(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	l := limits.Default()
	l.MaxNameBytes = 64
	l.MaxRecursionDepth = 64
	f.Fuzz(func(t *testing.T, data []byte) {
		spec, err := btf.Parse(data)
		if err != nil {
			return
		}
		out, err := TypesFromBTF(spec, 8, l)
		if errors.Is(err, ErrTooManyTypes) || errors.Is(err, ErrNoBTF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := symbols.BuildWith("fuzz", symbols.Declaration{PointerWidth: 8, Scalars: out.Scalars,
			Records: out.Records, Enumerations: out.Enumerations}, symbols.ReadOptions{MaxTableEntries: 1 << 16}); err != nil {
			t.Fatalf("generated table does not build: %v", err)
		}
	})
}
