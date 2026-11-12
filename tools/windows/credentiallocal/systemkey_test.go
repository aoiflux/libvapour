package credentiallocal

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"unicode/utf16"
)

func classOf(fourHexBytes []byte) []byte {
	s := hex.EncodeToString(fourHexBytes)
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2*len(units))
	for _, u := range units {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

func TestDeriveSystemKeyReordersTheFourClassParts(t *testing.T) {
	parts := map[string][]byte{
		"JD":    {0, 1, 2, 3},
		"Skew1": {4, 5, 6, 7},
		"GBG":   {8, 9, 10, 11},
		"Data":  {12, 13, 14, 15},
	}
	classes := map[string][]byte{}
	for name, p := range parts {
		classes[name] = classOf(p)
	}
	key, ok := deriveSystemKey(classes)
	if !ok {
		t.Fatal("not derived")
	}
	// scrambled = 0..15 in order; key[i] = scrambled[systemKeyOrder[i]].
	want := make([]byte, 16)
	for i := range want {
		want[i] = byte(systemKeyOrder[i])
	}
	if !bytes.Equal(key, want) {
		t.Errorf("key = %x, want %x", key, want)
	}
}

func TestDeriveSystemKeyFailsOnAMissingPart(t *testing.T) {
	classes := map[string][]byte{
		"JD":    classOf([]byte{1, 2, 3, 4}),
		"Skew1": classOf([]byte{5, 6, 7, 8}),
		"GBG":   classOf([]byte{9, 10, 11, 12}),
	}
	if _, ok := deriveSystemKey(classes); ok {
		t.Error("derived without Data")
	}
}

func TestDeriveSystemKeyFailsOnANonHexClass(t *testing.T) {
	classes := map[string][]byte{
		"JD":    nameBytes("zzzz"),
		"Skew1": classOf([]byte{5, 6, 7, 8}),
		"GBG":   classOf([]byte{9, 10, 11, 12}),
		"Data":  classOf([]byte{13, 14, 15, 16}),
	}
	if _, ok := deriveSystemKey(classes); ok {
		t.Error("derived from a non-hex class")
	}
}
