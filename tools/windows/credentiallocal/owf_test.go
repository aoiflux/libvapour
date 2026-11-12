package credentiallocal

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The published worked example of [MS-SAMR] 4.3 gives real hashes for two
// fixed strings; they are documentation vectors, not secrets.
func TestNTOWFv1AndLMOWFv1MatchTheMSSAMRExample(t *testing.T) {
	cases := []struct {
		pw, nt, lm string
	}{
		{"OLDPASSWORD", "6677b2c394311355b54f25eec5bfacf5", "c9b81d939d6fd80cd408e6b105741864"},
		{"NEWPASSWORD", "256781a62031289d3c2c98c14f1efc8c", "09eeab5aa415d6e4d408e6b105741864"},
	}
	for _, c := range cases {
		nt := NTOWFv1(c.pw)
		if got := hex.EncodeToString(nt[:]); got != c.nt {
			t.Errorf("NTOWFv1(%q) = %s, want %s", c.pw, got, c.nt)
		}
		lm, ok := LMOWFv1(c.pw)
		if !ok {
			t.Fatalf("LMOWFv1(%q) not computable", c.pw)
		}
		if got := hex.EncodeToString(lm[:]); got != c.lm {
			t.Errorf("LMOWFv1(%q) = %s, want %s", c.pw, got, c.lm)
		}
	}
}

func TestLMOWFv1RefusesLongOrNonASCIIPasswords(t *testing.T) {
	if _, ok := LMOWFv1("abcdefghijklmno"); ok {
		t.Error("15-character password should not be computable")
	}
	if _, ok := LMOWFv1("passé"); ok {
		t.Error("non-ASCII password should not be computable")
	}
}

// The 7-to-8 byte expansion vector of [MS-SAMR] 4.3 (S20 D3).
func TestExpandDESKeyMatchesTheMSSAMRExample(t *testing.T) {
	in := []byte{0x25, 0x67, 0x81, 0xa6, 0x20, 0x31, 0x28}
	want := []byte{0x25, 0xb3, 0xe0, 0x34, 0x62, 0x01, 0xc4, 0x51}
	if got := expandDESKey(in); !bytes.Equal(got, want) {
		t.Errorf("expandDESKey = %x, want %x", got, want)
	}
}
