package credentiallocal

import (
	"encoding/hex"
	"testing"
)

// RFC 1320 appendix A.5 test suite (S20 D7).
func TestMD4MatchesTheRFC1320Vectors(t *testing.T) {
	cases := map[string]string{
		"":                           "31d6cfe0d16ae931b73c59d7e0c089c0",
		"a":                          "bde52cb31de33e46245e05fbdbd6fb24",
		"abc":                        "a448017aaf21d8525fc10ae87aa6729d",
		"message digest":             "d9130a8164549fe818874806e1c7014b",
		"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "043f8582f241db351ce627e153e7f0e4",
	}
	for in, want := range cases {
		got := md4Sum([]byte(in))
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("md4 %q = %x, want %s", in, got, want)
		}
	}
}

func FuzzMD4(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("abc"))
	f.Add(make([]byte, 120))
	f.Fuzz(func(t *testing.T, msg []byte) {
		if md4Sum(msg) != md4Sum(append([]byte(nil), msg...)) {
			t.Fatal("md4 is not deterministic")
		}
	})
}
