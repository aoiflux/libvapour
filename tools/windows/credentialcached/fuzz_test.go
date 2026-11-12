package credentialcached

import (
	"testing"
	"unicode/utf16"
)

func FuzzDecodeSlot(f *testing.F) {
	f.Add(sealSlot(aMadeUpLogon, madeUpCacheKey), madeUpCacheKey)
	f.Add(emptySlotBytes(), madeUpCacheKey)
	f.Add([]byte{}, []byte{1})
	f.Fuzz(func(t *testing.T, raw, key []byte) {
		if len(key) != 16 {
			key = madeUpCacheKey
		}
		u, err := decodeSlot(raw, key)
		if err != nil {
			return
		}
		if len(u.verifier) != verifierLen {
			t.Fatalf("verifier of %d bytes", len(u.verifier))
		}
		units := len(utf16.Encode([]rune(u.effectiveName + u.logonDomainName + u.dnsLogonDomainName)))
		if 2*units > len(raw) {
			t.Fatalf("names of %d units from %d bytes", units, len(raw))
		}
	})
}
