package credentiallsasecrets

import (
	"testing"
)

func FuzzOpenProtectedValue(f *testing.F) {
	f.Add(seal(madeUpPolicyKey, madeUpKeyID, madeUpSalt, []byte("made-up")), madeUpPolicyKey)
	f.Add(sealedKeyList(), madeUpSystemKey)
	f.Add([]byte{0, 0, 0, 1}, []byte{1})
	f.Fuzz(func(t *testing.T, raw, key []byte) {
		if len(key) != 16 && len(key) != 32 {
			key = madeUpPolicyKey
		}
		value, err := openProtected(raw, key)
		if err == nil && len(value) > len(raw) {
			t.Fatalf("value of %d bytes from %d", len(value), len(raw))
		}
	})
}

func FuzzParseKeyList(f *testing.F) {
	f.Add(keyListBytes(madeUpKeyID, fixtureKey{madeUpKeyID, madeUpPolicyKey}))
	f.Add(keyListBytes(madeUpKeyID, fixtureKey{madeUpKeyID, madeUpPolicyKey}, fixtureKey{madeUpOtherID, madeUpOlderKey}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, list []byte) {
		kl, err := parseKeyList(list)
		if err == nil && len(kl.Keys[kl.CurrentID]) != policyKeyLen {
			t.Fatalf("current key of %d bytes", len(kl.Keys[kl.CurrentID]))
		}
	})
}
