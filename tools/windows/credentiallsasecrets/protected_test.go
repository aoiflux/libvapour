package credentiallsasecrets

import (
	"bytes"
	"errors"
	"testing"
)

func TestASealedValueOpensToTheSameBytes(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 44, 64, 300} {
		value := bytes.Repeat([]byte{0x3c}, n)
		for _, excess := range []int{0, 1} {
			s := sealing{repeats: saltRepeats, excess: excess}
			raw := sealWith(s, madeUpPolicyKey, madeUpKeyID, madeUpSalt, value)
			got, err := openProtected(raw, madeUpPolicyKey)
			if err != nil {
				t.Fatalf("n %d excess %d: %v", n, excess, err)
			}
			if !bytes.Equal(got, value) {
				t.Fatalf("n %d excess %d: value differs", n, excess)
			}
		}
	}
}

func TestAWrongKeyIsRejected(t *testing.T) {
	raw := seal(madeUpPolicyKey, madeUpKeyID, madeUpSalt, bytes.Repeat([]byte{1}, 44))
	wrong := append([]byte(nil), madeUpPolicyKey...)
	wrong[0] ^= 1
	if _, err := openProtected(raw, wrong); !errors.Is(err, ErrProtectedValue) {
		t.Fatalf("err = %v", err)
	}
}

func TestTheMeasuredControlsDoNotOpen(t *testing.T) {
	value := bytes.Repeat([]byte{0x44}, 64)
	once := sealWith(sealing{repeats: 1, excess: 1}, madeUpPolicyKey, madeUpKeyID, madeUpSalt, value)
	if _, err := openProtected(once, madeUpPolicyKey); err == nil {
		t.Error("a key derived from one salt copy opened")
	}
	chained := sealWith(sealing{repeats: saltRepeats, chained: true, excess: 1}, madeUpPolicyKey, madeUpKeyID, madeUpSalt, value)
	if got, err := openProtected(chained, madeUpPolicyKey); err == nil && bytes.Equal(got, value) {
		t.Error("a chained seal reproduced its bytes")
	}
}

func TestAnExcessOverOneBlockIsRejected(t *testing.T) {
	raw := sealWith(sealing{repeats: saltRepeats, excess: 17}, madeUpPolicyKey, madeUpKeyID, madeUpSalt, []byte{1, 2, 3})
	if _, err := openProtected(raw, madeUpPolicyKey); !errors.Is(err, ErrProtectedValue) {
		t.Fatalf("err = %v", err)
	}
}

func TestMalformedValuesGetTheirSentinel(t *testing.T) {
	good := seal(madeUpPolicyKey, madeUpKeyID, madeUpSalt, []byte("made-up"))
	otherMarker := append([]byte(nil), good...)
	otherMarker[3] = 2
	otherScheme := append([]byte(nil), good...)
	otherScheme[protectedSchemeOffset] = 4
	for name, tc := range map[string]struct {
		raw  []byte
		want error
	}{
		"empty":            {nil, ErrProtectedValue},
		"header only":      {good[:protectedDataOffset], ErrProtectedValue},
		"partial block":    {good[:len(good)-1], ErrProtectedValue},
		"other marker":     {otherMarker, ErrProtectedScheme},
		"other scheme":     {otherScheme, ErrProtectedScheme},
		"sixty bytes only": {good[:60], ErrProtectedValue},
	} {
		if _, err := openProtected(tc.raw, madeUpPolicyKey); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}
