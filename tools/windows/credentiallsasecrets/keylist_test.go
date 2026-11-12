package credentiallsasecrets

import (
	"bytes"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

func TestTheKeyListResolvesEveryIdentifier(t *testing.T) {
	kl, err := ReadKeyList(securityHive(sealedKeyList()), madeUpSystemKey)
	if err != nil {
		t.Fatal(err)
	}
	if kl.CurrentID != madeUpKeyID {
		t.Error("current identifier differs")
	}
	if !bytes.Equal(kl.Keys[madeUpKeyID], madeUpPolicyKey) || !bytes.Equal(kl.Keys[madeUpOtherID], madeUpOlderKey) {
		t.Error("an entry's key differs")
	}
}

func TestAKeyListUnderAnotherSystemKeyIsRejected(t *testing.T) {
	wrong := append([]byte(nil), madeUpSystemKey...)
	wrong[15] ^= 0x80
	if _, err := ReadKeyList(securityHive(sealedKeyList()), wrong); !errors.Is(err, ErrPolicyKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestKeyListChecks(t *testing.T) {
	short := bytes.Repeat([]byte{9}, 16)
	for name, list := range map[string][]byte{
		"current not listed": keyListBytes(madeUpKeyID, fixtureKey{madeUpOtherID, madeUpOlderKey}),
		"current key short":  keyListBytes(madeUpKeyID, fixtureKey{madeUpKeyID, short}),
		"no entries":         keyListBytes(madeUpKeyID),
		"entry cut":          keyListBytes(madeUpKeyID, fixtureKey{madeUpKeyID, madeUpPolicyKey})[:listEntriesOffset+entryHeaderLen+8],
		"header cut":         keyListBytes(madeUpKeyID)[:20],
	} {
		if _, err := parseKeyList(list); !errors.Is(err, ErrPolicyKey) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestAnAbsentKeyListSaysWhichFormTheHiveHolds(t *testing.T) {
	if _, err := ReadKeyList(securityHive(nil), madeUpSystemKey); !errors.Is(err, ErrPolicyKeyAbsent) {
		t.Errorf("absent: err = %v", err)
	}
	legacy := securityHive(nil)
	legacy.Values[legacy.Path(legacyPolicyPath)] = []registryhive.Value{defaultSecValue([]byte{1, 2, 3, 4})}
	if _, err := ReadKeyList(legacy, madeUpSystemKey); !errors.Is(err, ErrLegacyPolicyKey) {
		t.Errorf("legacy: err = %v", err)
	}
}

func TestAnUnreadableKeyListIsNotCalledAbsent(t *testing.T) {
	noRoot := securityHive(nil)
	noRoot.Root = nil
	if _, err := ReadKeyList(noRoot, madeUpSystemKey); !errors.Is(err, ErrPolicyKeyUnreadable) {
		t.Errorf("root: err = %v", err)
	}
	cut := securityHive(nil)
	cut.SubkeysIncomplete[cut.Path("Policy")] = true
	if _, err := ReadKeyList(cut, madeUpSystemKey); !errors.Is(err, ErrPolicyKeyUnreadable) {
		t.Errorf("subkeys: err = %v", err)
	}
	paged := securityHive(nil)
	k := paged.Path(keyListPath)
	paged.Values[k] = []registryhive.Value{{Name: defaultValueName, Length: 172}}
	if _, err := ReadKeyList(paged, madeUpSystemKey); !errors.Is(err, ErrPolicyKeyUnreadable) {
		t.Errorf("data: err = %v", err)
	}
	values := securityHive(nil)
	values.ValuesIncomplete[values.Path(keyListPath)] = true
	if _, err := ReadKeyList(values, madeUpSystemKey); !errors.Is(err, ErrPolicyKeyUnreadable) {
		t.Errorf("values: err = %v", err)
	}
}
