package credentialcached

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

var aMadeUpLogon = madeUpLogon{name: "made.up.user", domain: "MADEUP", dns: "madeup.example", userID: 1107, verifier: madeUpVerifier}

func TestASealedSlotDecodesToTheSameLogon(t *testing.T) {
	for _, l := range []madeUpLogon{
		aMadeUpLogon,
		{name: "a", domain: "B", dns: "", userID: 500, verifier: madeUpVerifier},
		{name: "ünïcødé-𝄞", domain: "DOM", dns: "dom.example", userID: 1, verifier: madeUpVerifier},
	} {
		u, err := decodeSlot(sealSlot(l, madeUpCacheKey), madeUpCacheKey)
		if err != nil {
			t.Fatalf("%q: %v", l.name, err)
		}
		if u.effectiveName != l.name || u.logonDomainName != l.domain || u.dnsLogonDomainName != l.dns || u.userID != l.userID {
			t.Errorf("%q: decoded %+v", l.name, u)
		}
		if !bytes.Equal(u.verifier, l.verifier) {
			t.Errorf("%q: verifier differs", l.name)
		}
	}
}

func TestSlotChecksRejectWithTheirSentinel(t *testing.T) {
	good := sealSlot(aMadeUpLogon, madeUpCacheKey)
	otherRevision := madeUpLogon(aMadeUpLogon)
	otherRevision.revision = 0x00010003
	longName := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(longName[slotNameLenOffset:], 0x400)
	noName := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(noName[slotNameLenOffset:], 0)
	oddName := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(oddName[slotNameLenOffset:], 3)
	otherKey := bytes.Repeat([]byte{0x4c}, 16)
	for name, tc := range map[string]struct {
		raw  []byte
		key  []byte
		want error
	}{
		"header only":    {good[:slotDataOffset], madeUpCacheKey, ErrSlotLayout},
		"partial block":  {good[:len(good)-3], madeUpCacheKey, ErrSlotLayout},
		"other revision": {sealSlot(otherRevision, madeUpCacheKey), madeUpCacheKey, ErrSlotRevision},
		"name past end":  {longName, madeUpCacheKey, ErrSlotNames},
		"empty name":     {noName, madeUpCacheKey, ErrSlotNames},
		"odd name":       {oddName, madeUpCacheKey, ErrSlotNames},
		"other key":      {good, otherKey, ErrSlotNames},
	} {
		if _, err := decodeSlot(tc.raw, tc.key); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

func TestOnlyDecimalNLNamesAreSlots(t *testing.T) {
	for name, want := range map[string]bool{
		"NL$1": true, "NL$10": true, "NL$50": true,
		"NL$Control": false, "NL$IterationCount": false, "NL$01": false, "NL$": false, "NL$x": false, "nl$1": false, "NL$1x": false,
	} {
		if _, ok := slotNumber(name); ok != want {
			t.Errorf("%q: %v", name, ok)
		}
	}
}

func TestTheMeasuredEmptyShapeIsEmpty(t *testing.T) {
	if !emptySlot(emptySlotBytes()) {
		t.Error("the M3 shape is not empty")
	}
	b := emptySlotBytes()
	b[slotIVOffset] = 1
	if emptySlot(b) {
		t.Error("a non-zero IV byte counts as empty")
	}
}

func TestTheCacheKeyIsTheSecondSixteenBytes(t *testing.T) {
	nlkm := make([]byte, 64)
	for i := range nlkm {
		nlkm[i] = byte(i)
	}
	k, ok := cacheKeyFrom(nlkm)
	if !ok || k[0] != 16 || len(k) != 16 {
		t.Fatalf("key %v %v", k, ok)
	}
	if _, ok := cacheKeyFrom(nlkm[:31]); ok {
		t.Error("a 31-byte secret gave a key")
	}
}
