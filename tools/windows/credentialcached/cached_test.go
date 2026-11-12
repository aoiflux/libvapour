package credentialcached

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools/windows/credentiallsasecrets"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

func TestUsedSlotsBecomeRowsInSlotOrder(t *testing.T) {
	second := aMadeUpLogon
	second.name, second.userID = "second.user", 1201
	h := cacheHive(
		slotEntry("NL$Control", []byte{4, 0, 1, 0, 10, 0, 0, 0}),
		slotEntry("NL$10", sealSlot(second, madeUpCacheKey)),
		slotEntry("NL$1", emptySlotBytes()),
		slotEntry("NL$2", sealSlot(aMadeUpLogon, madeUpCacheKey)),
		slotEntry(iterationValueName, []byte{0x0a, 0, 0, 0}),
	)
	d, sink := diagCtx()
	rows, err := cachedLogons(d, h, fixedKey(madeUpCacheKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Slot != "NL$2" || rows[1].Slot != "NL$10" {
		t.Fatalf("rows = %+v", rows)
	}
	r := rows[0]
	if r.EffectiveName != aMadeUpLogon.name || r.LogonDomainName != aMadeUpLogon.domain ||
		r.DNSLogonDomainName != aMadeUpLogon.dns || r.UserID != aMadeUpLogon.userID {
		t.Errorf("row = %+v", r)
	}
	if !bytes.Equal(r.Verifier, madeUpVerifier) || r.IterationCount != 10 || rows[1].IterationCount != 10 {
		t.Errorf("verifier or iteration value differs: %d", r.IterationCount)
	}
	if len(*sink) != 0 {
		t.Errorf("diagnostics = %v", *sink)
	}
}

func TestEmptySlotsNeedNoKey(t *testing.T) {
	var values []registryhive.Value
	for _, n := range []string{"NL$1", "NL$2", "NL$3"} {
		values = append(values, slotEntry(n, emptySlotBytes()))
	}
	asked := false
	key := func() ([]byte, error) { asked = true; return nil, errors.New("no key") }
	d, sink := diagCtx()
	rows, err := cachedLogons(d, cacheHive(values...), key)
	if err != nil || rows != nil || asked || len(*sink) != 0 {
		t.Fatalf("rows %v, err %v, key asked %v, diagnostics %v", rows, err, asked, *sink)
	}
}

func TestAUsedSlotWithoutAKeyFailsTheRun(t *testing.T) {
	h := cacheHive(slotEntry("NL$1", sealSlot(aMadeUpLogon, madeUpCacheKey)))
	d, _ := diagCtx()
	_, err := cachedLogons(d, h, func() ([]byte, error) { return nil, credentiallsasecrets.ErrPolicyKeyAbsent })
	if !errors.Is(err, ErrCacheKey) || !errors.Is(err, credentiallsasecrets.ErrPolicyKeyAbsent) {
		t.Fatalf("err = %v", err)
	}
}

func TestABadSlotIsADiagnosticNotARow(t *testing.T) {
	bad := sealSlot(aMadeUpLogon, madeUpCacheKey)
	binary.LittleEndian.PutUint32(bad[slotRevisionOffset:], 0x00010002)
	h := cacheHive(
		slotEntry("NL$1", bad),
		slotEntry("NL$2", sealSlot(aMadeUpLogon, madeUpCacheKey)),
		registryhive.Value{Name: "NL$3", Length: 168},
	)
	h.ValuesIncomplete[h.Path(cachePath)] = true
	d, sink := diagCtx()
	rows, err := cachedLogons(d, h, fixedKey(madeUpCacheKey))
	if err != nil || len(rows) != 1 || rows[0].Slot != "NL$2" {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
	if d.raised != 3 {
		t.Fatalf("diagnostics = %v", *sink)
	}
	joined := strings.Join(*sink, "\n")
	for _, want := range []string{"values do not all read", "slot NL$1 at 0x", "slot NL$3 at 0x", ErrSlotRevision.Error()} {
		if !strings.Contains(joined, want) {
			t.Errorf("no %q in %v", want, *sink)
		}
	}
}

func TestNoCacheKeyIsNoRows(t *testing.T) {
	d, _ := diagCtx()
	rows, err := cachedLogons(d, registrytest.NewFakeHive("SECURITY"), fixedKey(madeUpCacheKey))
	if err != nil || rows != nil {
		t.Fatalf("rows %v, err %v", rows, err)
	}
	unreadable := registrytest.NewFakeHive("SECURITY")
	unreadable.Root = nil
	if _, err := cachedLogons(d, unreadable, fixedKey(madeUpCacheKey)); !errors.Is(err, registryhive.ErrKeyUnreadable) {
		t.Fatalf("err = %v", err)
	}
}

// A protected value per S21 4.2, inverted, so cacheKey can be tested end to end.
func sealS21(k []byte, keyID [16]byte, value []byte) []byte {
	salt := bytes.Repeat([]byte{0x2e}, 32)
	input := append([]byte(nil), k...)
	for range 1000 {
		input = append(input, salt...)
	}
	derived := sha256.Sum256(input)
	plain := make([]byte, 16+len(value)+4)
	plain = append(plain, make([]byte, (16-len(plain)%16)%16)...)
	binary.LittleEndian.PutUint32(plain, uint32(len(value)))
	copy(plain[16:], value)
	block, _ := aes.NewCipher(derived[:])
	out := make([]byte, 60, 60+len(plain))
	copy(out, []byte{0, 0, 0, 1})
	copy(out[4:], keyID[:])
	binary.LittleEndian.PutUint32(out[20:], 3)
	copy(out[28:], salt)
	ct := make([]byte, len(plain))
	for i := 0; i < len(plain); i += 16 {
		block.Encrypt(ct[i:], plain[i:i+16])
	}
	return append(out, ct...)
}

func TestTheCacheKeyComesFromTheNLKMSecret(t *testing.T) {
	systemKey := bytes.Repeat([]byte{0x5a}, 16)
	policyKey := bytes.Repeat([]byte{0x6c}, 32)
	keyID := [16]byte{0xa1}
	list := make([]byte, 28+24)
	binary.LittleEndian.PutUint32(list, 3)
	copy(list[4:], keyID[:])
	binary.LittleEndian.PutUint32(list[24:], 1)
	copy(list[28:], keyID[:])
	binary.LittleEndian.PutUint32(list[28+20:], 32)
	list = append(list, policyKey...)

	nlkm := make([]byte, 64)
	copy(nlkm[16:32], madeUpCacheKey)
	h := registrytest.NewFakeHive("SECURITY")
	def := func(raw []byte) []registryhive.Value {
		return []registryhive.Value{{Name: "(Default)", Raw: raw, Length: uint32(len(raw))}}
	}
	h.Values[h.Path(`Policy\PolEKList`)] = def(sealS21(systemKey, [16]byte{0xee}, list))
	h.Values[h.Path(`Policy\Secrets\NL$KM\CurrVal`)] = def(sealS21(policyKey, keyID, nlkm))

	k, err := cacheKey(h, systemKey)
	if err != nil || !bytes.Equal(k, madeUpCacheKey) {
		t.Fatalf("key differs, err %v", err)
	}
	h.Values[h.Path(`Policy\Secrets\NL$KM\CurrVal`)] = def(sealS21(policyKey, keyID, nlkm[:20]))
	if _, err := cacheKey(h, systemKey); err == nil {
		t.Error("a 20-byte NL$KM gave a key")
	}
}
