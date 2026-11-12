package credentiallocal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func padTo16(b []byte) []byte {
	out := make([]byte, 32)
	copy(out, b)
	for i := 16; i < 32; i++ {
		out[i] = 16
	}
	return out
}

// pkcs7Pad appends a full 16-byte padding block of value 16.
func pkcs7Pad(b []byte) []byte {
	out := make([]byte, len(b)+16)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = 16
	}
	return out
}

// hashUnderRID is its own inverse across the encrypt/decrypt flag, so a hash
// wrapped under a RID and unwrapped under the same RID is recovered.
func TestRIDWrapRoundTrips(t *testing.T) {
	hash := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	for _, rid := range []uint32{500, 501, 1001} {
		wrapped := hashUnderRID(hash, rid, false)
		got := hashUnderRID(wrapped[:], rid, true)
		if !bytes.Equal(got[:], hash) {
			t.Errorf("rid %d: round trip = %x, want %x", rid, got, hash)
		}
	}
}

func buildAESKeyBlock(t *testing.T, systemKey, domainKey, salt []byte) []byte {
	t.Helper()
	f := make([]byte, fMinLen)
	binary.LittleEndian.PutUint32(f[fRevisionOffset:], revisionAES)
	copy(f[fSaltOffset:], salt)
	data, err := aesCBCEncrypt(systemKey, salt, padTo16(domainKey))
	if err != nil {
		t.Fatal(err)
	}
	copy(f[fDataOffset:], data)
	sum := sha256.Sum256(domainKey)
	check, err := aesCBCEncrypt(systemKey, salt, pkcs7Pad(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	copy(f[fChecksumOffset:], check[:aesChecksumLen])
	return f
}

func TestDomainKeyAESUnwrapsAndChecks(t *testing.T) {
	systemKey := bytes.Repeat([]byte{0xA5}, 16)
	domainKey := []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6}
	salt := bytes.Repeat([]byte{0x11}, 16)
	f := buildAESKeyBlock(t, systemKey, domainKey, salt)
	got, err := domainKey2(f, systemKey)
	if err != nil {
		t.Fatalf("domainKey: %v", err)
	}
	if !bytes.Equal(got, domainKey) {
		t.Errorf("domain key = %x, want %x", got, domainKey)
	}
}

func TestDomainKeyAESRejectsTheWrongSystemKey(t *testing.T) {
	systemKey := bytes.Repeat([]byte{0xA5}, 16)
	domainKey := bytes.Repeat([]byte{0x42}, 16)
	salt := bytes.Repeat([]byte{0x11}, 16)
	f := buildAESKeyBlock(t, systemKey, domainKey, salt)
	if _, err := domainKey2(bytes.Clone(f), bytes.Repeat([]byte{0xFF}, 16)); err == nil {
		t.Error("wrong system key accepted")
	}
}

// domainKey2 names the package function under test without shadowing the
// domainKey local in the production code's callers.
func domainKey2(f, systemKey []byte) ([]byte, error) { return domainKey(f, systemKey) }
