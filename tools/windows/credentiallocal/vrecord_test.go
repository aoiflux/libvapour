package credentiallocal

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"unicode/utf16"
)

func nameBytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2*len(units))
	for _, u := range units {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

func aesHashRecord(t *testing.T, domainKey, hash []byte, rid uint32) []byte {
	t.Helper()
	iv := bytes.Repeat([]byte{0x33}, 16)
	wrapped := hashUnderRID(hash, rid, false)
	cipher, err := aesCBCEncrypt(domainKey, iv, padTo16(wrapped[:]))
	if err != nil {
		t.Fatal(err)
	}
	rec := make([]byte, recordAESMinLen)
	binary.LittleEndian.PutUint16(rec[0:], 2)
	binary.LittleEndian.PutUint16(rec[recordRevisionOffset:], revisionAES)
	binary.LittleEndian.PutUint32(rec[recordLengthOffset:], 16)
	copy(rec[recordIVOffset:], iv)
	copy(rec[recordCipherOffset:], cipher)
	return rec
}

func buildV(name, ntRecord []byte) []byte {
	v := make([]byte, vDataBase)
	setEntry := func(index int, data []byte) {
		off := len(v) - vDataBase
		base := index * vEntrySize
		binary.LittleEndian.PutUint32(v[base:], uint32(off))
		binary.LittleEndian.PutUint32(v[base+4:], uint32(len(data)))
		v = append(v, data...)
	}
	setEntry(vNameEntry, name)
	setEntry(vNTHashEntry, ntRecord)
	return v
}

func TestHashFromRecordRecoversAnAESNTHash(t *testing.T) {
	domainKey := bytes.Repeat([]byte{0x42}, 16)
	nt := NTOWFv1("synthetic-passphrase-7")
	rid := uint32(1013)
	v := buildV(nameBytes("synthetic-user"), aesHashRecord(t, domainKey, nt[:], rid))

	if got := accountName(v); got != "synthetic-user" {
		t.Errorf("name = %q", got)
	}
	hash, present, ok := hashFromRecord(v, domainKey, vNTHashEntry, rid, true)
	if !ok || !present {
		t.Fatalf("present=%v ok=%v", present, ok)
	}
	if !bytes.Equal(hash[:], nt[:]) {
		t.Errorf("hash = %x, want %x", hash, nt)
	}
}

func TestHashFromRecordReportsAnEmptyRecord(t *testing.T) {
	v := make([]byte, vDataBase+8)
	base := vNTHashEntry * vEntrySize
	binary.LittleEndian.PutUint32(v[base:], 0)
	binary.LittleEndian.PutUint32(v[base+4:], 8)
	binary.LittleEndian.PutUint16(v[vDataBase+recordRevisionOffset:], revisionAES)
	_, present, ok := hashFromRecord(v, nil, vNTHashEntry, 500, true)
	if !ok || present {
		t.Errorf("empty record: present=%v ok=%v", present, ok)
	}
}

func TestRenderedNTHashIsLowercaseHex(t *testing.T) {
	domainKey := bytes.Repeat([]byte{0x42}, 16)
	nt := NTOWFv1("another-synthetic")
	rid := uint32(500)
	v := buildV(nameBytes("admin-synth"), aesHashRecord(t, domainKey, nt[:], rid))
	hash, _, _ := hashFromRecord(v, domainKey, vNTHashEntry, rid, true)
	if hex.EncodeToString(hash[:]) == "" {
		t.Error("empty hex")
	}
}

func FuzzParseV(f *testing.F) {
	f.Add(make([]byte, vDataBase))
	f.Add(buildV(nameBytes("x"), make([]byte, recordAESMinLen)))
	f.Fuzz(func(t *testing.T, v []byte) {
		_ = accountName(v)
		for _, entry := range []int{vLMHashEntry, vNTHashEntry} {
			hashFromRecord(v, make([]byte, 16), entry, 500, true)
		}
	})
}

func FuzzDecodeDomainKey(f *testing.F) {
	f.Add(make([]byte, fMinLen), make([]byte, 16))
	f.Fuzz(func(t *testing.T, raw, systemKey []byte) {
		if len(systemKey) != 16 {
			return
		}
		key, err := domainKey(raw, systemKey)
		if err == nil && len(key) != 16 {
			t.Fatalf("key length %d", len(key))
		}
	})
}
