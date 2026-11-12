package credentiallocal

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/util"
)

// V offset-table geometry (S20 M5). Each entry is {offset, length, unused},
// offsets relative to vDataBase.
const (
	vEntrySize   = 12
	vDataBase    = 0xCC
	vNameEntry   = 1
	vLMHashEntry = 13
	vNTHashEntry = 14
)

// AES hash record (S20 M6).
const (
	recordRevisionOffset = 2
	recordLengthOffset   = 4
	recordIVOffset       = 8
	recordIVLen          = 16
	recordCipherOffset   = 24
	recordCipherLen      = 0x20
	recordAESMinLen      = recordCipherOffset + recordCipherLen
	// Revision-1 records hold the 16-byte RC4 hash right after the 4-byte
	// header (S20 4.4, not measured).
	legacyRecordOffset = 4
)

func vEntry(v []byte, index int) (data []byte, ok bool) {
	base := index * vEntrySize
	if base+vEntrySize > len(v) {
		return nil, false
	}
	off := binary.LittleEndian.Uint32(v[base:])
	length := binary.LittleEndian.Uint32(v[base+4:])
	start := uint64(vDataBase) + uint64(off)
	end := start + uint64(length)
	if end > uint64(len(v)) || start > end {
		return nil, false
	}
	return v[start:end], true
}

func accountName(v []byte) string {
	data, ok := vEntry(v, vNameEntry)
	if !ok {
		return ""
	}
	return util.DecodeUTF16LE(data)
}

// hashFromRecord returns the recovered hash and whether one is present. A
// record without a stored hash (length 0 or too short) returns present=false
// with no error; a record that fails to decrypt returns ok=false.
func hashFromRecord(v, domainKey []byte, entry int, rid uint32, nt bool) (hash [16]byte, present, ok bool) {
	rec, got := vEntry(v, entry)
	if !got {
		return hash, false, false
	}
	// Too short to hold even a record header: no hash is stored for this
	// account (the common case for LM on current Windows, S20 D8).
	if len(rec) < recordIVOffset {
		return hash, false, true
	}
	switch binary.LittleEndian.Uint16(rec[recordRevisionOffset:]) {
	case revisionAES:
		if binary.LittleEndian.Uint32(rec[recordLengthOffset:]) == 0 {
			return hash, false, true
		}
		if len(rec) < recordAESMinLen {
			return hash, true, false
		}
		iv := rec[recordIVOffset : recordIVOffset+recordIVLen]
		plain, err := AESCBCDecrypt(domainKey, iv, rec[recordCipherOffset:recordCipherOffset+recordCipherLen])
		if err != nil {
			return hash, true, false
		}
		return hashUnderRID(plain[:16], rid, true), true, true
	case revisionRC4Legacy:
		if len(rec) < legacyRecordOffset+16 {
			return hash, false, true
		}
		h, decoded := legacyDecryptHash(rec[legacyRecordOffset:], domainKey, rid, nt)
		return h, true, decoded
	default:
		return hash, true, false
	}
}
