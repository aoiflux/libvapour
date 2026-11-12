package credentiallocal

import (
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
)

// Revision-1 (pre-Windows-10) key material. No vendor source states these
// strings or the construction; they come from the published SYSKEY algorithm
// and are not measured (S20 section 3 "Not measured", O2). The two constants
// are the historic qwerty and digit strings used to stir the system key.
var (
	legacyStir1 = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	legacyStir2 = []byte("0123456789012345678901234567890123456789\x00")
)

const (
	rc4SaltOffset = fKeyBlockOffset + 0x04
	rc4KeyOffset  = fKeyBlockOffset + 0x14
	rc4MinLen     = rc4KeyOffset + 16
)

func domainKeyRC4(f, systemKey []byte) ([]byte, error) {
	if len(f) < rc4MinLen {
		return nil, ErrDomainKey
	}
	salt := f[rc4SaltOffset : rc4SaltOffset+16]
	rc4Key := md5Concat(salt, legacyStir1, systemKey, legacyStir2)
	c, err := rc4.NewCipher(rc4Key)
	if err != nil {
		return nil, ErrDomainKey
	}
	key := make([]byte, 16)
	c.XORKeyStream(key, f[rc4KeyOffset:rc4KeyOffset+16])
	return key, nil
}

// legacyHashConstant distinguishes the NT and LM records in the revision-1
// per-record RC4 key (S20 4.4).
var (
	legacyNTConstant = []byte("NTPASSWORD\x00")
	legacyLMConstant = []byte("LMPASSWORD\x00")
)

func legacyRecordRC4Key(domainKey []byte, rid uint32, constant []byte) []byte {
	var ridLE [4]byte
	binary.LittleEndian.PutUint32(ridLE[:], rid)
	return md5Concat(domainKey, ridLE[:], constant)
}

func md5Concat(parts ...[]byte) []byte {
	h := md5.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func legacyDecryptHash(enc, domainKey []byte, rid uint32, nt bool) ([16]byte, bool) {
	var out [16]byte
	if len(enc) < 16 {
		return out, false
	}
	constant := legacyNTConstant
	if !nt {
		constant = legacyLMConstant
	}
	c, err := rc4.NewCipher(legacyRecordRC4Key(domainKey, rid, constant))
	if err != nil {
		return out, false
	}
	wrapped := make([]byte, 16)
	c.XORKeyStream(wrapped, enc[:16])
	return hashUnderRID(wrapped, rid, true), true
}
