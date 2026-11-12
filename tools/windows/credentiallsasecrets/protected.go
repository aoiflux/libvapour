package credentiallsasecrets

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

var (
	ErrProtectedValue   = errors.New("credentiallsasecrets: protected value does not decrypt")
	ErrProtectedScheme  = errors.New("credentiallsasecrets: protected value uses an unmeasured scheme")
	ErrUnknownPolicyKey = errors.New("credentiallsasecrets: protected value names a key not in the policy key list")
)

// Layout measured on every capture; no vendor source states it (S21 M3-M5).
const (
	protectedKeyIDOffset  = 4
	protectedSchemeOffset = 20
	protectedSaltOffset   = 28
	protectedSaltLen      = 32
	protectedDataOffset   = protectedSaltOffset + protectedSaltLen
	measuredScheme        = 3
	saltRepeats           = 1000
	plainHeaderLen        = 16
	plainMaxExcess        = 16
)

var measuredMarker = [4]byte{0, 0, 0, 1}

type protectedValue struct {
	keyID      [16]byte
	salt       []byte
	ciphertext []byte
}

func parseProtected(raw []byte) (protectedValue, error) {
	var p protectedValue
	if len(raw) < protectedDataOffset+aes.BlockSize || (len(raw)-protectedDataOffset)%aes.BlockSize != 0 {
		return p, ErrProtectedValue
	}
	if [4]byte(raw[:4]) != measuredMarker || binary.LittleEndian.Uint32(raw[protectedSchemeOffset:]) != measuredScheme {
		return p, ErrProtectedScheme
	}
	copy(p.keyID[:], raw[protectedKeyIDOffset:])
	p.salt = raw[protectedSaltOffset:protectedDataOffset]
	p.ciphertext = raw[protectedDataOffset:]
	return p, nil
}

func valueKey(k, salt []byte) []byte {
	h := sha256.New()
	h.Write(k)
	for range saltRepeats {
		h.Write(salt)
	}
	return h.Sum(nil)
}

func (p protectedValue) open(k []byte) ([]byte, error) {
	block, err := aes.NewCipher(valueKey(k, p.salt))
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(p.ciphertext))
	// Each block stands alone: chained decryption fails the S21 M4 controls.
	for i := 0; i < len(plain); i += aes.BlockSize {
		block.Decrypt(plain[i:], p.ciphertext[i:i+aes.BlockSize])
	}
	n := uint64(binary.LittleEndian.Uint32(plain))
	if n+plainHeaderLen > uint64(len(plain)) || uint64(len(plain))-plainHeaderLen-n > plainMaxExcess {
		return nil, ErrProtectedValue
	}
	return plain[plainHeaderLen : plainHeaderLen+n], nil
}

func openProtected(raw, k []byte) ([]byte, error) {
	p, err := parseProtected(raw)
	if err != nil {
		return nil, err
	}
	return p.open(k)
}
