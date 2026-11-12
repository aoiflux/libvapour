package credentiallocal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/util"
)

var (
	ErrSystemKey = errors.New("credentiallocal: lsa class names do not give a system key")
	ErrDomainKey = errors.New("credentiallocal: sam domain key does not unwrap")
)

var lsaKeyParts = []string{"JD", "Skew1", "GBG", "Data"}

// Output byte i is scrambled byte systemKeyOrder[i]. Measured; no vendor
// source states it (S20 M2).
var systemKeyOrder = [16]int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

type systemHive interface {
	OpenKey(string) (*registryhive.KeyNode, error)
	Subkeys(*registryhive.KeyNode) []*registryhive.KeyNode
	ClassData(*registryhive.KeyNode) []byte
}

func SystemKey(sys *registryhive.HiveLayer) ([]byte, bool) {
	set, _ := registryhive.CurrentControlSetChecked(sys)
	return systemKeyFrom(sys, set)
}

func systemKeyFrom(sys systemHive, controlSet string) ([]byte, bool) {
	lsa, err := sys.OpenKey(controlSet + `\Control\Lsa`)
	if err != nil {
		return nil, false
	}
	classes := map[string][]byte{}
	for _, k := range sys.Subkeys(lsa) {
		if cd := sys.ClassData(k); cd != nil {
			classes[k.Name] = cd
		}
	}
	return deriveSystemKey(classes)
}

func deriveSystemKey(classes map[string][]byte) ([]byte, bool) {
	scrambled := make([]byte, 0, 16)
	for _, name := range lsaKeyParts {
		cd, ok := classes[name]
		if !ok {
			return nil, false
		}
		b, err := hexClassBytes(cd)
		if err != nil || len(b) != 4 {
			return nil, false
		}
		scrambled = append(scrambled, b...)
	}
	key := make([]byte, 16)
	for i := range key {
		key[i] = scrambled[systemKeyOrder[i]]
	}
	return key, true
}

func hexClassBytes(classUTF16 []byte) ([]byte, error) {
	return hex.DecodeString(util.DecodeUTF16LE(classUTF16))
}

// The AES key block of the SAM domain F value (S20 M3, M4). The RC4 path lives
// in domainkey_legacy.go.
const (
	fKeyBlockOffset   = 0x68
	fRevisionOffset   = fKeyBlockOffset + 0x00
	fSaltOffset       = fKeyBlockOffset + 0x10
	fDataOffset       = fKeyBlockOffset + 0x20
	fChecksumOffset   = fKeyBlockOffset + 0x40
	aesSaltLen        = 16
	aesDataLen        = 0x20
	aesChecksumLen    = 0x30
	fMinLen           = fChecksumOffset + aesChecksumLen
	revisionAES       = 2
	revisionRC4Legacy = 1
)

func domainKey(f, systemKey []byte) ([]byte, error) {
	if len(f) < fRevisionOffset+4 {
		return nil, ErrDomainKey
	}
	switch binary.LittleEndian.Uint32(f[fRevisionOffset:]) {
	case revisionAES:
		return domainKeyAES(f, systemKey)
	case revisionRC4Legacy:
		return domainKeyRC4(f, systemKey)
	default:
		return nil, ErrDomainKey
	}
}

func domainKeyAES(f, systemKey []byte) ([]byte, error) {
	if len(f) < fMinLen {
		return nil, ErrDomainKey
	}
	salt := f[fSaltOffset : fSaltOffset+aesSaltLen]
	plain, err := AESCBCDecrypt(systemKey, salt, f[fDataOffset:fDataOffset+aesDataLen])
	if err != nil {
		return nil, ErrDomainKey
	}
	key := plain[:16]
	if !allEqual(plain[16:], 16) {
		return nil, ErrDomainKey
	}
	check, err := AESCBCDecrypt(systemKey, salt, f[fChecksumOffset:fChecksumOffset+aesChecksumLen])
	if err != nil {
		return nil, ErrDomainKey
	}
	want := sha256.Sum256(key)
	if !bytes.Equal(check[:32], want[:]) {
		return nil, ErrDomainKey
	}
	return key, nil
}

func allEqual(b []byte, v byte) bool {
	for _, x := range b {
		if x != v {
			return false
		}
	}
	return len(b) > 0
}
