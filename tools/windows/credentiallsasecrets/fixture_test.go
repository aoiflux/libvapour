package credentiallsasecrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

type sealing struct {
	repeats int
	chained bool
	excess  int
}

// excess 1 reproduces every measured shape: plaintext = 16 + n rounded up past
// at least one spare byte (S21 M5).
var specSealing = sealing{repeats: saltRepeats, excess: 1}

func sealWith(s sealing, k []byte, keyID [16]byte, salt, value []byte) []byte {
	n := plainHeaderLen + len(value) + s.excess
	n += (aes.BlockSize - n%aes.BlockSize) % aes.BlockSize
	plain := make([]byte, n)
	binary.LittleEndian.PutUint32(plain, uint32(len(value)))
	copy(plain[plainHeaderLen:], value)

	input := append([]byte(nil), k...)
	for range s.repeats {
		input = append(input, salt...)
	}
	derived := sha256.Sum256(input)
	block, _ := aes.NewCipher(derived[:])
	ct := make([]byte, len(plain))
	if s.chained {
		cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(ct, plain)
	} else {
		for i := 0; i < len(plain); i += aes.BlockSize {
			block.Encrypt(ct[i:], plain[i:i+aes.BlockSize])
		}
	}
	out := make([]byte, protectedDataOffset, protectedDataOffset+len(ct))
	copy(out, measuredMarker[:])
	copy(out[protectedKeyIDOffset:], keyID[:])
	binary.LittleEndian.PutUint32(out[protectedSchemeOffset:], measuredScheme)
	copy(out[protectedSaltOffset:], salt)
	return append(out, ct...)
}

func seal(k []byte, keyID [16]byte, salt, value []byte) []byte {
	return sealWith(specSealing, k, keyID, salt, value)
}

type fixtureKey struct {
	id  [16]byte
	key []byte
}

func keyListBytes(current [16]byte, entries ...fixtureKey) []byte {
	b := make([]byte, listEntriesOffset)
	binary.LittleEndian.PutUint32(b, 3)
	copy(b[listCurrentIDOffset:], current[:])
	binary.LittleEndian.PutUint32(b[20:], 3)
	binary.LittleEndian.PutUint32(b[listCountOffset:], uint32(len(entries)))
	for _, e := range entries {
		h := make([]byte, entryHeaderLen)
		copy(h, e.id[:])
		binary.LittleEndian.PutUint32(h[16:], 3)
		binary.LittleEndian.PutUint32(h[entryLengthOffset:], uint32(len(e.key)))
		b = append(append(b, h...), e.key...)
	}
	return b
}

var (
	madeUpSystemKey = bytes.Repeat([]byte{0x5a}, 16)
	madeUpSalt      = bytes.Repeat([]byte{0x21}, protectedSaltLen)
	madeUpKeyID     = [16]byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5}
	madeUpOtherID   = [16]byte{0xb1, 0xb2}
	madeUpPolicyKey = bytes.Repeat([]byte{0x6c}, policyKeyLen)
	madeUpOlderKey  = bytes.Repeat([]byte{0x7d}, policyKeyLen)
	headerKeyListID = [16]byte{0xee}
)

func defaultSecValue(raw []byte) registryhive.Value {
	return registryhive.Value{Name: defaultValueName, Type: 0, Raw: raw, Length: uint32(len(raw))}
}

func securityHive(listValue []byte) *registrytest.FakeHive {
	h := registrytest.NewFakeHive("SECURITY")
	if listValue != nil {
		h.Values[h.Path(keyListPath)] = []registryhive.Value{defaultSecValue(listValue)}
	}
	return h
}

func sealedKeyList() []byte {
	list := keyListBytes(madeUpKeyID, fixtureKey{madeUpKeyID, madeUpPolicyKey}, fixtureKey{madeUpOtherID, madeUpOlderKey})
	return seal(madeUpSystemKey, headerKeyListID, madeUpSalt, list)
}

func filetimeBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func diagCtx() (*diagnostics, *[]string) {
	sink := &[]string{}
	return &diagnostics{ctx: tools.Context{Options: map[string]any{"diagnostics": sink}}}, sink
}
