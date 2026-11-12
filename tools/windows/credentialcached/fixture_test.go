package credentialcached

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

type madeUpLogon struct {
	name, domain, dns string
	userID            uint32
	verifier          []byte
	revision          uint32
}

var (
	madeUpCacheKey = bytes.Repeat([]byte{0x4b}, 16)
	madeUpIV       = bytes.Repeat([]byte{0x19}, 16)
	madeUpVerifier = bytes.Repeat([]byte{0xd7}, verifierLen)
)

func utf16Bytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	return b
}

func align4(n int) int { return (n + 3) &^ 3 }

func sealSlot(l madeUpLogon, key []byte) []byte {
	names := [][]byte{utf16Bytes(l.name), utf16Bytes(l.domain), utf16Bytes(l.dns)}
	plain := make([]byte, plainNamesOffset)
	copy(plain, l.verifier)
	for _, n := range names {
		plain = append(plain, make([]byte, align4(len(plain))-len(plain))...)
		plain = append(plain, n...)
	}
	plain = append(plain, make([]byte, (aes.BlockSize-len(plain)%aes.BlockSize)%aes.BlockSize)...)

	raw := make([]byte, slotDataOffset, slotDataOffset+len(plain))
	binary.LittleEndian.PutUint16(raw[slotNameLenOffset:], uint16(len(names[0])))
	binary.LittleEndian.PutUint16(raw[slotDomainLenOffset:], uint16(len(names[1])))
	binary.LittleEndian.PutUint16(raw[slotDNSLenOffset:], uint16(len(names[2])))
	binary.LittleEndian.PutUint32(raw[slotUserIDOffset:], l.userID)
	revision := l.revision
	if revision == 0 {
		revision = measuredRevision
	}
	binary.LittleEndian.PutUint32(raw[slotRevisionOffset:], revision)
	copy(raw[slotIVOffset:], madeUpIV)
	block, _ := aes.NewCipher(key)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, madeUpIV).CryptBlocks(ct, plain)
	return append(raw, ct...)
}

// The M3 shape: 168 bytes, zero but for the revision word.
func emptySlotBytes() []byte {
	b := make([]byte, 168)
	binary.LittleEndian.PutUint32(b[slotRevisionOffset:], measuredRevision)
	return b
}

func slotEntry(name string, raw []byte) registryhive.Value {
	return registryhive.Value{Name: name, Type: 3, Raw: raw, Length: uint32(len(raw))}
}

func cacheHive(values ...registryhive.Value) *registrytest.FakeHive {
	h := registrytest.NewFakeHive("SECURITY")
	h.Values[h.Path(cachePath)] = values
	return h
}

func diagCtx() (*diagnostics, *[]string) {
	sink := &[]string{}
	return &diagnostics{ctx: tools.Context{Options: map[string]any{"diagnostics": sink}}}, sink
}

func fixedKey(k []byte) func() ([]byte, error) {
	return func() ([]byte, error) { return k, nil }
}
