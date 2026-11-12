package credentialcached

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/tools/windows/credentiallocal"
	"github.com/aoiflux/libvapour/util"
)

var (
	ErrSlotLayout   = errors.New("credentialcached: cache slot is too short or not block aligned")
	ErrSlotRevision = errors.New("credentialcached: cache slot revision is not the measured one")
	ErrSlotNames    = errors.New("credentialcached: cache slot names do not fit its decrypted part")
)

// Measured on every empty slot and in NL$Control +0 (S22 M2, M3).
const (
	slotRevisionOffset = 0x28
	measuredRevision   = 0x00010004
)

// Working layout W: not measured, no capture holds a used slot (S22 4.3, O1).
const (
	slotNameLenOffset   = 0x00
	slotDomainLenOffset = 0x02
	slotUserIDOffset    = 0x10
	slotDNSLenOffset    = 0x3C
	slotIVOffset        = 0x40
	slotIVEnd           = 0x50
	slotDataOffset      = 0x60
	plainNamesOffset    = 72
	verifierLen         = 16
	cacheKeyStart       = 16
	cacheKeyEnd         = 32
)

const slotPrefix = "NL$"

func slotNumber(name string) (uint64, bool) {
	digits, ok := strings.CutPrefix(name, slotPrefix)
	if !ok || digits == "" || digits[0] == '0' {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(digits, 10, 64)
	return n, err == nil
}

func emptySlot(raw []byte) bool {
	for i, b := range raw {
		if b != 0 && (i < slotRevisionOffset || i >= slotRevisionOffset+4) {
			return false
		}
	}
	return true
}

type usedSlot struct {
	effectiveName      string
	logonDomainName    string
	dnsLogonDomainName string
	userID             uint32
	verifier           []byte
}

func decodeSlot(raw, cacheKey []byte) (usedSlot, error) {
	if len(raw) < slotDataOffset+aes.BlockSize || (len(raw)-slotDataOffset)%aes.BlockSize != 0 {
		return usedSlot{}, ErrSlotLayout
	}
	if binary.LittleEndian.Uint32(raw[slotRevisionOffset:]) != measuredRevision {
		return usedSlot{}, ErrSlotRevision
	}
	plain, err := credentiallocal.AESCBCDecrypt(cacheKey, raw[slotIVOffset:slotIVEnd], raw[slotDataOffset:])
	if err != nil {
		return usedSlot{}, err
	}
	lengths := []int{
		int(binary.LittleEndian.Uint16(raw[slotNameLenOffset:])),
		int(binary.LittleEndian.Uint16(raw[slotDomainLenOffset:])),
		int(binary.LittleEndian.Uint16(raw[slotDNSLenOffset:])),
	}
	if lengths[0] == 0 {
		return usedSlot{}, ErrSlotNames
	}
	names := make([]string, len(lengths))
	at := plainNamesOffset
	for i, n := range lengths {
		at = (at + 3) &^ 3
		if n > len(plain)-at {
			return usedSlot{}, ErrSlotNames
		}
		s, ok := nameText(plain[at : at+n])
		if !ok {
			return usedSlot{}, ErrSlotNames
		}
		names[i] = s
		at += n
	}
	return usedSlot{
		effectiveName:      names[0],
		logonDomainName:    names[1],
		dnsLogonDomainName: names[2],
		userID:             binary.LittleEndian.Uint32(raw[slotUserIDOffset:]),
		verifier:           append([]byte(nil), plain[:verifierLen]...),
	}, nil
}

// U+FFFD stands for an unpaired surrogate after decoding, so a name holding
// one is refused with them.
func nameText(b []byte) (string, bool) {
	if len(b)%2 != 0 {
		return "", false
	}
	s := util.DecodeUTF16LE(b)
	if strings.ContainsRune(s, 0) || strings.ContainsRune(s, utf8.RuneError) {
		return "", false
	}
	return s, true
}

func cacheKeyFrom(nlkm []byte) ([]byte, bool) {
	if len(nlkm) < cacheKeyEnd {
		return nil, false
	}
	return nlkm[cacheKeyStart:cacheKeyEnd], true
}
