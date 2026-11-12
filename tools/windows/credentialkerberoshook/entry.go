package credentialkerberoshook

import "encoding/binary"

// S23 M2, M3: CDRegisterCSystem copies eight 16-byte blocks per entry and indexes
// the table by count << 7.
const (
	entrySize       = 0x80
	entryShift      = 7
	entryTypeOffset = 0x00
	entryNameOffset = 0x20
)

// S23 M3: CDRegisterCSystem refuses a registration that would bring the count
// to 0x18, so a table it filled never holds more entries than this.
const maxEntries = 0x17

type Slot string

const (
	SlotInitialise       Slot = "initialise"
	SlotEncrypt          Slot = "encrypt"
	SlotDecrypt          Slot = "decrypt"
	SlotFinish           Slot = "finish"
	SlotStringToKey      Slot = "string-to-key"
	SlotRandomToKey      Slot = "random-to-key"
	SlotControl          Slot = "control"
	SlotAlternateEncrypt Slot = "alternate-encrypt"
	SlotAlternateDecrypt Slot = "alternate-decrypt"
	SlotPseudoRandom     Slot = "pseudo-random"
	SlotPseudoRandomPlus Slot = "pseudo-random-plus"
)

type slotOffset struct {
	slot   Slot
	offset int
}

// S23 M5: the offsets come from the public names of the routines each slot
// points at on the measured builds.
var slotOffsets = []slotOffset{
	{SlotInitialise, 0x28},
	{SlotEncrypt, 0x30},
	{SlotDecrypt, 0x38},
	{SlotFinish, 0x40},
	{SlotStringToKey, 0x48},
	{SlotRandomToKey, 0x50},
	{SlotControl, 0x58},
	{SlotAlternateEncrypt, 0x60},
	{SlotAlternateDecrypt, 0x68},
	{SlotPseudoRandom, 0x70},
	{SlotPseudoRandomPlus, 0x78},
}

type entryPointer struct {
	slot    Slot
	address uint64
}

type entry struct {
	encryptionType int32
	name           uint64
	routines       []entryPointer
}

func decodeEntry(b []byte) (entry, bool) {
	if len(b) < entrySize {
		return entry{}, false
	}
	e := entry{
		encryptionType: int32(binary.LittleEndian.Uint32(b[entryTypeOffset:])),
		name:           binary.LittleEndian.Uint64(b[entryNameOffset:]),
	}
	for _, s := range slotOffsets {
		if p := binary.LittleEndian.Uint64(b[s.offset:]); p != 0 {
			e.routines = append(e.routines, entryPointer{slot: s.slot, address: p})
		}
	}
	return e, true
}

// IANA "Kerberos Encryption Type Numbers" (S23 F1). Negative numbers are for
// private use and have no registered name.
var encryptionTypeNames = map[int32]string{
	1:  "des-cbc-crc",
	2:  "des-cbc-md4",
	3:  "des-cbc-md5",
	5:  "des3-cbc-md5",
	7:  "des3-cbc-sha1",
	9:  "dsaWithSHA1-CmsOID",
	10: "md5WithRSAEncryption-CmsOID",
	11: "sha1WithRSAEncryption-CmsOID",
	12: "rc2CBC-EnvOID",
	13: "rsaEncryption-EnvOID",
	14: "rsaES-OAEP-ENV-OID",
	15: "des-ede3-cbc-Env-OID",
	16: "des3-cbc-sha1-kd",
	17: "aes128-cts-hmac-sha1-96",
	18: "aes256-cts-hmac-sha1-96",
	19: "aes128-cts-hmac-sha256-128",
	20: "aes256-cts-hmac-sha384-192",
	23: "rc4-hmac",
	24: "rc4-hmac-exp",
	25: "camellia128-cts-cmac",
	26: "camellia256-cts-cmac",
	65: "subkey-keymaterial",
}

func encryptionTypeName(t int32) string { return encryptionTypeNames[t] }
