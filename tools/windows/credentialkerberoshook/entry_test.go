package credentialkerberoshook

import (
	"encoding/binary"
	"testing"
)

func TestEntryDecodesTypeNameAndNonzeroRoutinesInOffsetOrder(t *testing.T) {
	b := make([]byte, entrySize)
	binary.LittleEndian.PutUint32(b[0:], uint32(0xffffff6b))
	binary.LittleEndian.PutUint64(b[0x20:], 0x7ffc_ae97_c000)
	binary.LittleEndian.PutUint64(b[0x28:], 0x7ffc_ae97_1000)
	binary.LittleEndian.PutUint64(b[0x40:], 0x7ffc_ae97_2000)
	binary.LittleEndian.PutUint64(b[0x60:], 0x7ffc_ae97_3000)
	binary.LittleEndian.PutUint64(b[0x78:], 0x7ffc_ae97_4000)
	binary.LittleEndian.PutUint64(b[0x08:], 0x1234)
	e, ok := decodeEntry(b)
	if !ok || e.encryptionType != -149 || e.name != 0x7ffc_ae97_c000 {
		t.Fatalf("%+v %v", e, ok)
	}
	want := []entryPointer{
		{SlotInitialise, 0x7ffc_ae97_1000}, {SlotFinish, 0x7ffc_ae97_2000},
		{SlotAlternateEncrypt, 0x7ffc_ae97_3000}, {SlotPseudoRandomPlus, 0x7ffc_ae97_4000},
	}
	if len(e.routines) != len(want) {
		t.Fatalf("routines %+v", e.routines)
	}
	for i := range want {
		if e.routines[i] != want[i] {
			t.Errorf("routine %d: %+v, want %+v", i, e.routines[i], want[i])
		}
	}
	if _, ok := decodeEntry(b[:entrySize-1]); ok {
		t.Error("a short entry decoded")
	}
}

func TestSlotsCoverEveryQuadwordAfterTheName(t *testing.T) {
	if len(slotOffsets) != (entrySize-entryNameOffset)/8-1 {
		t.Fatalf("%d slots", len(slotOffsets))
	}
	for i, s := range slotOffsets {
		if s.offset != entryNameOffset+8*(i+1) {
			t.Errorf("slot %s at 0x%x", s.slot, s.offset)
		}
	}
	if entrySize != 1<<entryShift {
		t.Error("entry size and scale disagree")
	}
}

func TestEncryptionTypeNamesFollowTheRegistry(t *testing.T) {
	for v, want := range map[int32]string{
		17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96", 23: "rc4-hmac", 24: "rc4-hmac-exp",
		1: "des-cbc-crc", 3: "des-cbc-md5", 0: "", 4: "", 21: "", -128: "", -133: "",
	} {
		if got := encryptionTypeName(v); got != want {
			t.Errorf("%d: %q, want %q", v, got, want)
		}
	}
}
