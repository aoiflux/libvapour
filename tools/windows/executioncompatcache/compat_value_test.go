package executioncompatcache

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
	"time"
	"unicode/utf16"
)

// Records follow S63 M22: signature, CRC-32, payload length, then key length,
// key, FILETIME, data size and data.
func payload(key string, ft uint64, data []byte) []byte {
	units := utf16.Encode([]rune(key))
	p := binary.LittleEndian.AppendUint16(nil, uint16(2*len(units)))
	for _, u := range units {
		p = binary.LittleEndian.AppendUint16(p, u)
	}
	p = binary.LittleEndian.AppendUint64(p, ft)
	p = binary.LittleEndian.AppendUint32(p, uint32(len(data)))
	return append(p, data...)
}

func record(p []byte, crc uint32) []byte {
	r := binary.LittleEndian.AppendUint32(nil, recordSignature)
	r = binary.LittleEndian.AppendUint32(r, crc)
	r = binary.LittleEndian.AppendUint32(r, uint32(len(p)))
	return append(r, p...)
}

func value(header uint32, records ...[]byte) []byte {
	v := make([]byte, header)
	binary.LittleEndian.PutUint32(v, header)
	for _, r := range records {
		v = append(v, r...)
	}
	return v
}

func filetime(t time.Time) uint64 { return uint64(t.Unix()+11644473600) * 10_000_000 }

func TestRecordsDecodeInOrderWithTheirChecksums(t *testing.T) {
	when := time.Date(2026, 5, 6, 18, 0, 0, 0, time.UTC)
	p1 := payload(`C:\Windows\a.exe`, filetime(when), []byte{1, 2, 3, 4})
	p2 := payload("pkg\tid", 0, nil)
	raw := value(0x34, record(p1, crc32.ChecksumIEEE(p1)), record(p2, 7))
	out, err := DecodeRecords(raw)
	if err != nil || len(out) != 2 {
		t.Fatalf("%v %+v", err, out)
	}
	a, b := out[0], out[1]
	if a.Position != 0 || a.Offset != 0x34 || a.Key != `C:\Windows\a.exe` || !a.FileLastWrite.Equal(when) || a.DataSize != 4 ||
		!a.ChecksumValid {
		t.Errorf("first %+v", a)
	}
	if b.Position != 1 || !b.FileLastWrite.IsZero() || b.ChecksumValid || len(b.Data) != 0 {
		t.Errorf("second %+v", b)
	}
	if _, err := DecodeRecords(value(0x30)); err != nil {
		t.Errorf("an empty cache with the 14393 header: %v", err)
	}
}

func TestHeadersAndRecordsOutsideTheMeasuredFormAreRefused(t *testing.T) {
	p := payload("k", 0, nil)
	for name, raw := range map[string][]byte{
		"short":        {1, 2},
		"other header": value(0x80, record(p, 0)),
		"header past":  binary.LittleEndian.AppendUint32(nil, 0x34),
	} {
		if _, err := DecodeRecords(raw); !errors.Is(err, ErrHeader) {
			t.Errorf("%s: %v", name, err)
		}
	}
	good := record(p, crc32.ChecksumIEEE(p))
	bad := append([]byte(nil), good...)
	bad[0] ^= 1
	odd := payload("k", 0, nil)
	odd[0] = 3
	long := payload("k", 0, []byte{1})
	binary.LittleEndian.PutUint32(long[len(long)-5:], 9)
	for name, raw := range map[string][]byte{
		"signature":       value(0x34, good, bad),
		"odd key":         value(0x34, record(odd, 0)),
		"data past":       value(0x34, record(long, 0)),
		"payload cut":     value(0x34, good, good[:len(good)-2]),
		"bytes left over": value(0x34, good, []byte{1, 2, 3}),
	} {
		out, err := DecodeRecords(raw)
		if !errors.Is(err, ErrRecord) {
			t.Errorf("%s: %v", name, err)
		}
		if name == "signature" && len(out) != 1 {
			t.Errorf("records before the bad one are kept: %d", len(out))
		}
	}
}

func FuzzDecodeRecords(f *testing.F) {
	p := payload(`C:\a.exe`, 1, []byte{9})
	f.Add(value(0x34, record(p, crc32.ChecksumIEEE(p))))
	f.Add(value(0x30))
	f.Fuzz(func(t *testing.T, raw []byte) {
		out, err := DecodeRecords(raw)
		if err != nil && !errors.Is(err, ErrHeader) && !errors.Is(err, ErrRecord) {
			t.Fatalf("unexpected error %v", err)
		}
		prev := 0
		for i, r := range out {
			if r.Position != i || r.Offset <= prev-1 || r.Offset >= len(raw) || int(r.DataSize) != len(r.Data) {
				t.Fatalf("record %d %+v", i, r)
			}
			prev = r.Offset + 1
		}
	})
}
