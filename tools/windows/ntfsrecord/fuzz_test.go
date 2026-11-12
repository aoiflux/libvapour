package ntfsrecord

import "testing"

func FuzzParseRecord(f *testing.F) {
	f.Add(sampleRecord().restored())
	f.Add(sampleRecord().protected())
	f.Add(fullRecord().protected())
	f.Add([]byte("FILE0\x00\x03\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseRecord(0x1000, b)
		if err != nil {
			return
		}
		if r.linkCount != le16(b, 0x12) || r.bytesInUse != le32(b, 0x18) || r.allocated != le32(b, 0x1c) {
			t.Fatalf("header dwords %d %d %d differ from the bytes", r.linkCount, r.bytesInUse, r.allocated)
		}
		switch r.fixup {
		case FixupProtected, FixupRestored, FixupTorn:
		default:
			t.Fatalf("fixup %q", r.fixup)
		}
		previousEnd, previousCode := 0, uint32(0)
		var names []fileName
		for _, a := range r.attributes {
			if a.offset%8 != 0 || a.offset < previousEnd || a.offset >= len(b) || a.offset >= maxRecordSize {
				t.Fatalf("attribute at 0x%x after 0x%x", a.offset, previousEnd)
			}
			if a.typeCode < previousCode {
				t.Fatalf("type 0x%x after 0x%x", a.typeCode, previousCode)
			}
			previousEnd, previousCode = a.offset+residentHeader, a.typeCode
			if !a.resident && a.value != nil {
				t.Fatal("nonresident attribute carries a value")
			}
			switch a.typeCode {
			case codeStandardInformation:
				_, _ = a.standardInformation()
			case codeFileName:
				if fn, err := a.fileName(); err == nil {
					names = append(names, fn)
				}
			}
		}
		if name, known := preferredName(names); known != (len(names) > 0) || !known && name != "" {
			t.Fatalf("preferred name %q %v of %d", name, known, len(names))
		}
	})
}
