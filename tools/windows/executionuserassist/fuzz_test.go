package executionuserassist

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func FuzzDecodeCountData(f *testing.F) {
	f.Add(countData(14, 21, 420000, 0x01db0000aabbccdd))
	f.Add(sessionData())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := DecodeCountData(b)
		if err != nil {
			if !errors.Is(err, ErrDataLength) || len(b) == countDataSize {
				t.Fatalf("%d bytes: %v", len(b), err)
			}
			return
		}
		if len(b) != countDataSize || d.LaunchCount != binary.LittleEndian.Uint32(b[4:]) ||
			d.LastLaunch != binary.LittleEndian.Uint64(b[0x3C:]) {
			t.Fatalf("%d bytes decoded as %+v", len(b), d)
		}
	})
}

func FuzzDecodeName(f *testing.F) {
	f.Add(rot13(systemPrefix+`\cmd.exe`), true)
	f.Add(rot13(systemX86+`\x`), false)
	f.Add(rot13("UEME_CTLSESSION"), true)
	f.Add("{", false)
	f.Fuzz(func(t *testing.T, stored string, wide bool) {
		d := decodeName(stored, wide)
		if rot13(d.name) != stored {
			t.Fatalf("rot13 is not its own inverse on %q", stored)
		}
		guid, rest, ok := splitFolderPrefix(d.name)
		if ok && guid+rest != d.name || !ok && rest != d.name {
			t.Fatalf("%q split into %q and %q", d.name, guid, rest)
		}
		if d.found && (!ok || !strings.EqualFold(d.folder.GUID, guid)) {
			t.Fatalf("%q: folder %+v without its braced prefix", d.name, d.folder)
		}
		if !d.found || d.folder.Path == "" {
			if d.expanded != d.name {
				t.Fatalf("%q expanded to %q with no folder path", d.name, d.expanded)
			}
		} else if d.expanded != d.folder.Path+rest {
			t.Fatalf("%q expanded to %q", d.name, d.expanded)
		}
	})
}
