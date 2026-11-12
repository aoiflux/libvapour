package imagebanners

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzLinuxBanner(f *testing.F) {
	f.Add([]byte(running617+"\n"), 4096)
	f.Add([]byte("Linux version (x)"), 16)
	f.Add([]byte("Linux version 1 (\x00"), 1)
	f.Fuzz(func(t *testing.T, b []byte, maxText int) {
		maxText = max(maxText%8192, 0)
		got, ok := parseLinuxBanner(b, maxText)
		if !ok {
			return
		}
		if !strings.HasPrefix(string(b), "Linux version ") || got.Release == "" || len(got.Release) > maxRelease ||
			strings.ContainsAny(got.Release, " \n") {
			t.Fatalf("banner %+v from %q", got, b)
		}
		if len(got.Banner) > maxText {
			t.Fatalf("text of %d bytes over %d", len(got.Banner), maxText)
		}
		for _, c := range []byte(got.Banner) {
			if !printable(c) {
				t.Fatalf("byte %#x in %q", c, got.Banner)
			}
		}
	})
}

func FuzzCodeViewRecord(f *testing.F) {
	f.Add(codeView("ntkrnlmp.pdb", 1, 1))
	f.Add(codeView(`c:\x\NTOSKRNL.PDB`, 2, 9))
	f.Add([]byte("RSDS"))
	f.Fuzz(func(t *testing.T, b []byte) {
		fp, ok := codeViewFingerprint(b)
		if !ok {
			return
		}
		if !bytes.HasPrefix(b, []byte("RSDS")) || len(fp.GUID) != 32 {
			t.Fatalf("fingerprint %+v from %q", fp, b)
		}
		nul := bytes.IndexByte(b[codeViewHead:], 0)
		if nul <= 0 || nul >= maxPathBytes {
			t.Fatalf("path end %d", nul)
		}
		known := false
		for _, k := range kernelPDBNames {
			known = known || strings.EqualFold(k, fp.PDBName)
		}
		if !known {
			t.Fatalf("name %q", fp.PDBName)
		}
	})
}
