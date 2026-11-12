package memorycode

import "testing"

func FuzzLinuxEntry(f *testing.F) {
	f.Add(uint64(0), "6.17.0")
	f.Add(linuxPresent|linuxSavedDirty, "6.14.5")
	f.Add(linuxPresent|linuxDirty|linuxNoExec, "6.4.0")
	f.Add(^uint64(0)&^linuxPresent, "6.10")
	f.Fuzz(func(t *testing.T, entry uint64, release string) {
		bits, _ := writtenBitsFor(release)
		p := decodeLinuxEntry(entry, bits)
		if entry&linuxPresent == 0 && p != (linuxPage{}) {
			t.Fatalf("not-present entry %#x decoded as %+v", entry, p)
		}
		if p.resident && p.executable == (entry&linuxNoExec != 0) {
			t.Fatalf("entry %#x: executable %v", entry, p.executable)
		}
		if p.written && entry&(linuxDirty|linuxSavedDirty) == 0 {
			t.Fatalf("entry %#x written without a dirty bit", entry)
		}
		if bits&writtenBits(linuxSavedDirty) != 0 {
			v, ok := majorMinor(release)
			if !ok || before(v, savedDirtyFrom) {
				t.Fatalf("release %q counts bit 58", release)
			}
		}
	})
}
