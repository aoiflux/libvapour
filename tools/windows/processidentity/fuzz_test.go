package processidentity

import (
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/util"
)

func FuzzStringShape(f *testing.F) {
	f.Add(uint16(20), uint16(22), uint64(0x200), []byte("C\x00:\x00\\\x00a\x00.\x00e\x00x\x00e\x00\x00\x00"), false, "C:\\a.exe")
	f.Add(uint16(3), uint16(1), uint64(0x2000), []byte{1, 2, 3}, true, "x\x00y")
	f.Fuzz(func(t *testing.T, length, maximum uint16, offset uint64, raw []byte, commandLine bool, text string) {
		const params, block = uint64(0x10000), uint64(0x1000)
		units := make([]uint16, len(raw)/2)
		for i := range units {
			units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
		}
		s := counted{UnicodeString: util.UnicodeString{Length: length, MaximumLength: maximum, Buffer: params + offset}, units: units}
		if !rewritten(s, params, params+block, commandLine) {
			if length%2 != 0 || uint32(maximum) != uint32(length)+terminatorBytes {
				t.Fatalf("length %d capacity %d kept", length, maximum)
			}
			if params+offset+uint64(maximum) > params+block {
				t.Fatalf("buffer outside the block kept")
			}
		}

		// A string laid out as the loader lays it out is never flagged, unless an
		// image path holds a NUL.
		u := utf16.Encode([]rune(text))
		if 2*len(u)+2 > 0xFFFF {
			return
		}
		clean := counted{UnicodeString: util.UnicodeString{Length: uint16(2 * len(u)), MaximumLength: uint16(2*len(u) + 2), Buffer: params + 0x100},
			units: append(u, 0)}
		if 0x100+uint64(clean.MaximumLength) > block {
			return
		}
		hasNUL := strings.ContainsRune(text, 0)
		if got := rewritten(clean, params, params+block, commandLine); got != (hasNUL && !commandLine) {
			t.Fatalf("loader-shaped %q (command line %v) flagged %v", text, commandLine, got)
		}
	})
}

func FuzzPathRules(f *testing.F) {
	f.Add(`\Device\HarddiskVolume3\Windows\System32\svchost.exe`, `C:\Windows\System32\svchost.exe`)
	f.Add(`Registry`, ``)
	f.Fuzz(func(t *testing.T, kernel, image string) {
		if pathsDiffer(kernel, kernel) || pathsDiffer(image, image) {
			t.Fatalf("a path differs from itself")
		}
		file := lastComponent(kernel)
		if len(file) > shortNameBytes {
			file = file[:shortNameBytes]
		}
		upper := []byte(file)
		for i, c := range upper {
			if c >= 'a' && c <= 'z' {
				upper[i] = c - ('a' - 'A')
			}
		}
		if nameDiffers(file, kernel) || nameDiffers(string(upper), kernel) {
			t.Fatalf("the kernel's own short name %q differs from %q", file, kernel)
		}
		if tail, ok := volumeTail(`\Device\HarddiskVolume1` + `\` + strings.TrimLeft(image, `\`)); ok {
			if win, ok := volumeTail(`C:` + tail); !ok || win != tail {
				t.Fatalf("tails %q and %q of one path disagree", tail, win)
			}
		}
	})
}
