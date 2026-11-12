package util

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

func FuzzDecodeUTF16LE(f *testing.F) {
	f.Add([]byte{'C', 0, ':', 0, 0, 0, 'x', 0})
	f.Add([]byte{0x3D, 0xD8, 0x00, 0xDE, 0x00})
	f.Add([]byte{0x00, 0xD8, 0x41})
	f.Fuzz(func(t *testing.T, b []byte) {
		full, z := DecodeUTF16LE(b), DecodeUTF16LEZ(b)
		if !utf8.ValidString(full) || !utf8.ValidString(z) {
			t.Fatalf("% x: invalid UTF-8 out", b)
		}
		cut := b
		for i := 0; i+1 < len(b); i += 2 {
			if b[i] == 0 && b[i+1] == 0 {
				cut = b[:i]
				break
			}
		}
		if want := DecodeUTF16LE(cut); z != want {
			t.Fatalf("% x: NUL view %q, prefix %q", b, z, want)
		}
		if len(b)%2 == 0 {
			units := make([]uint16, len(b)/2)
			for i := range units {
				units[i] = binary.LittleEndian.Uint16(b[2*i:])
			}
			if want := string(utf16.Decode(units)); full != want {
				t.Fatalf("% x: %q, standard decode %q", b, full, want)
			}
		}
	})
}

func FuzzDecodeUTF8Replace(f *testing.F) {
	f.Add([]byte("plain"))
	f.Add([]byte{0xF4, 0x91, 0x92, 0x93, 0xFF, 0x41})
	f.Add([]byte{0xE1, 0x80, 0xE2, 0xF0, 0x91, 0x92})
	f.Fuzz(func(t *testing.T, b []byte) {
		got := DecodeUTF8Replace(b)
		if !utf8.ValidString(got) {
			t.Fatalf("% x: invalid output", b)
		}
		if utf8.Valid(b) && got != string(b) {
			t.Fatalf("% x: valid input changed to %q", b, got)
		}
		// Replacement never adds a character: each U+FFFD covers at least a byte.
		if n := utf8.RuneCountInString(got); n > len(b) {
			t.Fatalf("% x: %d characters from %d bytes", b, n, len(b))
		}
		if i := bytes.IndexByte(b, 0); i >= 0 && DecodeUTF8Z(b) != DecodeUTF8Replace(b[:i]) {
			t.Fatalf("% x: NUL cut differs", b)
		}
		if ReplaceInvalidUTF8(string(b)) != got {
			t.Fatalf("% x: string form differs", b)
		}
	})
}

func FuzzReadCString(f *testing.F) {
	f.Add([]byte("abc\x00def"), uint16(0xFFE), uint16(16), uint16(8))
	f.Add([]byte("no-nul-at-all"), uint16(0), uint16(64), uint16(3))
	f.Fuzz(func(t *testing.T, data []byte, at, count, limit uint16) {
		if len(data) == 0 {
			return
		}
		r := &pagedReader{data: data, holes: map[uint64]bool{0x1000: true}}
		addr := uint64(at) % uint64(len(data))
		got, err := ReadCString(r, addr, uint64(count), uint64(limit))
		if err != nil {
			return
		}
		raw := data[addr:min(addr+uint64(count), uint64(len(data)))]
		if hole := uint64(0x1000); addr < hole && addr+uint64(len(raw)) > hole {
			raw = raw[:hole-addr]
		}
		if i := bytes.IndexByte(raw, 0); i >= 0 {
			raw = raw[:i]
		}
		if uint64(len(raw)) > uint64(limit) {
			t.Fatalf("%d bytes accepted past a limit of %d", len(raw), limit)
		}
		if want := DecodeUTF8Replace(raw); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

func FuzzUnicodeStringHeader(f *testing.F) {
	f.Add([]byte{10, 0, 12, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0}, true)
	f.Add([]byte{0xFF, 0xFF, 0, 0, 8, 0, 0, 0}, false)
	f.Fuzz(func(t *testing.T, data []byte, wide bool) {
		l := abiUnicodeStringLayout(4)
		if wide {
			l = abiUnicodeStringLayout(8)
		}
		s, err := ReadUnicodeString(&pagedReader{data: data}, 0, l, 0)
		if err == nil && s.Length != 0 && !utf8.ValidString(s.Value) {
			t.Fatalf("invalid text %q", s.Value)
		}
		if err == nil && uint64(len(s.Value)) > 3*MaxUnicodeStringBytes {
			t.Fatalf("text of %d bytes", len(s.Value))
		}
	})
}

func FuzzFiletimeToTime(f *testing.F) {
	f.Add(uint64(unixEpochFiletime))
	f.Add(uint64(1<<63 - 1))
	f.Fuzz(func(t *testing.T, v uint64) {
		got, ok := FiletimeToTime(v)
		if ok != (v != 0 && v < 1<<63) {
			t.Fatalf("%d: ok %v", v, ok)
		}
		if !ok {
			return
		}
		back := uint64(got.Unix()+secondsFrom1601To1970)*ticksPerSecond + uint64(got.Nanosecond()/nanosPerTick)
		if back != v {
			t.Fatalf("%d round-trips to %d", v, back)
		}
	})
}
