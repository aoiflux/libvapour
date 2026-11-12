package util

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"time"
)

func TestAlignmentWithAndWithoutAPowerOfTwo(t *testing.T) {
	for _, c := range []struct{ v, a, down, up uint64 }{
		{0x1234, 0x1000, 0x1000, 0x2000},
		{0x2000, 0x1000, 0x2000, 0x2000},
		{7, 0, 7, 7},
		{10, 3, 9, 12},
		{9, 3, 9, 9},
		{math.MaxUint64, 16, math.MaxUint64 - 15, 0},
	} {
		if got := AlignDown(c.v, c.a); got != c.down {
			t.Errorf("AlignDown(%#x, %#x) = %#x, want %#x", c.v, c.a, got, c.down)
		}
		if got := AlignUp(c.v, c.a); got != c.up {
			t.Errorf("AlignUp(%#x, %#x) = %#x, want %#x", c.v, c.a, got, c.up)
		}
		if got, want := IsAligned(c.v, c.a), c.down == c.v; got != want {
			t.Errorf("IsAligned(%#x, %#x) = %v", c.v, c.a, got)
		}
	}
}

func TestFixedWidthReadsRefuseShortBuffers(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if v, err := ReadUint16(b, binary.LittleEndian); err != nil || v != 0x0201 {
		t.Errorf("ReadUint16 %#x %v", v, err)
	}
	if v, err := ReadUint32(b, binary.BigEndian); err != nil || v != 0x01020304 {
		t.Errorf("ReadUint32 %#x %v", v, err)
	}
	if v, err := ReadUint64(b, binary.LittleEndian); err != nil || v != 0x0807060504030201 {
		t.Errorf("ReadUint64 %#x %v", v, err)
	}
	if _, err := ReadUint16(b[:1], binary.LittleEndian); !errors.Is(err, ErrBufferTooSmall) {
		t.Errorf("ReadUint16 short: %v", err)
	}
	if _, err := ReadUint32(b[:3], binary.LittleEndian); !errors.Is(err, ErrBufferTooSmall) {
		t.Errorf("ReadUint32 short: %v", err)
	}
	if _, err := ReadUint64(b[:7], binary.LittleEndian); !errors.Is(err, ErrBufferTooSmall) {
		t.Errorf("ReadUint64 short: %v", err)
	}
}

func TestSafeSubsliceRefusesRangesOutsideTheBuffer(t *testing.T) {
	b := make([]byte, 16)
	for _, c := range []struct {
		off, n int
		ok     bool
	}{
		{0, 16, true}, {16, 0, true}, {4, 12, true},
		{4, 13, false}, {17, 0, false}, {-1, 1, false}, {1, -1, false},
		{1, math.MaxInt, false}, {math.MaxInt, 1, false},
	} {
		got, ok := SafeSubslice(b, c.off, c.n)
		if ok != c.ok || (ok && len(got) != c.n) {
			t.Errorf("SafeSubslice(%d, %d) = %d bytes, %v", c.off, c.n, len(got), ok)
		}
	}
}

const unixEpochFiletime = 116444736000000000

func TestFiletimeCountsHundredNanosecondTicksFrom1601(t *testing.T) {
	for _, c := range []struct {
		v    uint64
		want string
	}{
		{1, "1601-01-01T00:00:00.0000001Z"},
		{unixEpochFiletime - 1, "1969-12-31T23:59:59.9999999Z"},
		{unixEpochFiletime, "1970-01-01T00:00:00.0000000Z"},
		{1<<63 - 1, "30828-09-14T02:48:05.4775807Z"},
	} {
		got, ok := FiletimeToTime(c.v)
		if !ok || got.Format("2006-01-02T15:04:05.0000000Z") != c.want || got.Location() != time.UTC {
			t.Errorf("FiletimeToTime(%d) = %v %v, want %s", c.v, got, ok, c.want)
		}
	}
	for _, v := range []uint64{0, 1 << 63, math.MaxUint64} {
		if got, ok := FiletimeToTime(v); ok || !got.IsZero() {
			t.Errorf("FiletimeToTime(%#x) = %v, want no time", v, got)
		}
	}
}

func TestFiletimeTextStopsAtYear9999(t *testing.T) {
	last := (uint64(LastRFC3339Second) + secondsFrom1601To1970) * ticksPerSecond
	if s, ok := FiletimeToRFC3339(last + ticksPerSecond - 1); !ok || s != "9999-12-31T23:59:59Z" {
		t.Errorf("last second: %q %v", s, ok)
	}
	if s, ok := FiletimeToRFC3339(last + ticksPerSecond); ok {
		t.Errorf("year 10000 has text %q", s)
	}
	if s, ok := FiletimeToRFC3339(unixEpochFiletime); !ok || s != "1970-01-01T00:00:00Z" {
		t.Errorf("epoch: %q %v", s, ok)
	}
	if _, ok := FiletimeToRFC3339(0); ok {
		t.Error("zero has text")
	}
}
