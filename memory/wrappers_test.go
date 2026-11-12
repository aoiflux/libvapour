package memory

import (
	"bytes"
	"errors"
	"testing"
)

func TestTheBufferServesARepeatedReadFromItsCopy(t *testing.T) {
	base := &countingReader{MemoryReader: image(pattern(64, 1))}
	r := NewBufferedMemoryReader(base)
	first, err := r.ReadAt(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	first[0] ^= 0xff
	second, err := r.ReadAt(8, 8)
	if err != nil || base.reads != 1 || !bytes.Equal(second, pattern(64, 1)[8:16]) {
		t.Fatalf("reads %d, second %x, err %v", base.reads, second, err)
	}
	if _, err := r.ReadAt(60, 8); err == nil {
		t.Fatal("read past the end served")
	}
	if _, err := r.ReadAt(60, 8); err == nil || base.reads != 3 {
		t.Errorf("a failed read was cached: reads %d", base.reads)
	}
	r.Clear()
	if _, err := r.ReadAt(8, 8); err != nil || base.reads != 4 || r.Size() != 64 {
		t.Errorf("after Clear: reads %d err %v", base.reads, err)
	}
}

func TestFallbacksAreTriedInOrderAndEveryErrorIsKept(t *testing.T) {
	primary := failingAt{image([]byte("primary.")), Range{0, 4}}
	second := failingAt{image([]byte("second..")), Range{0, 2}}
	third := image([]byte("third..."))
	r := NewFallbackReader(primary, nil, second, third)
	if b, err := r.ReadAt(4, 4); err != nil || string(b) != "ary." {
		t.Errorf("primary read: %q %v", b, err)
	}
	if b, err := r.ReadAt(2, 2); err != nil || string(b) != "co" {
		t.Errorf("first fallback: %q %v", b, err)
	}
	if b, err := r.ReadAt(0, 2); err != nil || string(b) != "th" {
		t.Errorf("second fallback: %q %v", b, err)
	}
	_, err := NewFallbackReader(primary, image(nil)).ReadAt(0, 2)
	if !errors.Is(err, ErrOutOfBounds) || r.Size() != 8 {
		t.Errorf("all failed: %v", err)
	}
}

type xorLayer byte

func (x xorLayer) ReadAt(next MemoryReader, offset, size uint64) ([]byte, error) {
	b, err := next.ReadAt(offset, size)
	for i := range b {
		b[i] ^= byte(x)
	}
	return b, err
}

type shiftLayer uint64

func (s shiftLayer) ReadAt(next MemoryReader, offset, size uint64) ([]byte, error) {
	return next.ReadAt(offset+uint64(s), size)
}

func TestLayersApplyFromTheBaseOutwards(t *testing.T) {
	base := image([]byte{0, 1, 2, 3, 4, 5})
	r := NewLayeredMemoryReader(base, shiftLayer(2), nil, xorLayer(0x10))
	b, err := r.ReadAt(0, 2)
	if err != nil || !bytes.Equal(b, []byte{0x12, 0x13}) || r.Size() != 6 {
		t.Errorf("layered read %x %v", b, err)
	}
	if b, _ := NewLayeredMemoryReader(base).ReadAt(1, 1); b[0] != 1 {
		t.Error("no layers did not read the base")
	}
}

func TestScatterKeepsRequestOrderAndIsolatesFailures(t *testing.T) {
	reqs := []ScatterRequest{{Offset: 4, Size: 2, Tag: "b"}, {Offset: 100, Size: 1, Tag: "x"}, {Offset: 0, Size: 2, Tag: "a"}}
	out := ScatterRead(image([]byte("abcdef")), reqs)
	if len(out) != 3 || string(out[0].Data) != "ef" || out[1].Error == "" || out[1].Data != nil || string(out[2].Data) != "ab" {
		t.Fatalf("results %+v", out)
	}
	for i := range reqs {
		if out[i].Request != reqs[i] {
			t.Errorf("result %d carries request %+v", i, out[i].Request)
		}
	}
	if r := ScatterRead(nil, reqs[:1]); r[0].Error == "" {
		t.Error("no reader gave no error")
	}
}
