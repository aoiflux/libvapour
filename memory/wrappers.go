package memory

import (
	"errors"
	"slices"
	"sync"
)

type spanKey struct{ offset, size uint64 }

// Nothing leaves the cache before Clear, so over a live source it would
// serve stale bytes.
type BufferedMemoryReader struct {
	base  MemoryReader
	mu    sync.Mutex
	spans map[spanKey][]byte
}

func NewBufferedMemoryReader(base MemoryReader) *BufferedMemoryReader {
	return &BufferedMemoryReader{base: base, spans: map[spanKey][]byte{}}
}

func (r *BufferedMemoryReader) ReadAt(offset uint64, size uint64) ([]byte, error) {
	key := spanKey{offset, size}
	r.mu.Lock()
	held, ok := r.spans[key]
	r.mu.Unlock()
	if ok {
		return slices.Clone(held), nil
	}
	b, err := r.base.ReadAt(offset, size)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.spans[key] = slices.Clone(b)
	r.mu.Unlock()
	return b, nil
}

func (r *BufferedMemoryReader) Size() uint64 { return r.base.Size() }

func (r *BufferedMemoryReader) Clear() {
	r.mu.Lock()
	clear(r.spans)
	r.mu.Unlock()
}

// Every source's error is kept so a caller can tell an unmapped address in
// all of them from a failed read in one.
type FallbackReader struct {
	primary   MemoryReader
	fallbacks []MemoryReader
}

func NewFallbackReader(primary MemoryReader, fallbacks ...MemoryReader) *FallbackReader {
	held := make([]MemoryReader, 0, len(fallbacks))
	for _, f := range fallbacks {
		if f != nil {
			held = append(held, f)
		}
	}
	return &FallbackReader{primary: primary, fallbacks: held}
}

func (r *FallbackReader) ReadAt(offset uint64, size uint64) ([]byte, error) {
	var errs []error
	if r.primary != nil {
		b, err := r.primary.ReadAt(offset, size)
		if err == nil {
			return b, nil
		}
		errs = append(errs, err)
	}
	for _, f := range r.fallbacks {
		b, err := f.ReadAt(offset, size)
		if err == nil {
			return b, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, ErrOutOfBounds
	}
	return nil, errors.Join(errs...)
}

func (r *FallbackReader) Size() uint64 {
	if r.primary != nil {
		return r.primary.Size()
	}
	var top uint64
	for _, f := range r.fallbacks {
		top = max(top, f.Size())
	}
	return top
}

type Layer interface {
	ReadAt(next MemoryReader, offset uint64, size uint64) ([]byte, error)
}

type stacked struct {
	layer Layer
	next  MemoryReader
}

func (s stacked) ReadAt(offset, size uint64) ([]byte, error) {
	return s.layer.ReadAt(s.next, offset, size)
}

func (s stacked) Size() uint64 { return s.next.Size() }

// The first layer reads the base directly; each later layer reads through
// the ones before it.
type LayeredMemoryReader struct {
	top MemoryReader
}

func NewLayeredMemoryReader(base MemoryReader, layers ...Layer) *LayeredMemoryReader {
	var top MemoryReader = base
	for _, l := range layers {
		if l != nil {
			top = stacked{layer: l, next: top}
		}
	}
	return &LayeredMemoryReader{top: top}
}

func (r *LayeredMemoryReader) ReadAt(offset uint64, size uint64) ([]byte, error) {
	return r.top.ReadAt(offset, size)
}

func (r *LayeredMemoryReader) Size() uint64 { return r.top.Size() }
