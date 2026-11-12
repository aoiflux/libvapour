package testsupport

import (
	"fmt"
	"sync"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

// The highest user-mode address of a 64-bit process (S79 D10).
const userSpaceTop = uint64(0x00007FFFFFFFFFFF)

// Bits 11:0 of CR3 are flags, not part of the table address (S79 D7).
const pageTableRootFlags = uint64(0xfff)

func sameRoot(a, b uint64) bool { return a&^pageTableRootFlags == b&^pageTableRootFlags }

func processMemoryWrapper(ctx *tools.Context, who string, wrap func(dtb uint64, inner memory.MemoryReader) (memory.MemoryReader, error)) {
	inner := ctx.ProcessMemory
	if inner == nil {
		panic("testsupport: " + who + " needs a context with a ProcessMemory factory")
	}
	ctx.ProcessMemory = func(dtb uint64) (memory.MemoryReader, error) {
		r, err := inner(dtb)
		if err != nil {
			return r, err
		}
		return wrap(dtb, r)
	}
}

// A user address read through the kernel layer resolves in whichever process
// the capture caught running, so its bytes would be credited to the wrong
// process. The recorder lets a test see a tool fall back to that layer.
func RefuseProcessSpace(ctx tools.Context, dtb uint64) (tools.Context, *UserReads) {
	reads := &UserReads{}
	processMemoryWrapper(&ctx, "RefuseProcessSpace", func(d uint64, r memory.MemoryReader) (memory.MemoryReader, error) {
		if sameRoot(d, dtb) {
			return nil, fmt.Errorf("testsupport: page table root 0x%x refused", d)
		}
		return r, nil
	})
	ctx.Memory = &userReadRecorder{MemoryReader: ctx.Memory, reads: reads}
	return ctx, reads
}

type UserReads struct {
	mu        sync.Mutex
	addresses []uint64
}

func (u *UserReads) record(at uint64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.addresses = append(u.addresses, at)
}

func (u *UserReads) Addresses() []uint64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]uint64(nil), u.addresses...)
}

type userReadRecorder struct {
	memory.MemoryReader
	reads *UserReads
}

func (r *userReadRecorder) ReadAt(offset, size uint64) ([]byte, error) {
	if offset <= userSpaceTop {
		r.reads.record(offset)
	}
	return r.MemoryReader.ReadAt(offset, size)
}

type HoleReader struct {
	memory.MemoryReader
	From, To uint64
}

func (h HoleReader) ReadAt(offset, size uint64) ([]byte, error) {
	if offset < h.To && h.From < offset+size {
		return nil, memory.ErrOutOfBounds
	}
	return h.MemoryReader.ReadAt(offset, size)
}

func HoleInProcess(ctx *tools.Context, dtb, from, to uint64) {
	processMemoryWrapper(ctx, "HoleInProcess", func(d uint64, r memory.MemoryReader) (memory.MemoryReader, error) {
		if d != dtb {
			return r, nil
		}
		return HoleReader{MemoryReader: r, From: from, To: to}, nil
	})
}

type PatchReader struct {
	memory.MemoryReader
	At   uint64
	Data []byte
}

func (p PatchReader) ReadAt(offset, size uint64) ([]byte, error) {
	raw, err := p.MemoryReader.ReadAt(offset, size)
	if err != nil {
		return raw, err
	}
	end := p.At + uint64(len(p.Data))
	lo, hi := max(offset, p.At), min(offset+uint64(len(raw)), end)
	if lo >= hi {
		return raw, nil
	}
	out := append([]byte(nil), raw...)
	copy(out[lo-offset:hi-offset], p.Data[lo-p.At:hi-p.At])
	return out, nil
}

func PatchInProcess(ctx *tools.Context, dtb, at uint64, data []byte) {
	processMemoryWrapper(ctx, "PatchInProcess", func(d uint64, r memory.MemoryReader) (memory.MemoryReader, error) {
		if d != dtb {
			return r, nil
		}
		return PatchReader{MemoryReader: r, At: at, Data: data}, nil
	})
}
