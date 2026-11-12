package linuxobj

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
)

var (
	ErrNoTranslator   = errors.New("linuxobj: the kernel layer does not translate to physical addresses")
	ErrRootMisaligned = errors.New("linuxobj: page-table root is not aligned")
)

const (
	rootAlign64 = 1 << 12
	rootAlign32 = 1 << 5
)

type kernelTranslator interface {
	Translate(virtualAddress uint64) (uint64, error)
}

type ProcessLayer struct {
	DTB    uint64
	Reader memory.MemoryReader
}

// ok false with a nil why means the task has no address space of its own; a
// non-nil why means it has one that cannot be reached.
func (k *Kernel) TaskDTB(t Task) (dtb uint64, ok bool, why error, err error) {
	kernelThread, rerr := k.IsKernelThread(t)
	if rerr != nil {
		return 0, false, rerr, nil
	}
	if kernelThread {
		return 0, false, nil, nil
	}
	mm, rerr := k.Pointer(k.in(t), t.Addr, "task_struct", "mm")
	if rerr != nil {
		return 0, false, rerr, nil
	}
	if mm == 0 {
		return 0, false, nil, nil
	}
	tr, isTr := k.mem.(kernelTranslator)
	if !isTr {
		return 0, false, nil, ErrNoTranslator
	}
	pgd, rerr := k.Pointer(k.mem, mm, "mm_struct", "pgd")
	if rerr != nil {
		return 0, false, fmt.Errorf("linuxobj: mm_struct at %#x: pgd does not read: %w", mm, rerr), nil
	}
	if pgd == 0 {
		return 0, false, fmt.Errorf("linuxobj: mm_struct at %#x: pgd is null", mm), nil
	}
	root, rerr := tr.Translate(pgd)
	if rerr != nil {
		return 0, false, fmt.Errorf("linuxobj: pgd at %#x: does not translate: %w", pgd, rerr), nil
	}
	align := uint64(rootAlign64)
	if k.PointerSize() < 8 {
		align = rootAlign32
	}
	if root%align != 0 {
		return 0, false, fmt.Errorf("linuxobj: pgd at %#x: root %#x: %w", pgd, root, ErrRootMisaligned), nil
	}
	return root, true, nil, nil
}

func (k *Kernel) ProcessLayer(t Task) (layer ProcessLayer, ok bool, why error, err error) {
	root, ok, why, err := k.TaskDTB(t)
	if !ok {
		return ProcessLayer{}, false, why, err
	}
	space, rerr := k.ctx.ProcessSpace(root)
	if rerr != nil {
		return ProcessLayer{}, false, rerr, nil
	}
	return ProcessLayer{DTB: root, Reader: space}, true, nil, nil
}
