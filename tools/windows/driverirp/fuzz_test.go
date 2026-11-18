package driverirp

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

const (
	fuzzKernelBase = uint64(0xfffff80000400000)
	fuzzKernelSize = uint64(0x100000)
	fuzzDriverBase = uint64(0xfffff80001000000)
	fuzzDriverSize = uint64(0x5000)
)

func FuzzEachSlotIsPlacedByItsHandler(f *testing.F) {
	f.Add(uint8(0), fuzzDriverBase+0x100, fuzzKernelBase+0x100, fuzzDriverBase, fuzzDriverSize)
	f.Add(uint8(14), uint64(0), ^uint64(0), uint64(0), uint64(0))
	f.Add(uint8(27), fuzzDriverBase+fuzzDriverSize, fuzzKernelBase-1, fuzzDriverBase+1, ^uint64(0))
	f.Fuzz(func(t *testing.T, slot uint8, handler, rest, start, size uint64) {
		k := testsupport.NewS64Kernel()
		k.AddModule("kernel.exe", fuzzKernelBase, fuzzKernelSize)
		k.AddModule("alpha.sys", fuzzDriverBase, fuzzDriverSize)
		handlers := make([]uint64, len(MajorFunctionNames))
		for i := range handlers {
			handlers[i] = rest
		}
		handlers[int(slot)%len(handlers)] = handler
		k.AddDriver(testsupport.S64Driver{Name: `\Driver\alpha`, ObjectName: "alpha", Start: start, Size: size,
			Handlers: handlers})
		rows, err := Run(k.Context())
		if err != nil || len(rows) != len(handlers) {
			t.Fatalf("%d rows, %v", len(rows), err)
		}
		for i, r := range rows {
			h := handlers[i]
			inImage := start != 0 && h >= start && h-start < size
			owner := ""
			switch {
			case h >= fuzzKernelBase && h-fuzzKernelBase < fuzzKernelSize:
				owner = "kernel"
			case h >= fuzzDriverBase && h-fuzzDriverBase < fuzzDriverSize:
				owner = "alpha"
			}
			if r.Major != i || r.MajorName != MajorFunctionNames[i] || r.Handler != h || r.InImage != inImage ||
				r.Module != owner || r.Unowned != (owner == "") {
				t.Fatalf("slot %d handler 0x%x: %+v", i, h, r)
			}
		}
	})
}
