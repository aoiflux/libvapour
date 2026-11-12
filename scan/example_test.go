package scan_test

import (
	"fmt"

	"github.com/aoiflux/libvapour/scan"
)

type image []byte

func (m image) ReadAt(off, size uint64) ([]byte, error) {
	if off > uint64(len(m)) || size > uint64(len(m))-off {
		return nil, fmt.Errorf("read 0x%x+0x%x past the image", off, size)
	}
	return m[off : off+size], nil
}

func (m image) Size() uint64 { return uint64(len(m)) }

func ExampleSweepTags() {
	mem := make(image, 0x3000)
	copy(mem[0x1004:], "Proc")
	copy(mem[0x2104:], "Thre")
	hits, err := scan.SweepTags(mem, []string{scan.ProcessFilter.Tag, scan.ThreadFilter.Tag}, 2)
	if err != nil {
		panic(err)
	}
	for _, h := range hits {
		fmt.Printf("%s at 0x%x\n", h.Tag, h.Offset)
	}
	// Output:
	// Proc at 0x1004
	// Thre at 0x2104
}
