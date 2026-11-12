package memory_test

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
)

type file []byte

func (f file) ReadAt(offset, size uint64) ([]byte, error) {
	if offset > uint64(len(f)) || size > uint64(len(f))-offset {
		return nil, memory.ErrOutOfBounds
	}
	return f[offset : offset+size], nil
}

func (f file) Size() uint64 { return uint64(len(f)) }

func ExampleNewSegmentedReader() {
	physical, err := memory.NewSegmentedReader(file("HDR:abcdwxyz"), []memory.Segment{
		{PhysicalBase: 0x1000, FileOffset: 4, Length: 4},
		{PhysicalBase: 0x8000, FileOffset: 8, Length: 4},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	b, _ := physical.ReadAt(0x8000, 4)
	_, hole := physical.ReadAt(0x2000, 1)
	fmt.Println(string(b), errors.Is(hole, memory.ErrUnmapped), memory.MappedRanges(physical))
	// Output: wxyz true [{4096 4100} {32768 32772}]
}

func ExampleDetectFormat() {
	_, format, err := memory.DetectFormat(file("no signature here"))
	fmt.Println(format, err)
	// Output: raw <nil>
}
