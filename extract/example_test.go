package extract_test

import (
	"fmt"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
)

type flat []byte

func (m flat) ReadAt(offset, size uint64) ([]byte, error) {
	if offset > uint64(len(m)) || size > uint64(len(m))-offset {
		return nil, fmt.Errorf("0x%x bytes at 0x%x pass the end", size, offset)
	}
	return m[offset : offset+size], nil
}

func (m flat) Size() uint64 { return uint64(len(m)) }

func ExampleReadPadded() {
	page := make([]byte, 0x1000)
	copy(page, "resident")
	physical, err := memory.NewSegmentedReader(flat(append(page, page...)), []memory.Segment{
		{PhysicalBase: 0x0000, FileOffset: 0, Length: 0x1000},
		{PhysicalBase: 0x2000, FileOffset: 0x1000, Length: 0x1000},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	b, gaps := extract.ReadPadded(physical, 0, 0x3000)
	fmt.Printf("0x%x bytes, 0x%x of them padding\n", len(b), gaps.PaddedBytes())
	for _, g := range gaps {
		fmt.Printf("gap 0x%x+0x%x\n", g.Start, g.Length)
	}
	for _, r := range gaps.Runs(0, 0x3000) {
		fmt.Printf("run 0x%x+0x%x\n", r.Offset, r.Length)
	}
	// Output:
	// 0x3000 bytes, 0x1000 of them padding
	// gap 0x1000+0x1000
	// run 0x0+0x1000
	// run 0x2000+0x1000
}
