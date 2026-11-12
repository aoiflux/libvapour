package layers_test

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/layers"
)

type flatImage []byte

func (f flatImage) ReadAt(off, size uint64) ([]byte, error) {
	if off > uint64(len(f)) || size > uint64(len(f))-off {
		return nil, fmt.Errorf("image: 0x%x+0x%x is past the end", off, size)
	}
	return f[off : off+size], nil
}

func (f flatImage) Size() uint64 { return uint64(len(f)) }

func ExampleNewProcessLayer() {
	img := make(flatImage, 0x10000)
	const present, writable = 1 << 0, 1 << 1
	put := func(at, v uint64) { binary.LittleEndian.PutUint64(img[at:], v) }
	put(0x1000, 0x2000|present|writable)
	put(0x2000, 0x3000|present|writable)
	put(0x3000, 0x4000|present|writable)
	put(0x4000+8*0x10, 0x8000|present|writable)
	copy(img[0x8000:], "hello")

	space := layers.NewProcessLayer(img, 0x1000, 0)
	b, err := space.ReadAt(0x10000, 5)
	fmt.Println(string(b), err)
	// Output: hello <nil>
}
