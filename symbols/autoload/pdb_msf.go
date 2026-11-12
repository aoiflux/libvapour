package autoload

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	msfSignature    = "Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
	msfHeaderSize   = len(msfSignature) + 6*4
	msfAbsentStream = 0xffffffff
)

var errNotMSF = errors.New("autoload: pdb file is not an MSF 7.00 container")

type msfContainer struct {
	data      []byte
	blockSize uint64
	sizes     []uint32
	blocks    [][]uint32
}

func readMSF(data []byte) (*msfContainer, error) {
	if len(data) < msfHeaderSize || string(data[:len(msfSignature)]) != msfSignature {
		return nil, errNotMSF
	}
	header := data[len(msfSignature):]
	blockSize := binary.LittleEndian.Uint32(header[0:])
	blockCount := uint64(binary.LittleEndian.Uint32(header[8:]))
	directoryBytes := uint64(binary.LittleEndian.Uint32(header[12:]))
	mapBlock := uint64(binary.LittleEndian.Uint32(header[20:]))
	switch blockSize {
	case 512, 1024, 2048, 4096:
	default:
		return nil, fmt.Errorf("autoload: pdb block size %d is not 512, 1024, 2048 or 4096", blockSize)
	}
	c := &msfContainer{data: data, blockSize: uint64(blockSize)}
	if fileBlocks := uint64(len(data)) / c.blockSize; blockCount > fileBlocks {
		return nil, fmt.Errorf("autoload: pdb declares %d blocks, the file holds %d", blockCount, fileBlocks)
	}
	directoryBlocks := (directoryBytes + c.blockSize - 1) / c.blockSize
	if directoryBytes < 4 || directoryBlocks*4 > c.blockSize || mapBlock >= blockCount {
		return nil, fmt.Errorf("autoload: pdb stream directory of %d bytes is not listed in one block", directoryBytes)
	}
	directory := make([]byte, 0, directoryBlocks*c.blockSize)
	blockMap := c.block(mapBlock)
	for i := range directoryBlocks {
		b := uint64(binary.LittleEndian.Uint32(blockMap[i*4:]))
		if b >= blockCount {
			return nil, fmt.Errorf("autoload: pdb stream directory names block %d of %d", b, blockCount)
		}
		directory = append(directory, c.block(b)...)
	}
	return c, c.readDirectory(directory[:directoryBytes], blockCount)
}

func (c *msfContainer) block(i uint64) []byte {
	return c.data[i*c.blockSize : (i+1)*c.blockSize]
}

// A well-formed file gives every block to at most one stream, so the streams
// together never span more blocks than the file has; a directory that claims
// more could make one block stand for gigabytes of stream data.
func (c *msfContainer) readDirectory(dir []byte, blockCount uint64) error {
	count := uint64(binary.LittleEndian.Uint32(dir))
	if 4+count*4 > uint64(len(dir)) {
		return fmt.Errorf("autoload: pdb stream directory lists %d streams in %d bytes", count, len(dir))
	}
	c.sizes = make([]uint32, count)
	c.blocks = make([][]uint32, count)
	at := 4 + count*4
	var used uint64
	for i := range count {
		size := binary.LittleEndian.Uint32(dir[4+i*4:])
		c.sizes[i] = size
		if size == msfAbsentStream {
			continue
		}
		n := (uint64(size) + c.blockSize - 1) / c.blockSize
		used += n
		if used > blockCount || at+n*4 > uint64(len(dir)) {
			return fmt.Errorf("autoload: pdb stream %d of %d bytes does not fit the file's blocks or its directory", i, size)
		}
		list := make([]uint32, n)
		for j := range n {
			b := binary.LittleEndian.Uint32(dir[at+j*4:])
			if uint64(b) >= blockCount {
				return fmt.Errorf("autoload: pdb stream %d names block %d of %d", i, b, blockCount)
			}
			list[j] = b
		}
		c.blocks[i] = list
		at += n * 4
	}
	return nil
}

func (c *msfContainer) stream(i int) []byte {
	if i < 0 || i >= len(c.sizes) || c.sizes[i] == msfAbsentStream {
		return nil
	}
	out := make([]byte, 0, uint64(len(c.blocks[i]))*c.blockSize)
	for _, b := range c.blocks[i] {
		out = append(out, c.block(uint64(b))...)
	}
	return out[:c.sizes[i]]
}
