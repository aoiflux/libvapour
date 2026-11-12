package executioncompatcachememory

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/util"
)

type element struct {
	keyLength  uint16
	keyMaximum uint16
	keyBuffer  uint64
	data       uint64
}

type entryData struct {
	fileTime uint64
	size     uint32
	buffer   uint64
}

func decodeElement(b []byte, key util.UnicodeStringLayout) (element, error) {
	if len(b) < elementSize {
		return element{}, fmt.Errorf("%w: element of %d bytes", ErrShort, len(b))
	}
	at := uint64(elementKeyOffset)
	if key.BufferOffset+8 > elementDataOffset-elementKeyOffset || key.LengthOffset+2 > key.BufferOffset || key.MaximumLengthOffset+2 > key.BufferOffset {
		return element{}, fmt.Errorf("%w: _UNICODE_STRING layout", ErrTypeMissing)
	}
	e := element{
		keyLength:  binary.LittleEndian.Uint16(b[at+key.LengthOffset:]),
		keyMaximum: binary.LittleEndian.Uint16(b[at+key.MaximumLengthOffset:]),
		keyBuffer:  binary.LittleEndian.Uint64(b[at+key.BufferOffset:]),
		data:       binary.LittleEndian.Uint64(b[elementDataOffset:]),
	}
	if e.keyLength%2 != 0 || e.keyLength > e.keyMaximum {
		return e, fmt.Errorf("%w: Length %d, MaximumLength %d", ErrKeyLayout, e.keyLength, e.keyMaximum)
	}
	return e, nil
}

func decodeEntryData(b []byte) (entryData, error) {
	if len(b) < dataObjectSize {
		return entryData{}, fmt.Errorf("%w: data object of %d bytes", ErrShort, len(b))
	}
	return entryData{
		fileTime: binary.LittleEndian.Uint64(b[dataTimeOffset:]),
		size:     binary.LittleEndian.Uint32(b[dataSizeOffset:]),
		buffer:   binary.LittleEndian.Uint64(b[dataBufferOffset:]),
	}, nil
}
