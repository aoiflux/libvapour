package util

import (
	"encoding/binary"
	"errors"
)

var ErrBufferTooSmall = errors.New("util: buffer too short")

func ReadUint16(buf []byte, order binary.ByteOrder) (uint16, error) {
	if len(buf) < 2 {
		return 0, ErrBufferTooSmall
	}
	return order.Uint16(buf), nil
}

func ReadUint32(buf []byte, order binary.ByteOrder) (uint32, error) {
	if len(buf) < 4 {
		return 0, ErrBufferTooSmall
	}
	return order.Uint32(buf), nil
}

func ReadUint64(buf []byte, order binary.ByteOrder) (uint64, error) {
	if len(buf) < 8 {
		return 0, ErrBufferTooSmall
	}
	return order.Uint64(buf), nil
}
