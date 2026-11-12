package util

import (
	"bytes"
	"errors"

	"github.com/aoiflux/libvapour/memory"
)

var ErrStringPastLimit = errors.New("util: string exceeds its read limit")

var errNoStringBytes = errors.New("util: string byte count is zero")

// Reads stop at page ends so that a string ending before an unmapped page is
// still read whole.
const stringReadPage = 0x1000

// count is how many bytes may hold the string and often comes from the image;
// limit is the caller's bound on the string itself. The text ends at the first
// NUL, at count, or where memory stops being readable after its first byte.
func ReadCString(r memory.MemoryReader, addr, count, limit uint64) (string, error) {
	if count == 0 {
		return "", errNoStringBytes
	}
	var text []byte
	for count > 0 {
		n := min(stringReadPage-addr%stringReadPage, count)
		b, err := r.ReadAt(addr, n)
		if err != nil {
			if len(text) == 0 {
				return "", err
			}
			break
		}
		if i := bytes.IndexByte(b, 0); i >= 0 {
			text = append(text, b[:i]...)
			break
		}
		text = append(text, b...)
		if uint64(len(text)) > limit {
			return "", ErrStringPastLimit
		}
		if uint64(len(b)) < n {
			break
		}
		next := addr + n
		if next < addr {
			break
		}
		addr, count = next, count-n
	}
	if uint64(len(text)) > limit {
		return "", ErrStringPastLimit
	}
	return DecodeUTF8Replace(text), nil
}
