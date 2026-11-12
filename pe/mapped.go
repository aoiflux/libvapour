package pe

import (
	"errors"
	"fmt"
)

// Residency is decided per 4 KiB page, so reads are split at page
// boundaries: one page that did not read costs only what lies on it.
const pageSize = uint64(0x1000)

var (
	ErrOutsideImage       = errors.New("pe: read outside SizeOfImage")
	ErrUnreadable         = errors.New("pe: image bytes do not read")
	ErrUnterminatedString = errors.New("pe: string has no NUL within its limit")
)

type ReaderAt interface {
	ReadAt(offset, size uint64) ([]byte, error)
}

type ReadRVA func(rva uint32, n int) ([]byte, error)

func MappedReader(r ReaderAt, base uint64, sizeOfImage uint32) ReadRVA {
	return func(rva uint32, n int) ([]byte, error) {
		if n < 0 || uint64(rva)+uint64(n) > uint64(sizeOfImage) {
			return nil, fmt.Errorf("%w: rva 0x%x+%d, SizeOfImage 0x%x", ErrOutsideImage, rva, n, sizeOfImage)
		}
		if n == 0 {
			return []byte{}, nil
		}
		b, err := r.ReadAt(base+uint64(rva), uint64(n))
		if err != nil {
			return nil, fmt.Errorf("%w: rva 0x%x+%d: %w", ErrUnreadable, rva, n, err)
		}
		if len(b) != n {
			return nil, fmt.Errorf("%w: rva 0x%x: %d of %d bytes", ErrUnreadable, rva, len(b), n)
		}
		return b, nil
	}
}

func readAt(read ReadRVA, rva uint64, n uint64) ([]byte, error) {
	if rva+n > 1<<32 {
		return nil, fmt.Errorf("%w: rva 0x%x+%d passes 32 bits", ErrOutsideImage, rva, n)
	}
	b, err := read(uint32(rva), int(n))
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) < n {
		return nil, fmt.Errorf("%w: rva 0x%x: %d of %d bytes", ErrUnreadable, rva, len(b), n)
	}
	return b[:n], nil
}

// A string read stops at the first NUL. Pieces end at page boundaries, and a
// piece that fails is halved, so a string that ends before an unread page or
// before the end of the image still reads.
func readString(read ReadRVA, rva uint64, limit int64) (string, error) {
	var out []byte
	at := rva
	for int64(len(out)) <= limit {
		want := min(pageSize-at%pageSize, uint64(limit-int64(len(out)))+1)
		var piece []byte
		for {
			b, err := readAt(read, at, want)
			if err == nil {
				piece = b
				break
			}
			if want == 1 {
				return "", err
			}
			want /= 2
		}
		if n := indexNUL(piece); n >= 0 {
			return string(append(out, piece[:n]...)), nil
		}
		out = append(out, piece...)
		at += uint64(len(piece))
	}
	return "", fmt.Errorf("%w: rva 0x%x, limit %d bytes", ErrUnterminatedString, rva, limit)
}
