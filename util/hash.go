package util

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/aoiflux/libvapour/memory"
)

// Bounds memory for a region of any size.
const hashReadBytes = 1 << 20

type RegionHashes struct {
	MD5    string
	SHA1   string
	SHA256 string
}

func HashRegion(reader memory.MemoryReader, offset uint64, size uint64) (RegionHashes, error) {
	m, s1, s256 := md5.New(), sha1.New(), sha256.New()
	if err := streamRegion(reader, offset, size, m, s1, s256); err != nil {
		return RegionHashes{}, err
	}
	return RegionHashes{MD5: digest(m), SHA1: digest(s1), SHA256: digest(s256)}, nil
}

func MD5Region(reader memory.MemoryReader, offset uint64, size uint64) (string, error) {
	return regionDigest(reader, offset, size, md5.New())
}

func SHA1Region(reader memory.MemoryReader, offset uint64, size uint64) (string, error) {
	return regionDigest(reader, offset, size, sha1.New())
}

func SHA256Region(reader memory.MemoryReader, offset uint64, size uint64) (string, error) {
	return regionDigest(reader, offset, size, sha256.New())
}

func regionDigest(reader memory.MemoryReader, offset, size uint64, h hash.Hash) (string, error) {
	if err := streamRegion(reader, offset, size, h); err != nil {
		return "", err
	}
	return digest(h), nil
}

func digest(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

// A short read is an error: a digest over fewer bytes than asked names a
// region that was never there.
func streamRegion(reader memory.MemoryReader, offset, size uint64, sinks ...hash.Hash) error {
	for done := uint64(0); done < size; {
		n := min(size-done, hashReadBytes)
		b, err := reader.ReadAt(offset+done, n)
		if err != nil {
			return err
		}
		if uint64(len(b)) != n {
			return fmt.Errorf("util: region read at 0x%x: %d of %d bytes", offset+done, len(b), n)
		}
		for _, h := range sinks {
			h.Write(b)
		}
		done += n
	}
	return nil
}
