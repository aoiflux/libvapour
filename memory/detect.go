package memory

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"

	"github.com/aoiflux/libvapour/limits"
)

var (
	ErrMinidump   = errors.New("memory: minidump of one process, not a memory image")
	ErrCompressed = errors.New("memory: zlib stream, not a memory image")
)

type FormatDetector interface {
	Name() string
	Detect(backing MemoryReader) (MemoryReader, bool, error)
}

const rawFormat = "raw"

func DefaultDetectors() []FormatDetector { return Detectors(limits.Default()) }

// Each detector claims a file only by the signature at its first byte, so
// the order matters only for speed; a file no detector claims is a raw
// image.
func Detectors(l limits.Limits) []FormatDetector {
	l = l.Effective()
	return []FormatDetector{crashDumpDetector{}, limeDetector{l}, elfCoreDetector{l}, minidumpDetector{}, zlibDetector{}}
}

// A claimed file that fails its own checks is refused rather than read as
// raw: its header bytes would otherwise be served as physical memory.
func DetectFormat(backing MemoryReader, detectors ...FormatDetector) (MemoryReader, string, error) {
	if backing == nil {
		return nil, "", fmt.Errorf("memory: detect format: no reader")
	}
	if len(detectors) == 0 {
		detectors = DefaultDetectors()
	}
	for _, d := range detectors {
		if d == nil {
			continue
		}
		r, ok, err := d.Detect(backing)
		if err != nil {
			return nil, d.Name(), err
		}
		if ok && r != nil {
			return r, d.Name(), nil
		}
	}
	return backing, rawFormat, nil
}

func readFull(r MemoryReader, offset, size uint64) ([]byte, error) {
	b, err := r.ReadAt(offset, size)
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) != size {
		return nil, fmt.Errorf("short read of 0x%x of 0x%x bytes at 0x%x: %w", len(b), size, offset, ErrOutOfBounds)
	}
	return b, nil
}

func hasPrefix(r MemoryReader, sig string) bool {
	if r.Size() < uint64(len(sig)) {
		return false
	}
	b, err := readFull(r, 0, uint64(len(sig)))
	return err == nil && string(b) == sig
}

type minidumpDetector struct{}

func (minidumpDetector) Name() string { return "minidump" }

func (minidumpDetector) Detect(backing MemoryReader) (MemoryReader, bool, error) {
	if !hasPrefix(backing, minidumpSignature) {
		return nil, false, nil
	}
	return nil, true, fmt.Errorf("%w: signature %s at offset 0", ErrMinidump, minidumpSignature)
}

const (
	minidumpSignature = "MDMP"
	zlibDeflate       = 8
	zlibMaxWindowLog  = 7
	zlibCheckModulus  = 31
	zlibPresetDict    = 0x20
	zlibTrialInput    = 0x10000
	zlibTrialOutput   = 0x1000
)

type zlibDetector struct{}

func (zlibDetector) Name() string { return "zlib" }

func (zlibDetector) Detect(backing MemoryReader) (MemoryReader, bool, error) {
	if !looksLikeZlib(backing) {
		return nil, false, nil
	}
	return nil, true, fmt.Errorf("%w: rfc 1950 header and a deflate stream at offset 0; decompress it first", ErrCompressed)
}

// About one random file in two thousand passes the two-byte RFC 1950
// check, so the deflate data after the header must also decode before a
// file is refused.
func looksLikeZlib(backing MemoryReader) bool {
	if backing.Size() < 3 {
		return false
	}
	head, err := readFull(backing, 0, min(backing.Size(), zlibTrialInput))
	if err != nil {
		return false
	}
	cmf, flg := head[0], head[1]
	if cmf&0x0F != zlibDeflate || cmf>>4 > zlibMaxWindowLog || (uint16(cmf)<<8|uint16(flg))%zlibCheckModulus != 0 {
		return false
	}
	// A stream that needs a preset dictionary cannot be decoded here, and a
	// capture program has no dictionary to set.
	if flg&zlibPresetDict != 0 {
		return false
	}
	// A short stream that ends cleanly counts; corrupt deflate data does not.
	out, err := io.ReadFull(flate.NewReader(bytes.NewReader(head[2:])), make([]byte, zlibTrialOutput))
	return out == zlibTrialOutput || out > 0 && errors.Is(err, io.ErrUnexpectedEOF)
}
