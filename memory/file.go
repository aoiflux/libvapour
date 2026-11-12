package memory

import (
	"errors"
	"fmt"
	"io"
	"os"
)

type FileMemoryReader struct {
	f    *os.File
	size uint64
}

func NewFileMemoryReader(path string) (*FileMemoryReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("memory: %w", err)
	}
	r, err := NewFileMemoryReaderFromFile(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return r, nil
}

func NewFileMemoryReaderFromFile(f *os.File) (*FileMemoryReader, error) {
	if f == nil {
		return nil, errors.New("memory: no file")
	}
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("memory: stat %s: %w", f.Name(), err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("memory: %s is a directory", f.Name())
	}
	return &FileMemoryReader{f: f, size: uint64(info.Size())}, nil
}

func (r *FileMemoryReader) ReadAt(offset uint64, size uint64) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	if err := checkSpan(offset, size, r.size); err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	n, err := r.f.ReadAt(buf, int64(offset))
	if n == len(buf) {
		return buf, nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return nil, fmt.Errorf("memory: read 0x%x bytes at 0x%x of %s: %w", size, offset, r.f.Name(), err)
}

func (r *FileMemoryReader) Size() uint64 { return r.size }

func (r *FileMemoryReader) ImmutableSnapshot() bool { return true }

func (r *FileMemoryReader) Close() error { return r.f.Close() }
