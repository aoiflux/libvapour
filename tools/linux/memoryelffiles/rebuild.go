package memoryelffiles

import (
	"errors"
	"fmt"
	"os"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const (
	ptLoad    = 1
	copyChunk = 1 << 20
)

var (
	ErrNoLoadSegment = errors.New("memoryelffiles: image has no loadable segment with file bytes")
	ErrSegmentWraps  = errors.New("memoryelffiles: segment runs past the end of the address space")
	ErrOverLimit     = errors.New("memoryelffiles: image is larger than the dump limit")
)

type segment struct {
	offset, address, size uint64
}

type plan struct {
	size     uint64
	segments []segment
}

// S61 E3, E4: a loadable segment holds the file bytes [p_offset, p_offset +
// p_filesz) at base address + p_vaddr, so placing each at its offset rebuilds
// the part of the file the loader mapped.
func layout(e linuxobj.ELF, maxEntries int) (plan, error) {
	headers, err := e.ProgramHeaders(maxEntries)
	if err != nil {
		return plan{}, err
	}
	base, ok := e.LoadBias(headers)
	if !ok {
		return plan{}, ErrNoLoadSegment
	}
	var p plan
	for _, h := range headers {
		if h.Type != ptLoad || h.Filesz == 0 {
			continue
		}
		end := h.Offset + h.Filesz
		at := base + h.Vaddr
		if end < h.Offset || at+h.Filesz < at {
			return plan{}, fmt.Errorf("segment at offset %#x: %w", h.Offset, ErrSegmentWraps)
		}
		p.segments = append(p.segments, segment{offset: h.Offset, address: at, size: h.Filesz})
		p.size = max(p.size, end)
	}
	if len(p.segments) == 0 {
		return plan{}, ErrNoLoadSegment
	}
	return p, nil
}

type writer struct {
	ctx    tools.Context
	dir    string
	limit  uint64
	failed tally
	padded tally
}

func (w *writer) write(r memory.MemoryReader, row ELF) string {
	name, padded, err := w.rebuild(r, row)
	if err != nil {
		w.failed.add("elf at %#x in pid %d: %v", row.StartAddress, row.PID, err)
		return ""
	}
	if padded > 0 {
		w.padded.add("%s: %d bytes", name, padded)
	}
	return name
}

func (w *writer) rebuild(r memory.MemoryReader, row ELF) (string, uint64, error) {
	e, ok, err := linuxobj.ParseELF(r, row.StartAddress)
	if err != nil {
		return "", 0, err
	}
	if !ok {
		return "", 0, linuxobj.ErrELFRead
	}
	p, err := layout(e, w.ctx.Bounds().MaxTableEntries)
	if err != nil {
		return "", 0, err
	}
	if p.size > w.limit {
		return "", 0, fmt.Errorf("%d bytes over %d: %w", p.size, w.limit, ErrOverLimit)
	}
	label := row.Process
	if row.PathRead && row.Path != "" {
		label = row.Path
	}
	name := extract.Name{Kind: extract.KindImage, Scope: extract.Process(uint64(row.PID)),
		Addresses: []uint64{row.StartAddress}, Labels: []string{label}, Ext: extract.ExtELF}.String()
	f, clean, err := extract.CreateUnique(w.dir, name, w.ctx.Bounds().NameAttempts)
	if err != nil {
		return "", 0, err
	}
	padded, werr := fill(f, r, p)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", 0, errors.Join(werr, extract.RemoveArtifact(w.dir, clean))
	}
	return clean, padded, nil
}

func fill(f *os.File, r memory.MemoryReader, p plan) (uint64, error) {
	if err := f.Truncate(int64(p.size)); err != nil {
		return 0, err
	}
	var padded uint64
	for _, s := range p.segments {
		for done := uint64(0); done < s.size; {
			n := min(copyChunk, s.size-done)
			b, gaps := extract.ReadPadded(r, s.address+done, n)
			padded += gaps.PaddedBytes()
			if _, err := f.WriteAt(b, int64(s.offset+done)); err != nil {
				return padded, err
			}
			done += n
		}
	}
	return padded, nil
}
