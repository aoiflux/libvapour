package registryhive

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

const DumpName = "windows.registry.dump_hives"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        DumpName,
			Description: "Write each listed hive's base block and stable storage as a hive file; requires the output_dir option",
		},
		runDumpAny,
	)
}

// No default directory: a tool writes files only when asked to.
var ErrNoOutputDir = errors.New("registryhive: " + tools.OptionOutputDir + " option not set")

type DumpedHive struct {
	Hive
	Dump
}

// Gaps are file offsets of bytes that did not read and were written as zero.
type Dump struct {
	FileName            string
	Size                uint64
	Captured            uint64
	Gaps                extract.GapMap
	Skipped             string
	BaseBlockUnreadable bool
}

func (h *HiveLayer) StableStoreLength() uint64 { return h.length[0] }

func (h *HiveLayer) StableStoreLengthKnown() (uint64, bool) { return h.length[0], h.lengthKnown[0] }

// One block at a time, so a block that does not map costs that block only.
// Gap starts are storage offsets.
func (h *HiveLayer) ReadStable(offset, length uint64) ([]byte, extract.GapMap) {
	out := make([]byte, length)
	var gaps extract.GapMap
	block := h.l.shape.blockSize
	for done := uint64(0); done < length; {
		at := offset + done
		n := min(block-at%block, length-done)
		if at > 0x7fffffff || at >= h.length[0] {
			gaps = addGap(gaps, at, length-done)
			break
		}
		addr, err := h.cellAddress(uint32(at))
		if err != nil {
			gaps = addGap(gaps, at, n)
			done += n
			continue
		}
		b, g := extract.ReadPadded(h.cells, addr, n)
		copy(out[done:], b)
		for _, gap := range g {
			gaps = addGap(gaps, gap.Start-addr+at, gap.Length)
		}
		done += n
	}
	return out, gaps
}

func addGap(gaps extract.GapMap, start, length uint64) extract.GapMap {
	if n := len(gaps); n > 0 && gaps[n-1].End() == start {
		gaps[n-1].Length += length
		return gaps
	}
	return append(gaps, extract.Gap{Start: start, Length: length})
}

func DumpFileName(path string, cmhive uint64, pointerSize uint8) string {
	return extract.Name{Kind: extract.KindHive, Scope: extract.Kernel, Width: pointerSize,
		Addresses: []uint64{cmhive}, Labels: []string{path}, Ext: extract.ExtHive}.String()
}

// The volatile storage has no file form and is not written. A hive over the
// dump limit is refused whole: a cut hive file no longer parses.
func DumpHive(ctx tools.Context, hive Hive, cellReader memory.MemoryReader, dir string) Dump {
	d := Dump{FileName: DumpFileName(hive.FileFullPath, hive.Address, ctx.Symbols.PointerSize())}
	h, err := NewHiveLayer(ctx, hive.Address)
	if err != nil {
		d.Skipped = err.Error()
		return d
	}
	h.SetCellReader(cellReader)
	stable, known := h.StableStoreLengthKnown()
	if !known {
		d.Skipped = "stable storage length not readable"
		return d
	}
	block := h.l.shape.blockSize
	d.Size = block + stable
	if limit := ctx.DumpLimit(); limit > 0 && d.Size > limit {
		d.Skipped = fmt.Sprintf("%d bytes is over the %d-byte dump limit", d.Size, limit)
		return d
	}
	f, err := extract.CreateNew(dir, d.FileName)
	if err != nil {
		d.Skipped = err.Error()
		return d
	}
	defer f.Close()
	base, err := h.BaseBlock()
	if err != nil {
		base, d.BaseBlockUnreadable = make([]byte, block), true
		d.Gaps = addGap(d.Gaps, 0, block)
	}
	if _, err := f.Write(base); err != nil {
		d.Skipped = err.Error()
		return d
	}
	const chunk = 256 * 4096
	for off := uint64(0); off < stable; off += chunk {
		n := min(uint64(chunk), stable-off)
		b, gaps := h.ReadStable(off, n)
		for _, g := range gaps {
			d.Gaps = addGap(d.Gaps, g.Start+block, g.Length)
		}
		if _, err := f.Write(b); err != nil {
			d.Skipped = err.Error()
			return d
		}
	}
	d.Captured = d.Size - d.Gaps.PaddedBytes()
	return d
}

func runDumpAny(ctx tools.Context) (any, error) { return RunDump(ctx) }

// Saved SAM and SECURITY hives hold account hashes and secrets;
// extract.CreateNew keeps the files to their owner.
func RunDump(ctx tools.Context) ([]DumpedHive, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", DumpName, ctx.Profile.OS())
	}
	dir, ok := ctx.OutputDir()
	if !ok {
		return nil, fmt.Errorf("%s: %w", DumpName, ErrNoOutputDir)
	}
	hives, err := Run(ctx)
	if err != nil {
		return nil, err
	}
	reader := CellReader(ctx)
	out := make([]DumpedHive, 0, len(hives))
	for _, hv := range hives {
		d := DumpHive(ctx, hv, reader, dir)
		if d.Skipped != "" {
			ctx.AddDiagnostic("%s: hive at 0x%x: not saved: %s", DumpName, hv.Address, d.Skipped)
		}
		out = append(out, DumpedHive{Hive: hv, Dump: d})
	}
	return out, nil
}
