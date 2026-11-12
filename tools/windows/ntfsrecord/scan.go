package ntfsrecord

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

const (
	scanWindow = 1 << 20
	// Every accepted record on the captures sits at a multiple of 8 (S42 M1).
	recordAlignment = 8
)

var (
	ErrNoPhysicalMemory = errors.New("ntfsrecord: no physical memory")
	ErrNotWindows       = errors.New("ntfsrecord: profile is not windows")
)

type tally struct {
	first map[error]uint64
	count map[error]int
	order []error
}

func (t *tally) add(err error, at uint64) {
	if t.count == nil {
		t.count, t.first = map[error]int{}, map[error]uint64{}
	}
	if t.count[err] == 0 {
		t.first[err] = at
		t.order = append(t.order, err)
	}
	t.count[err]++
}

type scanResult struct {
	records    []record
	candidates int
	rejected   tally
	torn       tally
	crowded    tally
	coverage   memory.Coverage
}

var errCrowded = errors.New("ntfsrecord: more signatures in one MiB than MaxMatchesPerChunk")

func scanMemory(phys memory.MemoryReader, perWindow int) scanResult {
	var res scanResult
	needle := []byte(signature)
	res.coverage = memory.ScanWindows(phys, scanWindow, maxRecordSize-1, func(base uint64, w []byte) bool {
		seen := 0
		for i := 0; i < len(w); {
			j := bytes.Index(w[i:], needle)
			if j < 0 {
				break
			}
			at := i + j
			i = at + 1
			if at >= scanWindow {
				break
			}
			physical := base + uint64(at)
			if physical%recordAlignment != 0 {
				continue
			}
			res.candidates++
			if seen++; perWindow > 0 && seen > perWindow {
				res.crowded.add(errCrowded, physical)
				break
			}
			r, err := parseRecord(physical, w[at:])
			if err != nil {
				res.rejected.add(err, physical)
				continue
			}
			if r.fixup == FixupTorn {
				res.torn.add(errTorn, physical)
			}
			res.records = append(res.records, r)
		}
		return false
	})
	return res
}

func scan(ctx tools.Context, tool string) ([]record, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %w", tool, ErrNotWindows)
	}
	phys := ctx.PhysicalMemory()
	if phys == nil {
		return nil, fmt.Errorf("%s: %w", tool, ErrNoPhysicalMemory)
	}
	res := scanMemory(phys, ctx.Bounds().MaxMatchesPerChunk)
	ctx.AddDiagnostic("%s: %d FILE signatures at 8-byte multiples, %d parsed as file record segments", tool,
		res.candidates, len(res.records))
	for _, err := range res.rejected.order {
		ctx.AddDiagnostic("%s: %d candidate records rejected, first at 0x%x: %v", tool, res.rejected.count[err],
			res.rejected.first[err], err)
	}
	if n := res.torn.count[errTorn]; n > 0 {
		ctx.AddDiagnostic("%s: %d records kept with fixup %s, first at 0x%x: %v", tool, n, FixupTorn,
			res.torn.first[errTorn], errTorn)
	}
	if n := res.crowded.count[errCrowded]; n > 0 {
		ctx.AddDiagnostic("%s: %d windows over MaxMatchesPerChunk (%d), first signature dropped at 0x%x", tool, n,
			ctx.Bounds().MaxMatchesPerChunk, res.crowded.first[errCrowded])
	}
	if err := res.coverage.Incomplete(); err != nil {
		ctx.AddDiagnostic("%s: physical memory not fully scanned: %v", tool, err)
		if ctx.StrictMode() {
			return res.records, fmt.Errorf("%s: %w", tool, err)
		}
	}
	return res.records, nil
}
