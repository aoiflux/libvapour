package autoload

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

// An RSDS record is the signature, a 16-byte GUID, a 32-bit age and the PDB
// path, NUL-terminated within MAX_PATH.
const (
	rsdsGUIDAt     = 4
	rsdsAgeAt      = 20
	rsdsNameAt     = 24
	rsdsMaxPath    = 260
	rsdsMaxRecord  = rsdsNameAt + rsdsMaxPath + 1
	kernelScanStep = 4 << 20
)

var (
	errNoKernelRecord   = errors.New("autoload: no kernel pdb record in the image")
	errKernelAmbiguous  = errors.New("autoload: the image holds several kernel builds")
	errKernelUndeclared = errors.New("autoload: no image header declares any kernel build found")
)

// ImageBase is the first image header at or below the record, within
// MaxKernelImageBytes; Corroborated says that header's debug directory holds
// this build's CodeView record.
type KernelCandidate struct {
	Fingerprint  Fingerprint
	Offset       uint64
	ImageBase    uint64
	Corroborated bool
}

func ScanKernelCandidates(r memory.MemoryReader, l limits.Limits) ([]KernelCandidate, error) {
	return scanKernelCandidates(r, kernelScanStep, uint64(l.Effective().MaxKernelImageBytes))
}

func scanKernelCandidates(r memory.MemoryReader, step, span uint64) ([]KernelCandidate, error) {
	var found []KernelCandidate
	coverage := memory.ScanWindows(r, step, rsdsMaxRecord, func(base uint64, window []byte) bool {
		owned := min(step, uint64(len(window)))
		for from := 0; uint64(from) < owned; {
			i := bytes.Index(window[from:], []byte("RSDS"))
			if i < 0 || uint64(from+i) >= owned {
				break
			}
			at := from + i
			from = at + 1
			if fp, ok := kernelRecord(window[at:]); ok {
				found = append(found, KernelCandidate{Fingerprint: fp, Offset: base + uint64(at)})
			}
		}
		return false
	})
	if err := coverage.Incomplete(); err != nil && len(found) == 0 {
		return nil, fmt.Errorf("%w in the readable part of the %d-byte image: %w", errNoKernelRecord, r.Size(), err)
	}
	for i := range found {
		found[i].ImageBase, found[i].Corroborated = declaringImage(r, found[i], span)
	}
	return found, nil
}

func kernelRecord(b []byte) (Fingerprint, bool) {
	if len(b) <= rsdsNameAt {
		return Fingerprint{}, false
	}
	path := b[rsdsNameAt:min(len(b), rsdsNameAt+rsdsMaxPath)]
	end := bytes.IndexByte(path, 0)
	if end <= 0 {
		return Fingerprint{}, false
	}
	name := pdbBaseName(string(path[:end]))
	if !isKernelPDB(name) {
		return Fingerprint{}, false
	}
	return Fingerprint{
		PDBName: name,
		GUID:    formatGUID(b[rsdsGUIDAt:rsdsAgeAt]),
		Age:     binary.LittleEndian.Uint32(b[rsdsAgeAt:]),
	}, true
}

// Only the nearest header counts: walking past one that does not declare the
// record would in time find a header that does by chance. The header reads
// its CodeView record at its RVA, so a kernel file held in the page cache,
// laid out by file offset, does not declare the record it holds. Unreadable
// pages are holes in the capture and are passed over.
func declaringImage(r memory.MemoryReader, c KernelCandidate, span uint64) (uint64, bool) {
	page := c.Offset &^ (kernelPageSize - 1)
	for back := uint64(0); back <= span && back <= page; back += kernelPageSize {
		base := page - back
		if !imageHeaderAt(r, base) {
			continue
		}
		records, err := layers.ImageCodeViews(r, base)
		if err != nil {
			return base, false
		}
		for _, rec := range records {
			if pdbBaseName(rec.PDBPath) == c.Fingerprint.PDBName && formatGUID(rec.GUID[:]) == c.Fingerprint.GUID && rec.Age == c.Fingerprint.Age {
				return base, true
			}
		}
		return base, false
	}
	return 0, false
}

const (
	dosLfanewAt = 0x3c
	ntSignature = "PE\x00\x00"
)

func imageHeaderAt(r memory.MemoryReader, base uint64) bool {
	head, err := r.ReadAt(base, kernelPageSize)
	if err != nil || len(head) < kernelPageSize || head[0] != 'M' || head[1] != 'Z' {
		return false
	}
	nt := uint64(binary.LittleEndian.Uint32(head[dosLfanewAt:]))
	return nt > 0 && nt+uint64(len(ntSignature)) <= kernelPageSize && string(head[nt:nt+uint64(len(ntSignature))]) == ntSignature
}

func SelectKernel(candidates []KernelCandidate) (*Fingerprint, error) {
	fp, _, err := selectKernel(candidates)
	return fp, err
}

// One build however many copies is the kernel. Among several builds, the one
// build an image header declares is taken, provisionally: an image can
// declare two, so the session confirms it against the kernel it maps.
func selectKernel(candidates []KernelCandidate) (*Fingerprint, bool, error) {
	if len(candidates) == 0 {
		return nil, false, fmt.Errorf("%w; give an explicit symbol table", errNoKernelRecord)
	}
	builds := buildsOf(candidates, false)
	if len(builds) == 1 {
		fp := builds[0].fp
		return &fp, false, nil
	}
	declared := buildsOf(candidates, true)
	switch len(declared) {
	case 1:
		fp := declared[0].fp
		return &fp, true, nil
	case 0:
		return nil, false, fmt.Errorf("%w: %d builds (%s) and none declared, so none can be told from a copy; give an explicit symbol table",
			errKernelUndeclared, len(builds), describeBuilds(builds))
	}
	return nil, false, fmt.Errorf("%w: %d builds are each declared by an image header (%s); give an explicit symbol table",
		errKernelAmbiguous, len(declared), describeBuilds(declared))
}

type buildSighting struct {
	fp       Fingerprint
	first    uint64
	copies   int
	declared bool
}

func buildsOf(candidates []KernelCandidate, declaredOnly bool) []buildSighting {
	var out []buildSighting
	at := map[Fingerprint]int{}
	for _, c := range candidates {
		if declaredOnly && !c.Corroborated {
			continue
		}
		i, seen := at[c.Fingerprint]
		if !seen {
			at[c.Fingerprint] = len(out)
			out = append(out, buildSighting{fp: c.Fingerprint, first: c.Offset})
			i = len(out) - 1
		}
		b := &out[i]
		b.copies++
		if c.Corroborated && !b.declared {
			b.first, b.declared = c.Offset, true
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].first < out[j].first })
	return out
}

func describeBuilds(builds []buildSighting) string {
	parts := make([]string, 0, len(builds))
	for _, b := range builds {
		s := fmt.Sprintf("%s at 0x%x", b.fp, b.first)
		if b.copies > 1 {
			s += fmt.Sprintf(", %d copies", b.copies)
		}
		if b.declared {
			s += ", declared"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}
