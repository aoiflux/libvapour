package imageliteral

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

const Name = "any.image.find_literal"

const (
	OptionLiterals        = Name + ".literals"
	OptionCaseInsensitive = Name + ".case_insensitive"
	OptionMaxScanBytes    = Name + ".max_scan_bytes"
)

var ErrNoPhysical = errors.New("imageliteral: session has no physical layer")

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Placeholder: where given byte strings occur in physical memory; a plain byte search with no analysis of its own",
		},
		RunAny,
	)
}

type Finding struct {
	Literal string
	Offset  uint64
	Length  uint64
	Preview string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type search struct {
	literals [][]byte
	given    []string
	fold     bool
	limit    uint64
	step     uint64
	perChunk int
}

func Run(ctx tools.Context) ([]Finding, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	s, err := readSearch(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if len(s.literals) == 0 {
		ctx.AddDiagnostic("%s: no literals given in %s", Name, OptionLiterals)
		return []Finding{}, nil
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysical)
	}
	if s.limit == 0 || s.limit > physical.Size() {
		s.limit = physical.Size()
	}

	longest := 0
	for _, l := range s.literals {
		longest = max(longest, len(l))
	}
	out := []Finding{}
	capped := 0
	coverage := memory.ScanWindows(physical, s.step, uint64(longest-1), func(base uint64, window []byte) bool {
		if base >= s.limit {
			return true
		}
		if !s.window(base, window, &out) {
			capped++
		}
		return false
	})
	if capped > 0 {
		ctx.AddDiagnostic("%s: %d windows held more than MaxMatchesPerChunk (%d) hits; the rest of each was not searched",
			Name, capped, s.perChunk)
	}
	if err := coverage.Incomplete(); err != nil {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		ctx.AddDiagnostic("%s: %v", Name, err)
	}

	preview := uint64(ctx.Bounds().RowPreviewBytes)
	for i := range out {
		out[i].Preview = previewAt(physical, out[i].Offset, max(preview, out[i].Length), out[i].Length)
	}
	slices.SortFunc(out, func(a, b Finding) int {
		switch {
		case a.Offset != b.Offset:
			if a.Offset < b.Offset {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Literal, b.Literal)
	})
	return out, nil
}

func readSearch(ctx tools.Context) (search, error) {
	bounds := ctx.Bounds()
	s := search{step: uint64(bounds.MaxBufferBytes), perChunk: bounds.MaxMatchesPerChunk}
	given, err := ctx.StringListOption(OptionLiterals)
	if err != nil {
		return s, err
	}
	if s.fold, err = ctx.BoolOption(OptionCaseInsensitive); err != nil {
		return s, err
	}
	if s.limit, _, err = ctx.UintOption(OptionMaxScanBytes); err != nil {
		return s, err
	}
	for _, g := range given {
		if g == "" || int64(len(g)) > bounds.MaxNameBytes {
			return s, fmt.Errorf("option %q: %w: a literal of %d bytes, not 1 to MaxNameBytes (%d)",
				OptionLiterals, tools.ErrOptionType, len(g), bounds.MaxNameBytes)
		}
		if slices.Contains(s.given, g) {
			continue
		}
		s.given = append(s.given, g)
		l := []byte(g)
		if s.fold {
			l = foldASCII(l)
		}
		s.literals = append(s.literals, l)
	}
	return s, nil
}

// A match belongs to the window it starts in below the step, and must end at
// or below the scan limit. false when the window held more than perChunk.
func (s search) window(base uint64, window []byte, out *[]Finding) bool {
	if s.fold {
		window = foldASCII(window)
	}
	owned := uint64(min(uint64(len(window)), s.step))
	found := 0
	for li, lit := range s.literals {
		for at := 0; uint64(at) < owned; {
			i := bytes.Index(window[at:], lit)
			if i < 0 || uint64(at+i) >= owned {
				break
			}
			at += i
			if base+uint64(at)+uint64(len(lit)) > s.limit {
				break
			}
			if found >= s.perChunk {
				return false
			}
			found++
			*out = append(*out, Finding{Literal: s.given[li], Offset: base + uint64(at), Length: uint64(len(lit))})
			at++
		}
	}
	return true
}

// The POSIX locale's tolower (S47 F5): A to Z only.
func foldASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// A preview that runs into a gap is cut back to the match, which read.
func previewAt(r memory.MemoryReader, at, n, match uint64) string {
	b, err := r.ReadAt(at, min(n, r.Size()-at))
	if err != nil {
		if b, err = r.ReadAt(at, match); err != nil {
			return ""
		}
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			c = '.'
		}
		out[i] = c
	}
	return string(out)
}
