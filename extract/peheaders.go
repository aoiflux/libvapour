package extract

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
)

// One page holds the headers of nearly every image; larger ones get a second
// read.
const HeaderProbeSize = pageSize

// e_lfanew and NumberOfSections are image bytes, so the follow-up read is
// capped here rather than by the much larger artefact limit.
const MaxHeaderSpan = uint64(0x10000)

// Distinct from pe.ErrNotPE: a page that was not read says nothing about
// whether a PE is there.
var ErrHeadersUnreadable = errors.New("extract: pe headers not readable")

// Decoding stops at padding, so an unread page is reported as unread, never as
// zeroed headers.
func ReadHeaders(reader memory.MemoryReader, base uint64) (*pe.Headers, error) {
	want := HeaderProbeSize
	for {
		b, gaps := ReadPadded(reader, base, want)
		resident := uint64(len(b))
		if len(gaps) > 0 {
			resident = gaps[0].Start - base
		}
		if resident == 0 {
			return nil, fmt.Errorf("%w: 0x%x", ErrHeadersUnreadable, base)
		}
		h, err := pe.ParseHeaders(b[:resident])
		var short *pe.TruncatedError
		if !errors.As(err, &short) {
			return h, err
		}
		switch {
		case resident < want:
			return nil, fmt.Errorf("%w: 0x%x: %w", ErrHeadersUnreadable, base, err)
		case short.Need > MaxHeaderSpan:
			return nil, fmt.Errorf("extract: pe headers at 0x%x span 0x%x, over 0x%x: %w", base, short.Need, MaxHeaderSpan, err)
		case short.Need <= want:
			return nil, err
		}
		want = short.Need
	}
}
