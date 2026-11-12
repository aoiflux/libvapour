package tracingtracepoints

import "encoding/binary"

type entryForm uint8

const (
	formRelative entryForm = iota
	formPointer
)

func (f entryForm) String() string {
	if f == formRelative {
		return "32-bit self-relative offset"
	}
	return "pointer"
}

func (f entryForm) width(pointerSize uint64) uint64 {
	if f == formRelative {
		return 4
	}
	return pointerSize
}

// decodeEntries gives the struct tracepoint address each entry of a
// __tracepoints_ptrs image names (TP3, TP4). A relative entry is the
// signed distance from the entry's own address (offset_to_ptr); the sum is
// taken modulo 2^64 and then put in the reader's address form.
func decodeEntries(raw []byte, start uint64, f entryForm, pointerSize uint64, form func(uint64) uint64) []uint64 {
	w := f.width(pointerSize)
	if w == 0 || (w != 4 && w != 8) {
		return nil
	}
	n := uint64(len(raw)) / w
	out := make([]uint64, 0, n)
	for i := range n {
		at := start + i*w
		b := raw[i*w : i*w+w]
		var v uint64
		switch {
		case f == formRelative:
			v = at + uint64(int64(int32(binary.LittleEndian.Uint32(b))))
		case w == 4:
			v = uint64(binary.LittleEndian.Uint32(b))
		default:
			v = binary.LittleEndian.Uint64(b)
		}
		out = append(out, form(v))
	}
	return out
}

// TP5: a form is a candidate only when it divides the section into whole
// entries; of the candidates, the one under which more entries name a
// readable tracepoint wins, and a tie goes to the form the table types,
// else to the relative form x86 selects.
func chooseForm(size, pointerSize uint64, typed *entryForm, resolved func(entryForm) int) (entryForm, int, bool) {
	best, bestCount, any := formRelative, -1, false
	for _, f := range []entryForm{formRelative, formPointer} {
		w := f.width(pointerSize)
		if w == 0 || size%w != 0 {
			continue
		}
		n := resolved(f)
		switch {
		case n > bestCount:
			best, bestCount, any = f, n, true
		case n == bestCount && typed != nil && *typed == f:
			best = f
		}
	}
	if !any || bestCount <= 0 {
		return best, max(bestCount, 0), false
	}
	return best, bestCount, true
}
