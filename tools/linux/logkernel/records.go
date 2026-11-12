package logkernel

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxkern"
)

// The padding after a record's dictionary aligns the next header, and no
// header type in the sources needs more than 8-byte alignment.
const maxPadding = 8

var (
	errRecordHeader = errors.New("logkernel: record header invalid")
	errWalkLimit    = errors.New("logkernel: record walk over the limit")
)

type logLayout struct {
	hdr, ts, length, textLen, dictLen, facility uint64
	flags, level                                bitField
	caller                                      uint64
	hasCaller                                   bool
}

func logLayoutOf(src *layoutSource) (logLayout, error) {
	typ := "printk_log"
	if _, ok := src.size(typ); !ok {
		typ = "log"
	}
	r := resolver{s: src}
	l := logLayout{hdr: r.size(typ), ts: r.off(typ, "ts_nsec"), length: r.off(typ, "len"),
		textLen: r.off(typ, "text_len"), dictLen: r.off(typ, "dict_len")}
	if err := r.err(); err != nil {
		return l, err
	}
	l.facility, l.flags, l.level = src.priority(typ, l.dictLen)
	if f, ok := src.member(typ, "caller_id"); ok {
		l.caller, l.hasCaller = f.off, true
	}
	fits := func(off, width uint64) bool { return off <= l.hdr && width <= l.hdr-off }
	if !fits(l.ts, 8) || !fits(l.length, 2) || !fits(l.textLen, 2) || !fits(l.dictLen, 2) || !fits(l.facility, 1) ||
		!fits(l.flags.off, 1) || !fits(l.level.off, 1) || l.hasCaller && !fits(l.caller, 4) {
		return l, fmt.Errorf("%s: a member lies outside the header: %w", typ, ErrLayout)
	}
	return l, nil
}

type logWalk struct {
	l               logLayout
	buf             span
	size            uint64
	first, next     uint64
	firstSeq, count uint64
	hasSeq          bool
	limit           int
}

type walkStop struct {
	off uint64
	err error
}

func (w logWalk) run() ([]record, *walkStop) {
	var recs []record
	most := w.size/w.l.hdr + 1
	if w.limit > 0 {
		most = min(most, uint64(w.limit))
	}
	idx, wrapped := w.first, false
	for {
		switch {
		case w.hasSeq && uint64(len(recs)) == w.count:
			return recs, nil
		case !w.hasSeq && len(recs) > 0 && idx == w.next:
			return recs, nil
		case uint64(len(recs)) >= most:
			return recs, &walkStop{idx, errWalkLimit}
		}
		if idx > w.size || w.l.hdr > w.size-idx {
			return recs, w.stop(recs, idx, errRecordHeader)
		}
		hdr, ok := w.buf.bytes(idx, w.l.hdr)
		if !ok {
			return recs, w.stop(recs, idx, skipErrors[skipUnread])
		}
		length := le(hdr[w.l.length : w.l.length+2])
		if length == 0 {
			if wrapped {
				return recs, w.stop(recs, idx, errRecordHeader)
			}
			idx, wrapped = 0, true
			continue
		}
		textLen, dictLen := le(hdr[w.l.textLen:w.l.textLen+2]), le(hdr[w.l.dictLen:w.l.dictLen+2])
		need := w.l.hdr + textLen + dictLen
		if length < need || length-need >= maxPadding || length > w.size-idx || wrapped && idx+length > w.first {
			return recs, w.stop(recs, idx, errRecordHeader)
		}
		body, ok := w.buf.bytes(idx+w.l.hdr, textLen+dictLen)
		if !ok {
			return recs, w.stop(recs, idx, skipErrors[skipUnread])
		}
		r := record{ts: le(hdr[w.l.ts : w.l.ts+8]), hasTs: true, facility: hdr[w.l.facility], hasLevel: true, final: true,
			flags: w.l.flags.of(hdr[w.l.flags.off]), level: w.l.level.of(hdr[w.l.level.off]), text: body[:textLen]}
		if w.hasSeq {
			r.seq, r.hasSeq = w.firstSeq+uint64(len(recs)), true
		}
		if w.l.hasCaller {
			r.caller, r.hasCaller = uint32(le(hdr[w.l.caller:w.l.caller+4])), true
		}
		r.subsystem, r.device = dictionary(body[textLen:])
		recs = append(recs, r)
		idx += length
	}
}

// A walk without sequence numbers cannot tell an empty buffer from a full
// one when the two offsets are equal, so a first record that fails there
// means empty.
func (w logWalk) stop(recs []record, idx uint64, err error) *walkStop {
	if !w.hasSeq && len(recs) == 0 && w.first == w.next {
		return nil
	}
	return &walkStop{idx, err}
}

func dictionary(b []byte) (subsystem, device string) {
	for _, prop := range bytes.Split(b, []byte{0}) {
		key, value, ok := bytes.Cut(prop, []byte{'='})
		if !ok {
			continue
		}
		switch string(key) {
		case "SUBSYSTEM":
			if subsystem == "" {
				subsystem = cString(value)
			}
		case "DEVICE":
			if device == "" {
				device = cString(value)
			}
		}
	}
	return subsystem, device
}

func readRecords(k *linuxkern.Kernel, src *layoutSource, diag func(string, ...any), b limits.Limits) ([]record, bool, error) {
	l, err := logLayoutOf(src)
	if err != nil {
		return nil, false, err
	}
	var readErr error
	at := func(name string) uint64 {
		a, err := k.Symbol(name)
		if err != nil && readErr == nil {
			readErr = err
		}
		return a
	}
	word := func(name string, width uint64) uint64 {
		addr := at(name)
		if readErr != nil {
			return 0
		}
		v, err := k.ReadUint(addr, width)
		if err != nil {
			readErr = fmt.Errorf("%s at %#x: %v", name, addr, err)
		}
		return v
	}
	bufAt := word("log_buf", k.PtrSize) & k.Mask
	w := logWalk{l: l, size: word("log_buf_len", 4), first: word("log_first_idx", 4), next: word("log_next_idx", 4),
		limit: b.MaxListEntries}
	if readErr != nil {
		return nil, false, fmt.Errorf("%v: %w", readErr, ErrHeader)
	}
	if k.HasSymbol("log_first_seq") && k.HasSymbol("log_next_seq") {
		first, next := word("log_first_seq", 8), word("log_next_seq", 8)
		if readErr != nil {
			return nil, false, fmt.Errorf("%v: %w", readErr, ErrHeader)
		}
		if first > next {
			return nil, false, fmt.Errorf("log_first_seq %d after log_next_seq %d: %w", first, next, ErrHeader)
		}
		w.firstSeq, w.count, w.hasSeq = first, next-first, true
	}
	if err := w.check(bufAt, b); err != nil {
		return nil, false, err
	}
	w.buf = readSpan(k.Mem, bufAt, w.size)
	recs, stop := w.run()
	if stop != nil {
		diag("%s: record at %#x: %v", Name, bufAt+stop.off, stop.err)
	}
	return recs, stop != nil, nil
}

func (w logWalk) check(bufAt uint64, b limits.Limits) error {
	switch {
	case bufAt == 0 || w.size == 0:
		return fmt.Errorf("log_buf %#x of %d bytes: %w", bufAt, w.size, ErrHeader)
	case w.size > uint64(b.MaxBufferBytes):
		return fmt.Errorf("log_buf at %#x: %d bytes: %w", bufAt, w.size, ErrLimit)
	case w.first >= w.size || w.next >= w.size:
		return fmt.Errorf("log_buf at %#x: offsets %d and %d in %d bytes: %w", bufAt, w.first, w.next, w.size, ErrHeader)
	}
	return nil
}
