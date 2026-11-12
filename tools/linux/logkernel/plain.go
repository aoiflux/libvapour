package logkernel

import (
	"bytes"
	"fmt"
	"math"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxkern"
)

const (
	nsecPerSec  = 1_000_000_000
	nsecPerUsec = 1_000
	usecDigits  = 6
)

func parsePlain(text []byte) []record {
	lines := bytes.Split(text, []byte{'\n'})
	ended := len(lines[len(lines)-1]) == 0
	if ended {
		lines = lines[:len(lines)-1]
	}
	recs := make([]record, 0, len(lines))
	for i, line := range lines {
		r := plainLine(line)
		r.final = ended || i < len(lines)-1
		recs = append(recs, r)
	}
	return recs
}

func plainLine(line []byte) record {
	r := record{text: line}
	if len(line) < 3 || line[0] != '<' {
		return r
	}
	end := bytes.IndexByte(line, '>')
	if end < 0 {
		return r
	}
	prio, ok := decimal(line[1:end])
	if !ok {
		return r
	}
	r.level, r.facility, r.hasLevel = uint8(prio&7), uint8(prio>>3), true
	r.text = line[end+1:]
	if ts, rest, ok := plainTime(r.text); ok {
		r.ts, r.hasTs, r.text = ts, true, rest
	}
	return r
}

func decimal(b []byte) (uint64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' || v > (math.MaxUint64-9)/10 {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
	}
	return v, true
}

func plainTime(b []byte) (uint64, []byte, bool) {
	if len(b) == 0 || b[0] != '[' {
		return 0, nil, false
	}
	b = bytes.TrimLeft(b[1:], " ")
	dot := bytes.IndexByte(b, '.')
	if dot < 0 || len(b) < dot+1+usecDigits+2 || b[dot+1+usecDigits] != ']' || b[dot+2+usecDigits] != ' ' {
		return 0, nil, false
	}
	sec, ok1 := decimal(b[:dot])
	usec, ok2 := decimal(b[dot+1 : dot+1+usecDigits])
	if !ok1 || !ok2 || sec > (math.MaxUint64-usec*nsecPerUsec)/nsecPerSec {
		return 0, nil, false
	}
	return sec*nsecPerSec + usec*nsecPerUsec, b[dot+3+usecDigits:], true
}

// plainText orders the ring oldest first and cuts it at pages that did not
// read, so no line is joined across missing bytes.
func plainText(s span, size, end uint64) (pieces [][]byte, missing bool) {
	start, n := uint64(0), end
	if end > size {
		start, n = end&(size-1), size
	}
	var cur []byte
	for i := uint64(0); i < n; {
		off := (start + i) & (size - 1)
		chunk := min(pageSize-(s.base+off)%pageSize, size-off, n-i)
		if b, ok := s.bytes(off, chunk); ok {
			cur = append(cur, b...)
		} else {
			missing = true
			if len(cur) > 0 {
				pieces, cur = append(pieces, cur), nil
			}
		}
		i += chunk
	}
	if len(cur) > 0 {
		pieces = append(pieces, cur)
	}
	return pieces, missing
}

func readPlain(k *linuxkern.Kernel, diag func(string, ...any), b limits.Limits) ([]record, bool, error) {
	var addrs [3]uint64
	for i, name := range []string{"log_buf", "log_buf_len", "log_end"} {
		a, err := k.Symbol(name)
		if err != nil {
			return nil, false, fmt.Errorf("%v: %w", err, ErrHeader)
		}
		addrs[i] = a
	}
	bufAt, err1 := k.ReadPointer(addrs[0])
	size, err2 := k.ReadUint(addrs[1], 4)
	end, err3 := k.ReadUint(addrs[2], 4)
	if err := firstErr(err1, err2, err3); err != nil {
		return nil, false, fmt.Errorf("log_buf at %#x: %v: %w", addrs[0], err, ErrHeader)
	}
	switch {
	case bufAt == 0 || size == 0 || size&(size-1) != 0:
		return nil, false, fmt.Errorf("log_buf %#x of %d bytes: %w", bufAt, size, ErrHeader)
	case size > uint64(b.MaxBufferBytes):
		return nil, false, fmt.Errorf("log_buf at %#x: %d bytes: %w", bufAt, size, ErrLimit)
	}
	s := readSpan(k.Mem, bufAt, size)
	pieces, missing := plainText(s, size, end)
	var recs []record
	for _, p := range pieces {
		recs = append(recs, parsePlain(p)...)
	}
	if missing {
		diag("%s: log_buf at %#x: %v", Name, bufAt, skipErrors[skipUnread])
	}
	return recs, missing, nil
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
