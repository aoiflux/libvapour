package logkernel

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxkern"
)

const (
	stateReserved  = 0
	stateFinalized = 2
	stateReusable  = 3

	lposDataless  = 1
	lposEmptyLine = 3
	lposFailed    = 1

	maxCountBits = 26
	maxSizeBits  = 31
)

type skip int

const (
	skipMiss skip = iota
	skipReserved
	skipReusable
	skipLost
	skipInvalid
	skipDisagree
	skipUnread
	skipBootstrap
	skipKinds
)

var skipErrors = [skipKinds]error{
	errors.New("logkernel: descriptor holds another id"),
	errors.New("logkernel: descriptor reserved by a writer"),
	errors.New("logkernel: descriptor reusable"),
	errors.New("logkernel: record data lost"),
	errors.New("logkernel: data block invalid"),
	errors.New("logkernel: record fields disagree"),
	errors.New("logkernel: record memory unreadable"),
	errors.New("logkernel: bootstrap descriptor"),
}

type skips [skipKinds]int

// lossy counts what a reader failed to read, as opposed to what the kernel
// itself had not written or had already given up.
func (s skips) lossy() bool { return s[skipInvalid]+s[skipDisagree]+s[skipUnread] > 0 }

type ringLayout struct {
	ptr uint64

	countBits, descs, infos, headID, tailID uint64
	sizeBits, data, headLpos, tailLpos      uint64

	descSize, stateVar, begin, next uint64

	infoSize, seq, ts, textLen, facility uint64
	flags, level                         bitField
	caller                               uint64
	hasCaller                            bool
	subsystem, subsystemLen              uint64
	device, deviceLen                    uint64
	hasDevice                            bool
}

func ringLayoutOf(src *layoutSource, ptr uint64) (ringLayout, error) {
	r := resolver{s: src}
	l := ringLayout{ptr: ptr}
	desc := r.off("printk_ringbuffer", "desc_ring")
	text := r.off("printk_ringbuffer", "text_data_ring")
	l.countBits = desc + r.off("prb_desc_ring", "count_bits")
	l.descs = desc + r.off("prb_desc_ring", "descs")
	l.infos = desc + r.off("prb_desc_ring", "infos")
	l.headID = desc + r.off("prb_desc_ring", "head_id")
	l.tailID = desc + r.off("prb_desc_ring", "tail_id")
	l.sizeBits = text + r.off("prb_data_ring", "size_bits")
	l.data = text + r.off("prb_data_ring", "data")
	l.headLpos = text + r.off("prb_data_ring", "head_lpos")
	l.tailLpos = text + r.off("prb_data_ring", "tail_lpos")
	l.descSize = r.size("prb_desc")
	l.stateVar = r.off("prb_desc", "state_var")
	lpos := r.off("prb_desc", "text_blk_lpos")
	l.begin = lpos + r.off("prb_data_blk_lpos", "begin")
	l.next = lpos + r.off("prb_data_blk_lpos", "next")
	l.infoSize = r.size("printk_info")
	l.seq = r.off("printk_info", "seq")
	l.ts = r.off("printk_info", "ts_nsec")
	l.textLen = r.off("printk_info", "text_len")
	if err := r.err(); err != nil {
		return l, err
	}
	l.facility, l.flags, l.level = src.priority("printk_info", l.textLen)
	if f, ok := src.member("printk_info", "caller_id"); ok {
		l.caller, l.hasCaller = f.off, true
	}
	if dev, ok := src.member("printk_info", "dev_info"); ok {
		sub, okS := src.member("dev_printk_info", "subsystem")
		subLen, okSL := src.length("dev_printk_info", "subsystem", "printk_info_subsystem")
		d, okD := src.member("dev_printk_info", "device")
		dLen, okDL := src.length("dev_printk_info", "device", "printk_info_device")
		if okS && okSL && okD && okDL {
			l.subsystem, l.subsystemLen, l.device, l.deviceLen = dev.off+sub.off, subLen, dev.off+d.off, dLen
			l.hasDevice = true
		}
	}
	return l, l.check()
}

func (l ringLayout) check() error {
	fits := func(off, width, size uint64) bool { return off <= size && width <= size-off }
	ok := l.descSize > 0 && l.infoSize > 0 &&
		fits(l.stateVar, l.ptr, l.descSize) && fits(l.begin, l.ptr, l.descSize) && fits(l.next, l.ptr, l.descSize) &&
		fits(l.seq, 8, l.infoSize) && fits(l.ts, 8, l.infoSize) && fits(l.textLen, 2, l.infoSize) &&
		fits(l.facility, 1, l.infoSize) && fits(l.flags.off, 1, l.infoSize) && fits(l.level.off, 1, l.infoSize) &&
		(!l.hasCaller || fits(l.caller, 4, l.infoSize)) &&
		(!l.hasDevice || fits(l.subsystem, l.subsystemLen, l.infoSize) && fits(l.device, l.deviceLen, l.infoSize))
	if !ok {
		return fmt.Errorf("a member lies outside its struct: %w", ErrLayout)
	}
	return nil
}

type ringHeader struct {
	countBits, sizeBits                uint64
	descs, infos, data                 uint64
	headID, tailID, headLpos, tailLpos uint64
}

type ringMath struct {
	width, idMask, flagShift uint64
	count, size              uint64
	sizeBits                 uint64
}

func (l ringLayout) math(h ringHeader) ringMath {
	bitsLong := 8 * l.ptr
	width := ^uint64(0) >> (64 - bitsLong)
	shift := bitsLong - 2
	return ringMath{width: width, idMask: width &^ (3 << shift), flagShift: shift,
		count: 1 << h.countBits, size: 1 << h.sizeBits, sizeBits: h.sizeBits}
}

func (l ringLayout) checkHeader(h ringHeader, b limits.Limits) error {
	if h.countBits < 1 || h.countBits > maxCountBits || h.sizeBits < 1 || h.sizeBits > maxSizeBits || h.sizeBits >= 8*l.ptr {
		return fmt.Errorf("count_bits %d, size_bits %d: %w", h.countBits, h.sizeBits, ErrHeader)
	}
	if h.descs == 0 || h.infos == 0 || h.data == 0 {
		return fmt.Errorf("null descriptor, info or data array: %w", ErrHeader)
	}
	m := l.math(h)
	if (h.headID-h.tailID)&m.idMask >= m.count {
		return fmt.Errorf("head id %#x and tail id %#x more than %d apart: %w", h.headID, h.tailID, m.count, ErrHeader)
	}
	if (h.headLpos-h.tailLpos)&m.width > m.size {
		return fmt.Errorf("data head %#x and tail %#x more than %d bytes apart: %w", h.headLpos, h.tailLpos, m.size, ErrHeader)
	}
	if m.count > uint64(b.MaxTableEntries) || m.count*(l.descSize+l.infoSize) > uint64(b.MaxBufferBytes) ||
		m.size > uint64(b.MaxBufferBytes) {
		return fmt.Errorf("%d descriptors and %d data bytes: %w", m.count, m.size, ErrLimit)
	}
	return nil
}

func (l ringLayout) parse(h ringHeader, descs, infos, data span) ([]record, skips) {
	var out []record
	var sk skips
	m := l.math(h)
	n := (h.headID-h.tailID)&m.idMask + 1
	for i := uint64(0); i < n; i++ {
		id := (h.tailID + i) & m.idMask
		rec, why, ok := l.record(h, m, id, descs, infos, data)
		if !ok {
			sk[why]++
			continue
		}
		out = append(out, rec)
	}
	return out, sk
}

func (l ringLayout) record(h ringHeader, m ringMath, id uint64, descs, infos, data span) (record, skip, bool) {
	idx := id & (m.count - 1)
	at := idx * l.descSize
	sv, ok1 := descs.uint(at+l.stateVar, l.ptr)
	begin, ok2 := descs.uint(at+l.begin, l.ptr)
	next, ok3 := descs.uint(at+l.next, l.ptr)
	if !ok1 || !ok2 || !ok3 {
		return record{}, skipUnread, false
	}
	if sv&m.idMask != id {
		return record{}, skipMiss, false
	}
	state := sv >> m.flagShift & 3
	switch state {
	case stateReserved:
		return record{}, skipReserved, false
	case stateReusable:
		if id == h.tailID && id == uint64(-uint32(m.count+1))&m.idMask && begin == lposFailed && next == lposFailed {
			return record{}, skipBootstrap, false
		}
		return record{}, skipReusable, false
	}
	info, ok := infos.bytes(idx*l.infoSize, l.infoSize)
	if !ok {
		return record{}, skipUnread, false
	}
	r := record{seq: le(info[l.seq : l.seq+8]), hasSeq: true, ts: le(info[l.ts : l.ts+8]), hasTs: true,
		facility: info[l.facility], hasLevel: true, final: state == stateFinalized}
	if r.seq&(m.count-1) != idx {
		return record{}, skipDisagree, false
	}
	r.flags, r.level = l.flags.of(info[l.flags.off]), l.level.of(info[l.level.off])
	if l.hasCaller {
		r.caller, r.hasCaller = uint32(le(info[l.caller:l.caller+4])), true
	}
	if l.hasDevice {
		r.subsystem = cString(info[l.subsystem : l.subsystem+l.subsystemLen])
		r.device = cString(info[l.device : l.device+l.deviceLen])
	}
	text, why, ok := l.text(h, m, id, begin, next, le(info[l.textLen:l.textLen+2]), data)
	if !ok {
		return record{}, why, false
	}
	r.text = text
	return r, 0, true
}

func (l ringLayout) text(h ringHeader, m ringMath, id, begin, next, textLen uint64, data span) ([]byte, skip, bool) {
	if begin&lposDataless != 0 && next&lposDataless != 0 {
		if begin == lposEmptyLine && next == lposEmptyLine {
			return []byte{}, 0, true
		}
		return nil, skipLost, false
	}
	var off, size uint64
	switch {
	case begin>>m.sizeBits == next>>m.sizeBits && begin < next:
		off, size = begin&(m.size-1), next-begin
	case (begin+m.size)&m.width>>m.sizeBits == next>>m.sizeBits:
		off, size = 0, next&(m.size-1)
	default:
		return nil, skipInvalid, false
	}
	if begin%l.ptr != 0 || next%l.ptr != 0 || size < l.ptr {
		return nil, skipInvalid, false
	}
	used := (h.headLpos - h.tailLpos) & m.width
	if (begin-h.tailLpos)&m.width > used || (next-h.tailLpos)&m.width > used {
		return nil, skipInvalid, false
	}
	blockID, ok := data.uint(off, l.ptr)
	if !ok {
		return nil, skipUnread, false
	}
	if blockID != id {
		return nil, skipDisagree, false
	}
	if textLen > size-l.ptr {
		return nil, skipInvalid, false
	}
	b, ok := data.bytes(off+l.ptr, textLen)
	if !ok {
		return nil, skipUnread, false
	}
	return b, 0, true
}

func readRing(k *linuxkern.Kernel, src *layoutSource, diag func(string, ...any), b limits.Limits) ([]record, bool, error) {
	l, err := ringLayoutOf(src, k.PtrSize)
	if err != nil {
		return nil, false, err
	}
	sym, err := k.Symbol("prb")
	if err != nil {
		return nil, false, fmt.Errorf("%v: %w", err, ErrNoLog)
	}
	rb, err := k.ReadPointer(sym)
	if err != nil || rb == 0 {
		return nil, false, fmt.Errorf("prb at %#x: pointer %#x: %v: %w", sym, rb, err, ErrHeader)
	}
	var h ringHeader
	var readErr error
	word := func(off, width uint64) uint64 {
		v, err := k.ReadUint(rb+off, width)
		if err != nil && readErr == nil {
			readErr = err
		}
		return v
	}
	pointer := func(off uint64) uint64 { return word(off, l.ptr) & k.Mask }
	h.countBits, h.sizeBits = word(l.countBits, 4), word(l.sizeBits, 4)
	h.descs, h.infos, h.data = pointer(l.descs), pointer(l.infos), pointer(l.data)
	h.headID, h.tailID = word(l.headID, l.ptr), word(l.tailID, l.ptr)
	h.headLpos, h.tailLpos = word(l.headLpos, l.ptr), word(l.tailLpos, l.ptr)
	if readErr != nil {
		return nil, false, fmt.Errorf("ring at %#x: %v: %w", rb, readErr, ErrHeader)
	}
	if err := l.checkHeader(h, b); err != nil {
		return nil, false, fmt.Errorf("ring at %#x: %w", rb, err)
	}
	m := l.math(h)
	descs := readSpan(k.Mem, h.descs, m.count*l.descSize)
	infos := readSpan(k.Mem, h.infos, m.count*l.infoSize)
	data := readSpan(k.Mem, h.data, m.size)
	recs, sk := l.parse(h, descs, infos, data)
	for why, n := range sk {
		if n > 0 && skip(why) != skipBootstrap {
			diag("%s: ring at %#x: descriptors skipped: %d: %v", Name, rb, n, skipErrors[why])
		}
	}
	return recs, sk.lossy(), nil
}
