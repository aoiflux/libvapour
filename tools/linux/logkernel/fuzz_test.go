package logkernel

import (
	"bytes"
	"math/bits"
	"strconv"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

var fuzzRing = ringLayout{ptr: 8,
	countBits: 0, descs: 8, infos: 16, headID: 24, tailID: 32,
	sizeBits: 48, data: 56, headLpos: 64, tailLpos: 72,
	descSize: descSize, stateVar: 0, begin: 8, next: 16,
	infoSize: infoSize, seq: 0, ts: 8, textLen: 16, facility: 18,
	flags: bitField{off: 19, width: 5}, level: bitField{off: 19, shift: 5, width: 3},
	caller: 20, hasCaller: true, subsystem: 24, subsystemLen: 16, device: 40, deviceLen: 48, hasDevice: true}

func ringSeed() (descs, infos, data []byte, h ringHeader) {
	f := newRing(3, 9, 512-24)
	f.add(rec{text: "seed", caller: 1, subsystem: "pci"})
	f.add(rec{text: "wraps past the end of the data array"})
	f.add(rec{emptyLine: true})
	f.add(rec{text: "x", state: fxCommitted})
	d, _ := f.mem.ReadAt(descsAt, 8*descSize)
	i, _ := f.mem.ReadAt(infosAt, 8*infoSize)
	b, _ := f.mem.ReadAt(dataAt, 512)
	return d, i, b, ringHeader{countBits: 3, sizeBits: 9, descs: descsAt, infos: infosAt, data: dataAt,
		headID: f.headID, tailID: f.tailID, headLpos: f.headLpos, tailLpos: f.tailLpos}
}

// The ring is untrusted memory: whatever the descriptors, infos and data
// hold, the parser ends, every id from tail to head is a record or a counted
// skip, and no text is longer than the data array.
func FuzzRingParser(f *testing.F) {
	d, i, b, h := ringSeed()
	f.Add(d, i, b, uint8(h.countBits), uint8(h.sizeBits), h.headID, h.tailID, h.headLpos, h.tailLpos)
	f.Add([]byte{}, []byte{}, []byte{}, uint8(1), uint8(1), uint64(0), uint64(0), uint64(0), uint64(0))
	f.Fuzz(func(t *testing.T, descs, infos, data []byte, countBits, sizeBits uint8, headID, tailID, headLpos, tailLpos uint64) {
		h := ringHeader{countBits: uint64(countBits % 8), sizeBits: uint64(sizeBits % 14), descs: 1, infos: 1, data: 1,
			headID: headID, tailID: tailID, headLpos: headLpos, tailLpos: tailLpos}
		if fuzzRing.checkHeader(h, limits.Limits{}.Effective()) != nil {
			return
		}
		m := fuzzRing.math(h)
		recs, sk := fuzzRing.parse(h, wholeSpan(descs), wholeSpan(infos), wholeSpan(data))
		total := len(recs)
		for _, n := range sk {
			total += n
		}
		if want := (h.headID-h.tailID)&m.idMask + 1; uint64(total) != want {
			t.Fatalf("%d records and skips for %d ids", total, want)
		}
		for _, r := range recs {
			if uint64(len(r.text)) > m.size {
				t.Fatalf("text of %d bytes from a %d-byte ring", len(r.text), m.size)
			}
		}
		rows := rowsOf(recs)
		if len(rows) < len(recs) {
			t.Fatalf("%d rows for %d records", len(rows), len(recs))
		}
	})
}

// The record buffer is untrusted: the walk ends within one pass of the
// buffer and never reads past it.
func FuzzRecordWalk(f *testing.F) {
	seed := newLog(256, true)
	seed.store("one", "SUBSYSTEM=usb\x00DEVICE=c1:2", 6, 0, 2, 1, 3)
	seed.store("two", "", 4, 1, 8, 2, 0x80000000)
	buf, _ := seed.mem.ReadAt(logBufAt, 256)
	f.Add(buf, uint32(0), uint32(seed.next), uint64(0), uint64(2), true)
	f.Add(buf, uint32(0), uint32(0), uint64(0), uint64(0), false)
	l := logLayout{hdr: 20, ts: 0, length: 8, textLen: 10, dictLen: 12, facility: 14,
		flags: bitField{off: 15, width: 5}, level: bitField{off: 15, shift: 5, width: 3}, caller: 16, hasCaller: true}
	f.Fuzz(func(t *testing.T, buf []byte, first, next uint32, firstSeq, count uint64, hasSeq bool) {
		w := logWalk{l: l, buf: wholeSpan(buf), size: uint64(len(buf)), first: uint64(first), next: uint64(next),
			firstSeq: firstSeq, count: count, hasSeq: hasSeq, limit: 1 << 16}
		if w.check(1, limits.Limits{}.Effective()) != nil {
			return
		}
		recs, _ := w.run()
		if uint64(len(recs)) > w.size/l.hdr+1 {
			t.Fatalf("%d records from %d bytes", len(recs), w.size)
		}
		var body int
		for _, r := range recs {
			body += len(r.text)
		}
		if body > len(buf) {
			t.Fatalf("%d text bytes from a %d-byte buffer walked once", body, len(buf))
		}
		_ = rowsOf(recs)
	})
}

func unescape(s string) ([]byte, bool) {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < ' ' || c >= 0x7f {
			return nil, false
		}
		if c != '\\' {
			out = append(out, c)
			continue
		}
		if i+3 >= len(s) || s[i+1] != 'x' {
			return nil, false
		}
		v, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
		if err != nil {
			return nil, false
		}
		out = append(out, byte(v))
		i += 3
	}
	return out, true
}

// The character ring is untrusted: any bytes and any end count give lines
// that come from the buffer.
func FuzzCharacterRing(f *testing.F) {
	f.Add([]byte("<6>[    1.000000] hello\n<12>user\npartial"), uint32(40))
	f.Add([]byte("<99999999999999999999>x\n[ 1.0] y\n"), uint32(1<<31))
	f.Fuzz(func(t *testing.T, buf []byte, end uint32) {
		if len(buf) == 0 {
			return
		}
		size := uint64(1) << (bits.Len(uint(len(buf))) - 1)
		pieces, missing := plainText(wholeSpan(buf[:size]), size, uint64(end))
		if missing {
			t.Fatal("a whole buffer has no missing bytes")
		}
		var n int
		for _, p := range pieces {
			n += len(p)
			for _, r := range parsePlain(p) {
				if len(r.text) > len(p) || r.hasLevel && r.level > 7 {
					t.Fatalf("record %+v from %q", r, p)
				}
				if back, ok := unescape(escapeText(r.text)); !ok || !bytes.Equal(back, r.text) {
					t.Fatalf("escaped %q does not give back %q", escapeText(r.text), r.text)
				}
			}
		}
		if uint64(n) != min(uint64(end), size) {
			t.Fatalf("%d bytes ordered from %d written into %d", n, end, size)
		}
	})
}
