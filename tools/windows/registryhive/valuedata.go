package registryhive

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/util"
)

// Every non-last big-data segment measured holds 16,344 bytes of data and 4
// bytes of slack; the PDB names no constant for it.
const bigDataSegmentBytes = 16344

const residentBytes = 4

const (
	regNone           = 0
	regSZ             = 1
	regExpandSZ       = 2
	regBinary         = 3
	regDWORD          = 4
	regDWORDBigEndian = 5
	regLink           = 6
	regMultiSZ        = 7
	regResourceList   = 8
	regQWORD          = 11
)

// Raw stops at the first byte that does not read, so a short Raw marks the
// value unreadable without inventing bytes.
func (h *HiveLayer) valueData(ref dataRef, length uint32) []byte {
	if length == 0 {
		return []byte{}
	}
	if ref.resident {
		if length > residentBytes {
			return nil
		}
		var b [residentBytes]byte
		binary.LittleEndian.PutUint32(b[:], ref.field)
		return append([]byte(nil), b[:length]...)
	}
	want := uint64(length)
	if limit := uint64(h.bounds.MaxBufferBytes); limit > 0 && want > limit {
		want = limit
	}
	addr, capacity, err := h.cellExtent(ref.field)
	if err != nil {
		return nil
	}
	if capacity >= uint64(length) {
		return readPrefix(h, addr, want)
	}
	return h.bigData(ref.field, want)
}

func readPrefix(h *HiveLayer, addr, n uint64) []byte {
	b, gaps := extract.ReadPadded(h.cells, addr, n)
	if len(gaps) > 0 {
		return b[:gaps[0].Start-addr]
	}
	return b
}

func (h *HiveLayer) bigData(index uint32, want uint64) []byte {
	if !h.l.hasBig {
		return nil
	}
	bl := h.l.big
	head, _, err := h.readCell(index, bl.list+4)
	if err != nil || expectSignature(head, bl.signature, sigBigData) != nil {
		return nil
	}
	count, ok1 := head.u16(bl.count)
	listIndex, ok2 := head.u32(bl.list)
	if !ok1 || !ok2 || uint64(count)*bigDataSegmentBytes < want {
		return nil
	}
	list, _, err := h.readCell(listIndex, 4*uint64(count))
	if err != nil {
		return nil
	}
	out := make([]byte, 0, want)
	for i := uint64(0); i < uint64(count) && uint64(len(out)) < want; i++ {
		seg, ok := list.u32(4 * i)
		if !ok {
			return out
		}
		addr, capacity, err := h.cellExtent(seg)
		n := min(want-uint64(len(out)), bigDataSegmentBytes)
		if err != nil || capacity < n {
			return out
		}
		part := readPrefix(h, addr, n)
		out = append(out, part...)
		if uint64(len(part)) < n {
			return out
		}
	}
	return out
}

func renderData(typ uint32, raw []byte) string {
	switch typ {
	case regSZ, regExpandSZ, regLink:
		return util.DecodeUTF16LEZ(raw)
	case regMultiSZ:
		return strings.Join(multiString(raw), "\n")
	case regDWORD:
		if len(raw) == 4 {
			return fmt.Sprintf("0x%x", binary.LittleEndian.Uint32(raw))
		}
	case regDWORDBigEndian:
		if len(raw) == 4 {
			return fmt.Sprintf("0x%x", binary.BigEndian.Uint32(raw))
		}
	case regQWORD:
		if len(raw) == 8 {
			return fmt.Sprintf("0x%x", binary.LittleEndian.Uint64(raw))
		}
	}
	return hexBytes(raw)
}

// Learn: the sequence ends at the first empty string.
func multiString(raw []byte) []string {
	var out []string
	for _, s := range strings.Split(util.DecodeUTF16LE(raw), "\x00") {
		if s == "" {
			break
		}
		out = append(out, s)
	}
	return out
}

func hexBytes(raw []byte) string {
	var b strings.Builder
	for i, c := range raw {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%02x", c)
	}
	return b.String()
}
