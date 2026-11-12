package diskbootrecords

import (
	"bytes"

	"github.com/aoiflux/libvapour/memory"
)

const (
	chunkBytes = uint64(16 << 20)
	pageBytes  = uint64(0x1000)
)

type scanStats struct {
	unreadPages int
	lastUnread  uint64
	firstUnread uint64
	unreadErr   error
	torn        int
	candidates  int
}

// When a whole chunk does not read, its pages are read one by one, so one
// missing page does not hide the records in the rest of the chunk.
type window struct {
	at   uint64
	data []byte
	held []bool
}

func readWindow(r memory.MemoryReader, at, n uint64, st *scanStats) window {
	if b, err := r.ReadAt(at, n); err == nil && uint64(len(b)) == n {
		return window{at: at, data: b}
	}
	w := window{at: at, data: make([]byte, n), held: make([]bool, pagesSpanned(at, n))}
	for off := uint64(0); off < n; {
		size := min(pageBytes-(at+off)%pageBytes, n-off)
		b, err := r.ReadAt(at+off, size)
		if err == nil && uint64(len(b)) == size {
			copy(w.data[off:], b)
			w.held[(at+off)/pageBytes-at/pageBytes] = true
		} else {
			if err == nil {
				err = memory.ErrOutOfBounds
			}
			page := (at + off) / pageBytes
			switch {
			case st.unreadPages == 0:
				st.firstUnread, st.unreadErr = at+off, err
				fallthrough
			case page > st.lastUnread:
				st.unreadPages++
				st.lastUnread = page
			}
		}
		off += size
	}
	return w
}

func pagesSpanned(at, n uint64) uint64 { return (at+n-1)/pageBytes - at/pageBytes + 1 }

func (w window) holds(off, n uint64) bool {
	if w.held == nil {
		return true
	}
	first := w.at / pageBytes
	for p := (w.at + off) / pageBytes; p <= (w.at+off+n-1)/pageBytes; p++ {
		if !w.held[p-first] {
			return false
		}
	}
	return true
}

// scan visits each record that ends in the marker, in address order. Each
// chunk is read with recordSize-1 bytes of the previous one in front, so a
// record that crosses a chunk end is seen whole, once.
func scan(r memory.MemoryReader, st *scanStats, visit func(addr uint64, b []byte) bool) {
	for _, rg := range memory.MappedRanges(r) {
		for at := rg.Start; at < rg.End; at += chunkBytes {
			lead := min(uint64(recordSize-1), at-rg.Start)
			n := min(chunkBytes, rg.End-at) + lead
			w := readWindow(r, at-lead, n, st)
			for p := uint64(0); ; p++ {
				i := bytes.Index(w.data[p:], marker[:])
				if i < 0 {
					break
				}
				p += uint64(i)
				if p < markerOffset {
					continue
				}
				start := p - markerOffset
				st.candidates++
				if !w.holds(start, recordSize) {
					st.torn++
					continue
				}
				if !visit(at-lead+start, w.data[start:start+recordSize]) {
					return
				}
			}
		}
	}
}
