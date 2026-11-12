package servicerecord

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

type head struct {
	address uint64
	form    headForm
	fromPDB bool
	// From ScTotalNumServiceRecs when the PDB names it (S34 P2).
	sentinelCount      uint32
	sentinelCountKnown bool
}

var (
	errRepeat    = errors.New("servicerecord: record repeats")
	errEntryCap  = errors.New("servicerecord: MaxListEntries reached")
	errRejected  = errors.New("servicerecord: record fails a check")
	errNoPDBHead = errors.New("servicerecord: PDB names no service database")
)

func pdbHead(r memory.MemoryReader, table symbols.SymbolTable, image addressRange) (head, error) {
	for _, form := range []struct {
		public string
		form   headForm
	}{{publicDatabase, headDatabase}, {publicSentinel, headSentinel}} {
		sym, err := table.LookupSymbol(form.public)
		if err != nil {
			continue
		}
		h := head{address: image.start + sym.Address, form: form.form, fromPDB: true}
		want := uint32(tagDatabase)
		if form.form == headSentinel {
			want = tagSentinel
		}
		if v, ok := readUint32(r, h.address); !ok || v != want {
			return head{}, fmt.Errorf("%s at 0x%x: tag not found", form.public, h.address)
		}
		if form.form == headSentinel {
			if c, err := table.LookupSymbol(publicSentinelSize); err == nil {
				h.sentinelCount, h.sentinelCountKnown = readUint32(r, image.start+c.Address)
			}
		}
		return h, nil
	}
	return head{}, errNoPDBHead
}

// A place counts only when its links lead to records that point back
// (S34 4.4 step 1, M6).
func searchHeads(r memory.MemoryReader, image addressRange) []head {
	var out []head
	for page := image.start &^ (pageSize - 1); page < image.end; page += pageSize {
		data, err := r.ReadAt(page, pageSize)
		if err != nil || len(data) < pageSize {
			continue
		}
		for off := 0; off+4 <= len(data); off += pointerSize {
			at := page + uint64(off)
			switch binary.LittleEndian.Uint32(data[off:]) {
			case tagDatabase:
				if databaseHeadHolds(r, at, image) {
					out = append(out, head{address: at, form: headDatabase})
				}
			case tagSentinel:
				if sentinelHeadHolds(r, at, image) {
					out = append(out, head{address: at, form: headSentinel})
				}
			}
		}
		if page+pageSize < page {
			break
		}
	}
	return out
}

func databaseHeadHolds(r memory.MemoryReader, at uint64, image addressRange) bool {
	first, ok1 := readPointer(r, at+databaseFirst)
	last, ok2 := readPointer(r, at+databaseLast)
	if !ok1 || !ok2 || first == 0 || last == 0 {
		return false
	}
	for _, l := range layouts {
		if l.head != headDatabase {
			continue
		}
		f, why1 := decode(r, l, first, image)
		e, why2 := decode(r, l, last, image)
		if why1 == "" && why2 == "" && f.previous == 0 && e.next == 0 {
			return true
		}
	}
	return false
}

func sentinelHeadHolds(r memory.MemoryReader, at uint64, image addressRange) bool {
	for _, l := range layouts {
		if l.head != headSentinel {
			continue
		}
		first, ok := readPointer(r, at+l.next)
		if !ok || first == 0 {
			continue
		}
		if rec, why := decode(r, l, first, image); why == "" && rec.previous == at {
			return true
		}
	}
	return false
}

type walk struct {
	layout        layout
	records       []record
	cut           error
	cutAt         uint64
	badBackLinks  int
	firstBadLink  uint64
	databaseLast  uint64
	databaseCount uint32
	counter       uint32
	headRead      bool
}

func walkList(r memory.MemoryReader, l layout, h head, image addressRange, maxEntries int) walk {
	w := walk{layout: l}
	var at, before uint64
	if h.form == headDatabase {
		var ok bool
		if at, ok = readPointer(r, h.address+databaseFirst); !ok {
			w.cut, w.cutAt = fmt.Errorf("%w: head not read", errRejected), h.address
			return w
		}
		w.databaseLast, _ = readPointer(r, h.address+databaseLast)
		w.counter, _ = readUint32(r, h.address+databaseCounter)
		w.databaseCount, w.headRead = readUint32(r, h.address+databaseCount)
	} else {
		var ok bool
		if at, ok = readPointer(r, h.address+l.next); !ok {
			w.cut, w.cutAt = fmt.Errorf("%w: head not read", errRejected), h.address
			return w
		}
		before = h.address
	}
	seen := map[uint64]bool{}
	for at != 0 {
		if seen[at] {
			w.cut, w.cutAt = errRepeat, at
			return w
		}
		if maxEntries > 0 && len(w.records) >= maxEntries {
			w.cut, w.cutAt = errEntryCap, at
			return w
		}
		seen[at] = true
		rec, why := decode(r, l, at, image)
		if why != "" {
			w.cut, w.cutAt = fmt.Errorf("%w: %s", errRejected, why), at
			return w
		}
		if rec.previous != before {
			if w.badBackLinks == 0 {
				w.firstBadLink = at
			}
			w.badBackLinks++
		}
		w.records = append(w.records, rec)
		before, at = at, rec.next
	}
	return w
}

// Within the head's family the layout that walks furthest is kept
// (S34 4.4 step 2).
func bestWalk(r memory.MemoryReader, h head, image addressRange, maxEntries int, only *layout) walk {
	var best walk
	chosen := false
	for _, l := range layouts {
		if l.head != h.form || (only != nil && only.name != l.name) {
			continue
		}
		w := walkList(r, l, h, image, maxEntries)
		if !chosen || len(w.records) > len(best.records) {
			best, chosen = w, true
		}
	}
	return best
}

func (w walk) headProblems(h head) []string {
	var out []string
	if h.form == headDatabase {
		if !w.headRead {
			return []string{"head count not read"}
		}
		if n := len(w.records); n > 0 && w.databaseLast != w.records[n-1].address {
			out = append(out, fmt.Sprintf("head names 0x%x as the last record, the walk ends at 0x%x", w.databaseLast, w.records[n-1].address))
		}
		if int(w.databaseCount) != len(w.records) {
			out = append(out, fmt.Sprintf("head counts %d records, the walk reached %d", w.databaseCount, len(w.records)))
		}
		for _, rec := range w.records {
			if rec.sequence > w.counter {
				out = append(out, fmt.Sprintf("record at 0x%x has sequence %d above the head's counter %d", rec.address, rec.sequence, w.counter))
				break
			}
		}
		return out
	}
	if h.sentinelCountKnown && int(h.sentinelCount) != len(w.records) {
		out = append(out, fmt.Sprintf("ScTotalNumServiceRecs is %d, the walk reached %d", h.sentinelCount, len(w.records)))
	}
	return out
}
