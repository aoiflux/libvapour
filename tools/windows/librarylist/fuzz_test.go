package librarylist

import (
	"encoding/binary"
	"fmt"
	"testing"

	ts "github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

const fuzzBase = uint64(0x10000)

type byteSpace []byte

func (b byteSpace) ReadAt(at, n uint64) ([]byte, error) {
	if at < fuzzBase || at-fuzzBase > uint64(len(b)) || n > uint64(len(b))-(at-fuzzBase) {
		return nil, fmt.Errorf("fuzz: 0x%x bytes at 0x%x outside the space", n, at)
	}
	return b[at-fuzzBase : at-fuzzBase+n], nil
}

func (b byteSpace) Size() uint64 { return 1 << 47 }

func loaderSeed(records int) []byte {
	const recordBytes = 0x140
	buf := make([]byte, 0x60+records*recordBytes)
	put := func(at, v uint64) { binary.LittleEndian.PutUint64(buf[at-fuzzBase:], v) }
	for list := range 3 {
		head := fuzzBase + 0x10 + uint64(list)*0x10
		prev := head
		for r := range records {
			link := fuzzBase + 0x60 + uint64(r)*recordBytes + uint64(list)*0x10
			put(prev, link)
			put(link+8, prev)
			prev = link
		}
		put(prev, head)
		put(head+8, prev)
	}
	return buf
}

func FuzzLoaderLists(f *testing.F) {
	f.Add(loaderSeed(0))
	f.Add(loaderSeed(1))
	f.Add(loaderSeed(3))
	broken := loaderSeed(3)
	binary.LittleEndian.PutUint64(broken[0x60:], 0)
	f.Add(broken)
	layout, err := nativeLayout(ts.S56Table())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		space := byteSpace(data)
		w := winkernel.ListWalker{Tool: Name, Memory: space, Layout: layout.list, Limit: 64}
		out, err := walkLoader(w, space, fuzzBase, layout)
		if err != nil {
			t.Fatalf("a non-strict walk returned %v", err)
		}
		if len(out.records) > 3*64 {
			t.Fatalf("%d records from three lists capped at 64", len(out.records))
		}
		seen := map[uint64]bool{}
		flagged := 0
		for _, r := range out.records {
			if seen[r.at] {
				t.Fatalf("record 0x%x listed twice", r.at)
			}
			seen[r.at] = true
			d := r.fields
			if d.BaseUnreadable {
				flagged++
				if d.Base != 0 {
					t.Fatalf("row %+v: an unread DllBase is 0", d)
				}
			}
			if d.Entry != r.at || !(d.InLoadOrder || d.InMemoryOrder || d.InInitializationOrder) {
				t.Fatalf("row %+v is in no list", d)
			}
		}
		if flagged != out.baseUnread {
			t.Fatalf("%d rows flagged, %d counted", flagged, out.baseUnread)
		}
	})
}
