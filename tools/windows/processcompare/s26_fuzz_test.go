package processcompare

import (
	"testing"

	"github.com/aoiflux/libvapour/tools/any/processscan"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
)

func FuzzCompareViews(f *testing.F) {
	seed := listedPlusOne()
	seed.link([]int{0, 1, 2}, []int{0, 1, 2, 3}, []int{1, 2, 3})
	b, _ := seed.k.ReadAt(seed.at[3], 0xfc0)
	f.Add(b, b[:0x400])
	f.Fuzz(func(t *testing.T, hidden, listed []byte) {
		if len(hidden) > int(stride) {
			hidden = hidden[:stride]
		}
		if len(listed) > int(stride) {
			listed = listed[:stride]
		}
		im := listedPlusOne()
		im.link([]int{0, 1, 2}, []int{0, 1, 2, 3}, []int{1, 2, 3})
		im.k.put(im.at[3], hidden)
		im.k.put(im.at[2], listed)
		im.pool = []processscan.Process{{Offset: phys(im.at[3])}, {Offset: phys(im.at[2])}}
		im.owners = []threadscan.Owned{{Process: im.at[3]}}
		ctx, _ := im.ctx(nil)
		rows, err := run(ctx, im.src)
		if err != nil {
			return
		}
		for _, r := range rows {
			if !(r.ActiveList || r.KernelList || r.SessionRing || r.PoolScan || r.ThreadOwner || r.CsrssHandle) {
				t.Fatalf("row in no view: %+v", r)
			}
			if r.Hidden != (r.Verdict == VerdictHidden) || (r.Verdict == VerdictListed) != r.ActiveList {
				t.Fatalf("verdict %s hidden %v listed %v", r.Verdict, r.Hidden, r.ActiveList)
			}
		}
	})
}
