package scan

import (
	"cmp"
	"crypto/sha256"
	"slices"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
)

type Place struct {
	Pool, Body               uint64
	Virtual                  bool
	VirtualPool, VirtualBody uint64
}

// Zero when the kernel maps no address of the frame.
func (p Place) BodyAddress() uint64 {
	if p.Virtual {
		return p.VirtualBody
	}
	return 0
}

func (p Place) PoolAddress() uint64 {
	if p.Virtual {
		return p.VirtualPool
	}
	return 0
}

// Rows the kernel maps come first, in virtual address order; the rest follow
// by physical address.
func ComparePlaces(a, b Place) int {
	if a.Virtual != b.Virtual {
		if a.Virtual {
			return -1
		}
		return 1
	}
	if a.Virtual {
		if c := cmp.Compare(a.VirtualPool, b.VirtualPool); c != 0 {
			return c
		}
	}
	return cmp.Compare(a.Pool, b.Pool)
}

type Copy struct {
	Pool   uint64
	Mapped bool
}

type Placed[T any] struct {
	Row             T
	Place           Place
	Copies          []Copy
	OtherMapped     []uint64
	TypeIndexFailed bool

	keys  uint16
	size  uint64
	named bool
}

func (p Placed[T]) OtherMappedPool() uint64 {
	if len(p.OtherMapped) == 0 {
		return 0
	}
	return p.OtherMapped[0]
}

func (p Placed[T]) OtherMappedBody() uint64 {
	if len(p.OtherMapped) == 0 {
		return 0
	}
	return p.OtherMapped[0] + (p.Place.Body - p.Place.Pool)
}

func InPlaceOrder[T any](rows []Placed[T]) {
	slices.SortStableFunc(rows, func(a, b Placed[T]) int { return ComparePlaces(a.Place, b.Place) })
}

func Rows[T any](placed []Placed[T]) []T {
	out := make([]T, len(placed))
	for i, p := range placed {
		out[i] = p.Row
	}
	return out
}

type copyCounts struct{ withheld, mapped int }

// A byte-identical allocation at a second physical address adds nothing but
// its address. Every copy the kernel maps is reported, each naming the
// others; unmapped copies are withheld behind the reported ones.
func settleCopies[T any](reader memory.MemoryReader, rows []Placed[T], residency Residency, every bool) ([]Placed[T], copyCounts) {
	var counts copyCounts
	if every {
		return rows, counts
	}
	type key struct {
		digest [32]byte
		size   uint64
	}
	group := map[key]int{}
	var order [][]int
	for i := range rows {
		b, err := reader.ReadAt(rows[i].Place.Pool, rows[i].size)
		if err != nil || rows[i].size == 0 {
			order = append(order, []int{i})
			continue
		}
		k := key{sha256.Sum256(b), rows[i].size}
		g, seen := group[k]
		if !seen {
			g = len(order)
			group[k] = g
			order = append(order, nil)
		}
		order[g] = append(order[g], i)
	}
	var out []Placed[T]
	for _, members := range order {
		if len(members) == 1 {
			out = append(out, rows[members[0]])
			continue
		}
		mapped := make([]bool, len(members))
		anyMapped := false
		for k, i := range members {
			mapped[k] = residency != nil && residency.Contains(rows[i].Place.Pool)
			anyMapped = anyMapped || mapped[k]
		}
		copies := make([]Copy, len(members))
		for k, i := range members {
			copies[k] = Copy{Pool: rows[i].Place.Pool, Mapped: mapped[k]}
		}
		keep := func(k int) bool { return mapped[k] }
		if !anyMapped {
			lowest := 0
			for k, i := range members {
				if rows[i].Place.Pool < rows[members[lowest]].Place.Pool {
					lowest = k
				}
			}
			keep = func(k int) bool { return k == lowest }
		}
		for k, i := range members {
			if !keep(k) {
				counts.withheld++
				continue
			}
			r := rows[i]
			for j, c := range copies {
				if j == k {
					continue
				}
				r.Copies = append(r.Copies, c)
				if c.Mapped {
					r.OtherMapped = append(r.OtherMapped, c.Pool)
				}
			}
			slices.Sort(r.OtherMapped)
			out = append(out, r)
		}
		if anyMapped {
			n := 0
			for _, m := range mapped {
				if m {
					n++
				}
			}
			counts.mapped += n - 1
		}
	}
	return out, counts
}

// The lowest kernel address of the frame, among the page keys the row's
// TypeIndex decodes under, gives the row its virtual address.
func placeRows[T any](rows []Placed[T], residency Residency) error {
	if residency == nil || len(rows) == 0 {
		return nil
	}
	queries := make([]layers.AddressQuery, len(rows))
	for i, r := range rows {
		keys := r.keys
		if keys == 0 {
			keys = layers.AnyPageKey
		}
		queries[i] = layers.AddressQuery{Physical: r.Place.Pool, Keys: keys}
	}
	found, err := residency.LowestAddresses(queries)
	if err != nil {
		return err
	}
	for i, f := range found {
		if i < len(rows) && f.Mapped {
			p := &rows[i].Place
			p.Virtual = true
			p.VirtualPool = f.Virtual
			p.VirtualBody = f.Virtual + (p.Body - p.Pool)
		}
	}
	return nil
}
