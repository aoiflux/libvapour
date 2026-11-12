package credentialkerberoshook

import (
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools/any/memoryranges"
)

type viewIndex []memoryranges.Mapping

func newViewIndex(maps []memoryranges.Mapping) viewIndex {
	v := make(viewIndex, 0, len(maps))
	for _, m := range maps {
		if m.End >= m.Start {
			v = append(v, m)
		}
	}
	sort.SliceStable(v, func(i, j int) bool { return v[i].Start < v[j].Start })
	return v
}

// VADs do not overlap, so the last one starting at or below the address is
// the only one that can hold it.
func (v viewIndex) at(addr uint64) (memoryranges.Mapping, bool) {
	i := sort.Search(len(v), func(i int) bool { return v[i].Start > addr }) - 1
	if i < 0 || addr > v[i].End {
		return memoryranges.Mapping{}, false
	}
	return v[i], true
}

func (v viewIndex) named(file string) []memoryranges.Mapping {
	var out []memoryranges.Mapping
	for _, m := range v {
		if strings.EqualFold(baseName(m.Path), file) {
			out = append(out, m)
		}
	}
	return out
}
