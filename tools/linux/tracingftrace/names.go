package tracingftrace

import (
	"fmt"
	"sort"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

// S15b 4.3 step 2: an ftrace address sits past the function's first bytes, so
// a name exactly at it is rare; the nearest symbol below it is given with
// its offset.
func kernelNamer(k *linuxkern.Kernel) linuxmodule.KernelNamer {
	var sorted []symbols.Symbol
	var shift uint64
	built, usable := false, false
	return func(addr uint64) []string {
		if names, _ := k.SymbolsAt(addr); len(names) > 0 {
			return names
		}
		if !built {
			built = true
			syms, err1 := k.TableSymbols()
			s, err2 := k.Shift()
			if err1 == nil && err2 == nil && len(syms) > 0 {
				sorted, shift, usable = append([]symbols.Symbol(nil), syms...), s, true
				sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Address < sorted[j].Address })
			}
		}
		if !usable {
			return nil
		}
		link := k.Canonical(addr) - shift
		i := sort.Search(len(sorted), func(i int) bool { return sorted[i].Address > link }) - 1
		if i < 0 {
			return nil
		}
		return []string{fmt.Sprintf("%s+%#x", sorted[i].Name, link-sorted[i].Address)}
	}
}
