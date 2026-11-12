package symbols

import (
	"cmp"
	"slices"
	"strings"
	"sync"
)

// Sorted on first use: most tools look symbols up by name only.
type addressIndex struct {
	mu     sync.Mutex
	sorted []Symbol
	stale  bool
}

func (x *addressIndex) invalidate() {
	x.mu.Lock()
	x.stale = true
	x.mu.Unlock()
}

func (t *Table) SymbolsAt(address uint64) []Symbol {
	if t == nil {
		return nil
	}
	t.byAddress.mu.Lock()
	if t.byAddress.sorted == nil || t.byAddress.stale {
		sorted := make([]Symbol, 0, len(t.symbols))
		for _, s := range t.symbols {
			sorted = append(sorted, s)
		}
		slices.SortFunc(sorted, func(a, b Symbol) int {
			if c := cmp.Compare(a.Address, b.Address); c != 0 {
				return c
			}
			return strings.Compare(a.Name, b.Name)
		})
		t.byAddress.sorted, t.byAddress.stale = sorted, false
	}
	sorted := t.byAddress.sorted
	t.byAddress.mu.Unlock()
	i, _ := slices.BinarySearchFunc(sorted, address, func(s Symbol, a uint64) int { return cmp.Compare(s.Address, a) })
	var out []Symbol
	for ; i < len(sorted) && sorted[i].Address == address; i++ {
		out = append(out, sorted[i])
	}
	return out
}

// Nil when nothing is there, so that no symbol is told apart from a symbol
// whose name is empty.
func NamesAt(locator SymbolLocator, address uint64) []string {
	if locator == nil {
		return nil
	}
	found := locator.SymbolsAt(address)
	if len(found) == 0 {
		return nil
	}
	names := make([]string, len(found))
	for i, s := range found {
		names[i] = s.Name
	}
	return names
}
