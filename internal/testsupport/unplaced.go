package testsupport

import (
	"fmt"
	"slices"

	"github.com/aoiflux/libvapour/symbols"
)

type unplacedTable struct {
	*symbols.Table
	names []string
}

// Unplaced refuses the named symbols, or every symbol when none is named, as
// a session with no kernel base does (S79 4.5 step 5).
func Unplaced(t *symbols.Table, names ...string) symbols.SymbolTable {
	return unplacedTable{Table: t, names: names}
}

func (t unplacedTable) LookupSymbol(name string) (symbols.Symbol, error) {
	s, err := t.Table.LookupSymbol(name)
	if err != nil || len(t.names) > 0 && !slices.Contains(t.names, name) {
		return s, err
	}
	return symbols.Symbol{}, fmt.Errorf("%w: %q at 0x%x in its table: no kernel base", symbols.ErrNotPlaced, name, s.Address)
}
