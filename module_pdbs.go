package libvapour

import (
	"sync"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
)

// Many tools ask for the same module's PDB; a failure is kept too, so a
// build the server lacks costs one request per session, not one per tool.
type modulePDBs struct {
	opts autoload.LoadOptions

	mu   sync.Mutex
	seen map[autoload.Fingerprint]pdbAnswer
}

type pdbAnswer struct {
	table symbols.SymbolTable
	err   error
}

func newModulePDBs(opts autoload.LoadOptions) *modulePDBs {
	return &modulePDBs{opts: opts, seen: map[autoload.Fingerprint]pdbAnswer{}}
}

func (m *modulePDBs) load(fp autoload.Fingerprint) (symbols.SymbolTable, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.seen[fp]; ok {
		return a.table, a.err
	}
	table, err := autoload.LoadWithOptions(&fp, m.opts)
	m.seen[fp] = pdbAnswer{table: table, err: err}
	return table, err
}
