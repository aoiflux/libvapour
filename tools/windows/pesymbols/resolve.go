package pesymbols

import (
	"fmt"
	"slices"

	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// questions holds what was asked of one module, in the caller's order, with
// repeats. Each distinct key is answered at most once, by the first source
// that knows it.
type questions[K comparable] struct {
	asked   []K
	answers map[K]Symbol
	open    int
}

func newQuestions[K comparable](asked []K) *questions[K] {
	q := &questions[K]{asked: asked, answers: map[K]Symbol{}}
	seen := map[K]bool{}
	for _, k := range asked {
		if !seen[k] {
			seen[k] = true
			q.open++
		}
	}
	return q
}

func (q *questions[K]) settled() bool { return q.open == 0 }

func (q *questions[K]) pending(k K) bool {
	_, done := q.answers[k]
	return !done && slices.Contains(q.asked, k)
}

func (q *questions[K]) offer(look func(K) (Symbol, bool)) {
	for _, k := range q.asked {
		if _, done := q.answers[k]; done {
			continue
		}
		if s, ok := look(k); ok {
			q.answers[k] = s
			q.open--
		}
	}
}

// Answers follow the ask order and repeat with it; unanswered keys are
// listed once each.
func (q *questions[K]) results() ([]Symbol, []K) {
	var found []Symbol
	var missing []K
	listed := map[K]bool{}
	for _, k := range q.asked {
		if s, ok := q.answers[k]; ok {
			found = append(found, s)
		} else if !listed[k] {
			listed[k] = true
			missing = append(missing, k)
		}
	}
	return found, missing
}

func Resolve(ctx tools.Context, source string, wanted map[string][]string) (map[string][]Symbol, map[string][]string, error) {
	wanted = folded(wanted)
	inst := lazyInstances(ctx, source, wanted)
	found, missing := resolveNames(ctx, source, wanted, inst.of)
	if inst.err != nil && len(missing) > 0 {
		return found, missing, inst.err
	}
	return found, missing, nil
}

func ResolveIn(ctx tools.Context, source string, instances map[string][]Module, wanted map[string][]string) (map[string][]Symbol, map[string][]string) {
	return resolveNames(ctx, source, folded(wanted), func(module string) []Module { return instances[module] })
}

func ResolveAddresses(ctx tools.Context, source string, wanted map[string][]uint64) (map[string][]Symbol, map[string][]uint64, error) {
	wanted = folded(wanted)
	inst := lazyInstances(ctx, source, wanted)
	found, missing := map[string][]Symbol{}, map[string][]uint64{}
	for _, module := range moduleKeys(wanted) {
		q := newQuestions(wanted[module])
		if source == SourceKernel && module == KernelModuleName {
			if loc, ok := ctx.Symbols.(symbols.SymbolLocator); ok {
				q.offer(func(a uint64) (Symbol, bool) { return firstAt(loc, module, a, a, 0) })
			}
		} else {
			pdbs := newPDBSet()
			for _, m := range inst.of(module) {
				if q.settled() {
					break
				}
				loc, ok := pdbs.table(ctx, m).(symbols.SymbolLocator)
				if !ok {
					continue
				}
				q.offer(func(a uint64) (Symbol, bool) {
					if !inside(m, a) {
						return Symbol{}, false
					}
					return firstAt(loc, module, a-m.Base, a, m.PID)
				})
			}
			pdbs.report(ctx, module)
		}
		var reads exportReads
		for _, m := range inst.of(module) {
			if q.settled() {
				break
			}
			exports, ok := reads.of(ctx, m)
			if !ok {
				continue
			}
			byAddress := map[uint64]pe.Export{}
			for _, e := range exports {
				if a := e.Address(m.Base); e.Name != "" && q.pending(a) {
					if _, taken := byAddress[a]; !taken {
						byAddress[a] = e
					}
				}
			}
			q.offer(func(a uint64) (Symbol, bool) {
				e, ok := byAddress[a]
				return exportSymbol(module, m, e), ok
			})
		}
		reads.report(ctx, module)
		collect(found, missing, module, q)
	}
	if inst.err != nil && len(missing) > 0 {
		return found, missing, inst.err
	}
	return found, missing, nil
}

func resolveNames(ctx tools.Context, source string, wanted map[string][]string, of func(string) []Module) (map[string][]Symbol, map[string][]string) {
	found, missing := map[string][]Symbol{}, map[string][]string{}
	for _, module := range moduleKeys(wanted) {
		q := newQuestions(wanted[module])
		if source == SourceKernel && module == KernelModuleName {
			q.offer(func(n string) (Symbol, bool) {
				s, err := ctx.Symbols.LookupSymbol(n)
				return Symbol{Module: module, Name: n, Address: s.Address}, err == nil
			})
		} else {
			pdbs := newPDBSet()
			for _, m := range of(module) {
				if q.settled() {
					break
				}
				table := pdbs.table(ctx, m)
				if table == nil {
					continue
				}
				q.offer(func(n string) (Symbol, bool) {
					s, err := table.LookupSymbol(n)
					return Symbol{Module: module, Name: n, Address: m.Base + s.Address, FoundInPID: m.PID}, err == nil
				})
			}
			pdbs.report(ctx, module)
		}
		// Another mapping of the same build is still read: an export table
		// is often resident only in part, and the missing page may be
		// resident in another process.
		var reads exportReads
		for _, m := range of(module) {
			if q.settled() {
				break
			}
			exports, ok := reads.of(ctx, m)
			if !ok {
				continue
			}
			byName := map[string]pe.Export{}
			for _, e := range exports {
				if e.Name != "" && q.pending(e.Name) {
					if _, taken := byName[e.Name]; !taken {
						byName[e.Name] = e
					}
				}
			}
			q.offer(func(n string) (Symbol, bool) {
				e, ok := byName[n]
				return exportSymbol(module, m, e), ok
			})
		}
		reads.report(ctx, module)
		collect(found, missing, module, q)
	}
	return found, missing
}

func collect[K comparable](found map[string][]Symbol, missing map[string][]K, module string, q *questions[K]) {
	f, m := q.results()
	if len(f) > 0 {
		found[module] = f
	}
	if len(m) > 0 {
		missing[module] = m
	}
}

func exportSymbol(module string, m Module, e pe.Export) Symbol {
	return Symbol{Module: module, Name: e.Name, Address: e.Address(m.Base), FoundInPID: m.PID,
		Forwarder: e.Forwarder, ForwarderUnreadable: e.ForwarderUnreadable}
}

// The table sorts the names at one address, so the first is the same
// whichever order the PDB listed them in.
func firstAt(loc symbols.SymbolLocator, module string, lookup, address, pid uint64) (Symbol, bool) {
	at := loc.SymbolsAt(lookup)
	if len(at) == 0 {
		return Symbol{}, false
	}
	return Symbol{Module: module, Name: at[0].Name, Address: address, FoundInPID: pid}, true
}

func inside(m Module, address uint64) bool {
	return address >= m.Base && (m.Size == 0 || address-m.Base < m.Size)
}

// exportReads counts the mappings of one module whose exports did not read,
// so a module mapped in a hundred processes gives one line, not a hundred.
type exportReads struct {
	tried, failed int
	first         error
}

func (r *exportReads) of(ctx tools.Context, m Module) ([]pe.Export, bool) {
	r.tried++
	exports, err := Exports(ctx, m)
	if err != nil {
		r.failed++
		if r.first == nil {
			r.first = fmt.Errorf("%s at 0x%x in pid %d: %w", m.Name, m.Base, m.PID, err)
		}
		return nil, false
	}
	return exports, true
}

func (r *exportReads) report(ctx tools.Context, module string) {
	if r.failed > 0 {
		ctx.AddDiagnostic("%s: %s: exports do not read in %d of %d mappings tried: first: %v", Name, module, r.failed, r.tried, r.first)
	}
}
