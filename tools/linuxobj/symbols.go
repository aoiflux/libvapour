package linuxobj

type nameLister interface {
	SymbolNames() []string
}

// A wrapping table has the method whatever it wraps and answers nil when the
// inner table cannot list, so nil means not listed and an empty slice means
// a table with no names.
func (k *Kernel) SymbolNames() (names []string, listed bool) {
	l, ok := k.sym.(nameLister)
	if !ok {
		return nil, false
	}
	names = l.SymbolNames()
	return names, names != nil
}
