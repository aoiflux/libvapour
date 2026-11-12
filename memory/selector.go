package memory

import (
	"errors"
	"fmt"
	"sort"
)

var ErrNoProvider = errors.New("memory: no acquisition provider opened the source")

type ProviderSelector struct {
	byName map[string]AcquisitionProvider
	names  []string
}

func NewProviderSelector(providers ...AcquisitionProvider) (*ProviderSelector, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("%w: no providers", ErrProviderConfig)
	}
	s := &ProviderSelector{byName: map[string]AcquisitionProvider{}}
	for i, p := range providers {
		if p == nil {
			return nil, fmt.Errorf("%w: provider %d is nil", ErrProviderConfig, i)
		}
		name := p.Name()
		if name == "" {
			return nil, fmt.Errorf("%w: provider %d has no name", ErrProviderConfig, i)
		}
		if _, dup := s.byName[name]; dup {
			return nil, fmt.Errorf("%w: two providers named %s", ErrProviderConfig, name)
		}
		s.byName[name] = p
		s.names = append(s.names, name)
	}
	sort.Strings(s.names)
	return s, nil
}

// Preferred providers are tried in the caller's order, then the rest by
// name, so the same configuration always tries them in the same order.
func (s *ProviderSelector) Select(preferred []string, config AcquisitionConfig) (AcquisitionSession, string, error) {
	order := make([]string, 0, len(s.names))
	seen := map[string]bool{}
	for _, name := range preferred {
		if _, ok := s.byName[name]; !ok {
			return nil, "", fmt.Errorf("%w: no provider named %s", ErrProviderConfig, name)
		}
		if !seen[name] {
			seen[name] = true
			order = append(order, name)
		}
	}
	for _, name := range s.names {
		if !seen[name] {
			order = append(order, name)
		}
	}
	var errs []error
	for _, name := range order {
		session, err := s.byName[name].Open(config)
		if err == nil && session != nil {
			return session, name, nil
		}
		if err == nil {
			err = fmt.Errorf("%w: %s opened no session and gave no error", ErrProviderContract, name)
		}
		errs = append(errs, fmt.Errorf("provider %s: %w", name, err))
	}
	return nil, "", fmt.Errorf("%w: %w", ErrNoProvider, errors.Join(errs...))
}
