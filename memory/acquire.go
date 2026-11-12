package memory

import (
	"errors"
	"fmt"
	"io"

	"github.com/aoiflux/libvapour/limits"
)

type DiagnosticCategory string

const (
	DiagnosticProviderConfig DiagnosticCategory = "provider_config"
	DiagnosticProviderOpen   DiagnosticCategory = "provider_open"
	DiagnosticProviderRead   DiagnosticCategory = "provider_read"
	DiagnosticProviderClose  DiagnosticCategory = "provider_close"
)

type AcquisitionDiagnostic struct {
	Category DiagnosticCategory `json:"category"`
	Provider string             `json:"provider"`
	Message  string             `json:"message"`
}

type AcquisitionConfig struct {
	Source  string
	Strict  bool
	Options map[string]any
	Limits  limits.Limits
}

type AcquisitionProvider interface {
	Name() string
	Open(config AcquisitionConfig) (AcquisitionSession, error)
}

type AcquisitionSession interface {
	Reader() MemoryReader
	Close() error
	Diagnostics() []AcquisitionDiagnostic
}

var ErrProviderContract = errors.New("memory: provider breaks the acquisition contract")

func knownCategory(c DiagnosticCategory) bool {
	switch c {
	case DiagnosticProviderConfig, DiagnosticProviderOpen, DiagnosticProviderRead, DiagnosticProviderClose:
		return true
	}
	return false
}

// The check opens and closes one session, so it needs a source the provider
// can really open.
func ValidateProviderContract(provider AcquisitionProvider, config AcquisitionConfig) error {
	if provider == nil {
		return fmt.Errorf("%w: no provider", ErrProviderContract)
	}
	name := provider.Name()
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrProviderContract)
	}
	session, err := provider.Open(config)
	if err != nil {
		return fmt.Errorf("memory: provider %s: open: %w", name, err)
	}
	if session == nil {
		return fmt.Errorf("%w: %s opened no session and gave no error", ErrProviderContract, name)
	}
	var problems []error
	if session.Reader() == nil {
		problems = append(problems, fmt.Errorf("%w: %s session has no reader", ErrProviderContract, name))
	}
	for _, d := range session.Diagnostics() {
		if !knownCategory(d.Category) {
			problems = append(problems, fmt.Errorf("%w: %s diagnostic category %q", ErrProviderContract, name, d.Category))
		}
		if d.Provider != name {
			problems = append(problems, fmt.Errorf("%w: %s diagnostic names provider %q", ErrProviderContract, name, d.Provider))
		}
	}
	if err := session.Close(); err != nil {
		problems = append(problems, fmt.Errorf("memory: provider %s: close: %w", name, err))
	}
	return errors.Join(problems...)
}

type providerSession struct {
	reader      MemoryReader
	closer      io.Closer
	diagnostics []AcquisitionDiagnostic
}

func (s *providerSession) Reader() MemoryReader { return s.reader }

func (s *providerSession) Close() error {
	if s.closer == nil {
		return nil
	}
	err := s.closer.Close()
	s.closer = nil
	return err
}

func (s *providerSession) Diagnostics() []AcquisitionDiagnostic {
	return append([]AcquisitionDiagnostic(nil), s.diagnostics...)
}
