package memory

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrProviderConfig = errors.New("memory: provider configuration unusable")
	ErrStrictRepair   = errors.New("memory: strict mode refuses a container that needed a repair")
)

const (
	fileProviderName   = "file"
	readerProviderName = "reader"
	liveProviderName   = "live"
	optionLiveReader   = "live_reader"
)

type containerNoter interface {
	containerNotes() []string
	containerRepairs() []string
}

type fileProvider struct{}

func NewFileProvider() AcquisitionProvider { return fileProvider{} }

func (fileProvider) Name() string { return fileProviderName }

func (fileProvider) Open(config AcquisitionConfig) (AcquisitionSession, error) {
	if config.Source == "" {
		return nil, fmt.Errorf("%w: %s provider needs a source path", ErrProviderConfig, fileProviderName)
	}
	file, err := NewFileMemoryReader(config.Source)
	if err != nil {
		return nil, err
	}
	reader, format, err := DetectFormat(file, Detectors(config.Limits)...)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("memory: open %s: %w", config.Source, err)
	}
	if n, ok := reader.(containerNoter); ok && config.Strict {
		if repairs := n.containerRepairs(); len(repairs) > 0 {
			_ = file.Close()
			return nil, fmt.Errorf("memory: open %s: %w: %s", config.Source, ErrStrictRepair, strings.Join(repairs, "; "))
		}
	}
	s := &providerSession{reader: reader, closer: file}
	s.diagnostics = append(s.diagnostics, AcquisitionDiagnostic{Category: DiagnosticProviderOpen, Provider: fileProviderName,
		Message: fmt.Sprintf("memory: %s opened as %s, 0x%x bytes of address space", config.Source, format, reader.Size())})
	if n, ok := reader.(containerNoter); ok {
		for _, note := range n.containerNotes() {
			s.diagnostics = append(s.diagnostics, AcquisitionDiagnostic{Category: DiagnosticProviderRead, Provider: fileProviderName,
				Message: "memory: " + note})
		}
	}
	return s, nil
}

type readerProvider struct{ reader MemoryReader }

func NewReaderProvider(reader MemoryReader) AcquisitionProvider {
	return readerProvider{reader: reader}
}

func (readerProvider) Name() string { return readerProviderName }

// The caller keeps ownership of the reader, so closing the session leaves
// it open.
func (p readerProvider) Open(AcquisitionConfig) (AcquisitionSession, error) {
	if p.reader == nil {
		return nil, fmt.Errorf("%w: %s provider was given no reader", ErrProviderConfig, readerProviderName)
	}
	return &providerSession{reader: p.reader}, nil
}

type liveProvider struct{}

// Deprecated: it captures no live memory; it serves the reader passed in
// the "live_reader" option. Use NewReaderProvider.
func NewLiveProvider() AcquisitionProvider { return liveProvider{} }

func (liveProvider) Name() string { return liveProviderName }

func (liveProvider) Open(config AcquisitionConfig) (AcquisitionSession, error) {
	raw, ok := config.Options[optionLiveReader]
	if !ok {
		return nil, fmt.Errorf("%w: %s provider needs option %s", ErrProviderConfig, liveProviderName, optionLiveReader)
	}
	reader, ok := raw.(MemoryReader)
	if !ok || reader == nil {
		return nil, fmt.Errorf("%w: option %s is %T, not a memory reader", ErrProviderConfig, optionLiveReader, raw)
	}
	return &providerSession{reader: reader}, nil
}
