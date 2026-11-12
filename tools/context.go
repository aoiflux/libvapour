package tools

import (
	"errors"
	"fmt"
	"maps"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
)

var (
	ErrMissingMemoryReader     = errors.New("tools: no kernel memory")
	ErrMissingSymbolTable      = errors.New("tools: no symbol table")
	ErrMissingProfile          = errors.New("tools: no profile")
	ErrProcessSpaceUnavailable = errors.New("tools: process address space unavailable")
)

// Not safe for concurrent use: tools keep result caches in the shared Options
// map and AddDiagnostic appends without a lock. Use one context per
// goroutine; the readers may be shared.
type Context struct {
	Memory        memory.MemoryReader
	Symbols       symbols.SymbolTable
	Profile       profiles.Profile
	Options       map[string]any
	ProcessMemory func(directoryTableBase uint64) (memory.MemoryReader, error)
	LoadPDB       func(fp autoload.Fingerprint) (symbols.SymbolTable, error)
	Limits        limits.Limits

	running string
}

func (c Context) Validate() error {
	if c.Memory == nil {
		return ErrMissingMemoryReader
	}
	if _, err := c.Limits.Resolved(); err != nil {
		return err
	}
	if c.Symbols == nil {
		return ErrMissingSymbolTable
	}
	if c.Profile == nil {
		return ErrMissingProfile
	}
	return c.ValidateOptions()
}

// Validate reports limits that do not resolve; callers still need caps.
func (c Context) Bounds() limits.Limits { return c.Limits.Effective() }

func (c Context) Running() string { return c.running }

// Never the kernel reader once a factory exists: the kernel layer's root is
// the CR3 caught at acquisition, so its user half is some other process.
func (c Context) ProcessSpace(directoryTableBase uint64) (memory.MemoryReader, error) {
	if c.ProcessMemory == nil {
		return c.Memory, nil
	}
	r, err := c.ProcessMemory(directoryTableBase)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: root 0x%x: %w", ErrProcessSpaceUnavailable, directoryTableBase, err)
	case r == nil:
		return nil, fmt.Errorf("%w: root 0x%x: no reader", ErrProcessSpaceUnavailable, directoryTableBase)
	}
	return r, nil
}

func (c Context) AddDiagnostic(format string, args ...any) {
	sink, ok := c.Options[optionDiagnostics].(*[]string)
	if !ok || sink == nil {
		return
	}
	*sink = append(*sink, fmt.Sprintf(format, args...))
}

// An unreadable value counts as strict: stopping on a gap is the safer error.
func (c Context) StrictMode() bool {
	strict, err := c.BoolOption(optionStrict)
	return strict || err != nil
}

// For setup reads that must see every process, such as resolving a symbol
// that a chosen process would resolve differently or not at all.
func (c Context) WithoutPIDFilter() Context {
	if _, ok := c.Options[optionPID]; !ok {
		return c
	}
	c.Options = maps.Clone(c.Options)
	delete(c.Options, optionPID)
	return c
}

func (c Context) KernelFrames() (*layers.FrameMap, error) {
	physical := c.PhysicalMemory()
	if physical == nil {
		return nil, errors.New("tools: kernel frames: no physical memory")
	}
	root, ok := c.KernelDTB()
	if !ok {
		return nil, errors.New("tools: kernel frames: no kernel page-table root")
	}
	name := c.PagingMode()
	mode, ok := layers.PagingModeByName(name)
	if !ok {
		return nil, fmt.Errorf("tools: kernel frames: paging mode %q has no table walk", name)
	}
	return layers.MapFrames(physical, root, mode, c.Bounds())
}
