package pesymbols

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

const Name = "windows.pe.resolve_symbols"

const (
	OptionModule     = "windows.pe.resolve_symbols.module"
	OptionSymbols    = "windows.pe.resolve_symbols.symbols"
	OptionAddresses  = "windows.pe.resolve_symbols.addresses"
	OptionSource     = "windows.pe.resolve_symbols.source"
	OptionLoaderList = "windows.pe.resolve_symbols.loader_list"
)

const (
	SourceProcesses = "processes"
	SourceKernel    = "kernel"
)

const KernelModuleName = "ntoskrnl.exe"

var (
	ErrNotWindows         = errors.New("pesymbols: profile is not windows")
	ErrNoModuleRequested  = errors.New("pesymbols: no module named")
	ErrNoSymbolsRequested = errors.New("pesymbols: no symbol names or addresses given")
	ErrNamesAndAddresses  = errors.New("pesymbols: both symbol names and addresses given")
	ErrUnknownSource      = errors.New("pesymbols: source is neither processes nor kernel")
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Resolve symbol names to addresses, or addresses to names, in a module mapped in process or kernel memory, from its PDB or its export directory (needs the module option and the symbols or addresses option)",
		},
		RunAny,
	)
}

type Module struct {
	PID                uint64
	ProcessName        string
	DirectoryTableBase uint64
	Name               string
	Base               uint64
	Size               uint64
}

type Symbol struct {
	Module     string
	Name       string
	Address    uint64
	FoundInPID uint64
	Forwarder  string
	// Address lies in the export directory, so it is a forwarder whose
	// string did not read, not code.
	ForwarderUnreadable bool
}

type Result struct {
	Module           string
	Source           string
	Symbols          []Symbol
	Missing          []string
	MissingAddresses []uint64
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) (Result, error) {
	if err := ctx.Validate(); err != nil {
		return Result{}, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return Result{}, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	req, err := readRequest(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", Name, err)
	}
	out := Result{Module: req.module, Source: req.source}
	if len(req.names) > 0 {
		found, missing, err := Resolve(ctx, req.source, map[string][]string{req.module: req.names})
		if err != nil {
			return Result{}, fmt.Errorf("%s: %w", Name, err)
		}
		out.Symbols, out.Missing = found[req.module], missing[req.module]
		return out, nil
	}
	found, missing, err := ResolveAddresses(ctx, req.source, map[string][]uint64{req.module: req.addresses})
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", Name, err)
	}
	out.Symbols, out.MissingAddresses = found[req.module], missing[req.module]
	return out, nil
}

type request struct {
	module    string
	source    string
	names     []string
	addresses []uint64
}

func readRequest(ctx tools.Context) (request, error) {
	var r request
	module, err := ctx.StringOption(OptionModule)
	if err != nil {
		return r, err
	}
	if r.module = moduleKey(module); r.module == "" {
		return r, ErrNoModuleRequested
	}
	if r.names, err = ctx.StringListOption(OptionSymbols); err != nil {
		return r, err
	}
	if r.addresses, err = ctx.UintListOption(OptionAddresses); err != nil {
		return r, err
	}
	switch {
	case len(r.names) == 0 && len(r.addresses) == 0:
		return r, ErrNoSymbolsRequested
	case len(r.names) > 0 && len(r.addresses) > 0:
		return r, ErrNamesAndAddresses
	}
	if r.source, err = ctx.StringOption(OptionSource); err != nil {
		return r, err
	}
	switch r.source {
	case "":
		r.source = SourceProcesses
	case SourceProcesses, SourceKernel:
	default:
		return r, fmt.Errorf("%q: %w", r.source, ErrUnknownSource)
	}
	return r, nil
}

// Windows file names compare without case, so module keys are folded once
// here and every source is matched against the folded form.
func moduleKey(name string) string { return strings.ToLower(strings.TrimSpace(name)) }
