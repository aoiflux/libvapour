package libvapour

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
	toolprocesslist "github.com/aoiflux/libvapour/tools/any/processlist"
	// A program that imports only this package has always been able to run
	// windows.module.list through ExecuteAll; the import keeps it registered.
	_ "github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const (
	optionDiagnostics        = "diagnostics"
	optionStrict             = "strict"
	optionPID                = "pid"
	optionStartFlink         = "any.process.list.start_flink"
	optionProcessListSanity  = "any.process.list.sanity_filter"
	optionProcessListActive  = "any.process.list.active_only"
	optionProcessListCross   = "any.process.list.cross_checker"
	optionNetworkScanCorrupt = "windows.network.scan.include_corrupt"
)

type OpenConfig struct {
	SymbolsPath               string
	KernelCR3                 uint64
	Strict                    bool
	PID                       uint64
	CollectDiagnostics        bool
	ProcessListSanityFilter   bool
	ProcessListActiveOnly     bool
	ProcessListCrossCheckCSV  string
	ProcessListCrossCheck     []toolprocesslist.SnapshotProcess
	NetworkScanIncludeCorrupt bool
	OfflineOnly               bool
	PagefilePaths             []string
	Limits                    Limits
	SymbolLoad                autoload.LoadOptions
	ToolOptions               map[string]any
}

// Not safe for concurrent use: tools keep result caches in the context's
// options and append diagnostics without a lock. Open one session per
// goroutine.
type Session struct {
	capture memory.AcquisitionSession
	files   []io.Closer
	ctx     tools.Context
	notes   []string
}

type ToolExecution struct {
	Spec     tools.Spec
	Result   any
	Error    error
	Duration time.Duration
}

type ExecutionReport struct {
	Tools         []ToolExecution
	Diagnostics   []string
	TotalDuration time.Duration
}

func OpenMemory(imagePath string, osName string, cfg OpenConfig) (*Session, error) {
	switch strings.ToLower(strings.TrimSpace(osName)) {
	case "windows":
		return OpenWindowsMemory(imagePath, cfg)
	case "linux":
		return OpenLinuxMemory(imagePath, cfg)
	}
	return nil, fmt.Errorf("libvapour: operating system %q is not windows or linux", osName)
}

func AnalyzeMemory(imagePath string, osName string, cfg OpenConfig, toolNames []string) (ExecutionReport, error) {
	s, err := OpenMemory(imagePath, osName, cfg)
	if err != nil {
		return ExecutionReport{}, err
	}
	var report ExecutionReport
	if len(toolNames) == 0 {
		report = s.ExecuteAll()
	} else {
		report = s.ExecuteSelected(toolNames)
	}
	if err := s.Close(); err != nil {
		return report, fmt.Errorf("libvapour: close session: %w", err)
	}
	return report, nil
}

func (s *Session) Context() tools.Context { return s.ctx }

func (s *Session) Execute(name string) (any, error) { return tools.Execute(s.ctx, name) }

func (s *Session) ExecuteAll() ExecutionReport {
	return s.runEach(tools.List())
}

// A name the registry does not know still gets a row, carrying the
// registry's error, so the report has one row per name asked for.
func (s *Session) ExecuteSelected(names []string) ExecutionReport {
	specs := make([]tools.Spec, len(names))
	for i, name := range names {
		specs[i] = tools.Spec{Name: name}
		if t, err := tools.Get(name); err == nil {
			specs[i] = t.Spec
		}
	}
	return s.runEach(specs)
}

func (s *Session) runEach(specs []tools.Spec) ExecutionReport {
	start := time.Now()
	runs := make([]ToolExecution, 0, len(specs))
	for _, spec := range specs {
		began := time.Now()
		result, err := tools.Execute(s.ctx, spec.Name)
		runs = append(runs, ToolExecution{Spec: spec, Result: result, Error: err, Duration: time.Since(began)})
	}
	return ExecutionReport{Tools: runs, Diagnostics: s.Diagnostics(), TotalDuration: time.Since(start)}
}

func (s *Session) Diagnostics() []string {
	if sink := diagnosticSink(s.ctx.Options); sink != nil {
		return slices.Clone(*sink)
	}
	return slices.Clone(s.notes)
}

func (s *Session) Close() error {
	if s.capture == nil {
		return nil
	}
	err := errors.Join(s.capture.Close(), closeAll(s.files))
	s.capture, s.files = nil, nil
	return err
}

func diagnosticSink(options map[string]any) *[]string {
	sink, _ := options[optionDiagnostics].(*[]string)
	return sink
}

// The state of a session being opened; every failure closes what it holds.
type opening struct {
	cfg      OpenConfig
	bounds   Limits
	load     autoload.LoadOptions
	capture  memory.AcquisitionSession
	physical memory.MemoryReader
	files    []io.Closer
	notes    []string
}

func beginOpen(imagePath string, cfg OpenConfig) (*opening, error) {
	bounds, err := cfg.Limits.Resolved()
	if err != nil {
		return nil, fmt.Errorf("libvapour: open config: %w", err)
	}
	load := cfg.SymbolLoad
	load.OfflineOnly = load.OfflineOnly || cfg.OfflineOnly
	load.Limits = bounds
	if load.Read.MaxTableEntries == 0 {
		load.Read.MaxTableEntries = bounds.MaxTableEntries
	}
	if load, err = load.Resolved(); err != nil {
		return nil, fmt.Errorf("libvapour: open config: %w", err)
	}
	if err := validateToolOptions(cfg.ToolOptions); err != nil {
		return nil, fmt.Errorf("libvapour: open config: %w", err)
	}
	selector, err := memory.NewProviderSelector(memory.NewFileProvider())
	if err != nil {
		return nil, fmt.Errorf("libvapour: open capture %s: %w", imagePath, err)
	}
	capture, _, err := selector.Select([]string{"file"}, memory.AcquisitionConfig{Source: imagePath, Strict: cfg.Strict, Limits: bounds})
	if err != nil {
		return nil, fmt.Errorf("libvapour: open capture %s: %w", imagePath, err)
	}
	physical := capture.Reader()
	if physical == nil {
		return nil, errors.Join(fmt.Errorf("libvapour: open capture %s: the provider gave no reader", imagePath), capture.Close())
	}
	o := &opening{cfg: cfg, bounds: bounds, load: load, capture: capture, physical: physical}
	for _, d := range capture.Diagnostics() {
		o.notes = append(o.notes, d.Message)
	}
	return o, nil
}

func (o *opening) note(format string, args ...any) {
	o.notes = append(o.notes, fmt.Sprintf(format, args...))
}

func (o *opening) fail(err error) (*Session, error) {
	return nil, errors.Join(err, closeAll(o.files), o.capture.Close())
}

// Config fields are set after ToolOptions, so a field the caller set wins
// over the same key in the map.
func (o *opening) options() (map[string]any, error) {
	cfg := o.cfg
	options := maps.Clone(cfg.ToolOptions)
	if options == nil {
		options = map[string]any{}
	}
	if cfg.CollectDiagnostics {
		options[optionDiagnostics] = &[]string{}
	}
	if cfg.Strict {
		options[optionStrict] = true
	}
	if cfg.PID != 0 {
		options[optionPID] = cfg.PID
	}
	if cfg.ProcessListSanityFilter {
		options[optionProcessListSanity] = true
	}
	if cfg.ProcessListActiveOnly {
		options[optionProcessListActive] = true
	}
	rows := slices.Clone(cfg.ProcessListCrossCheck)
	if cfg.ProcessListCrossCheckCSV != "" {
		loaded, err := toolprocesslist.LoadSnapshotCSV(cfg.ProcessListCrossCheckCSV)
		if err != nil {
			return nil, fmt.Errorf("libvapour: process cross-check file %s: %w", cfg.ProcessListCrossCheckCSV, err)
		}
		rows = append(rows, loaded...)
	}
	if len(rows) > 0 {
		options[optionProcessListCross] = toolprocesslist.NewSnapshotCrossChecker(rows)
	}
	if cfg.NetworkScanIncludeCorrupt {
		options[optionNetworkScanCorrupt] = true
	}
	return options, nil
}

// A run of many tools would otherwise stop at each tool that reads a bad
// option; the open checks every key the shared readers and the session name.
func validateToolOptions(options map[string]any) error {
	ctx := tools.Context{Options: options}
	errs := []error{ctx.ValidateOptions()}
	for _, key := range []string{optionProcessListSanity, optionProcessListActive, optionNetworkScanCorrupt} {
		_, err := ctx.BoolOption(key)
		errs = append(errs, err)
	}
	_, _, err := ctx.UintOption(optionStartFlink)
	errs = append(errs, err)
	if v, ok := options[optionProcessListCross]; ok {
		if _, ok := v.(toolprocesslist.CrossChecker); !ok {
			errs = append(errs, fmt.Errorf("%w: %q is %T; want a processlist.CrossChecker", tools.ErrOptionType, optionProcessListCross, v))
		}
	}
	return errors.Join(errs...)
}

// The open notes go first into the diagnostics sink when there is one, so a
// run's diagnostics read in the order things happened.
func (o *opening) finish(ctx tools.Context) *Session {
	s := &Session{capture: o.capture, files: o.files, ctx: ctx}
	if sink := diagnosticSink(ctx.Options); sink != nil {
		*sink = append(*sink, o.notes...)
	} else {
		s.notes = o.notes
	}
	return s
}
