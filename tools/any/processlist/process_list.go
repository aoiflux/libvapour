package processlist

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

const Name = "any.process.list"

const (
	optionStartFlink       = "any.process.list.start_flink"
	optionSanityFilter     = "any.process.list.sanity_filter"
	optionActiveOnlyFilter = "any.process.list.active_only"
	optionCrossChecker     = "any.process.list.cross_checker"
	optionResultCache      = "any.process.list.result_cache"
)

var (
	ErrNoListMember = errors.New("processlist: symbol table lacks a member the process list needs")
	ErrNoListHead   = errors.New("processlist: PsActiveProcessHead does not resolve and no start entry is set")
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Walk the kernel's active process list",
		},
		RunAny,
	)
}

type Process struct {
	PID                uint64
	Name               string
	EPROCESS           uint64
	DirectoryTableBase uint64

	Columns

	Linux LinuxColumns
}

type Listing struct {
	Processes []Process
	Closed    bool
}

type optionalField struct {
	offset  uint64
	present bool
}

func RunAny(ctx tools.Context) (any, error) {
	rows, err := Run(ctx)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(ctx.Profile.OS(), "linux") {
		return linuxTool(ctx, rows)
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return rows, nil
	}
	pids := ctx.PIDs()
	columns := NewColumnReader(ctx)
	columns.ReportAbsent(ctx, Name)
	kept := make([]Process, 0, len(rows))
	for _, p := range rows {
		if !pids.Keep(p.PID) {
			continue
		}
		if err := columns.ReportUnread(ctx, Name, p.PID, p.Name, p.EPROCESS, p.Columns); err != nil {
			return nil, err
		}
		kept = append(kept, p)
	}
	return kept, nil
}

func Run(ctx tools.Context) ([]Process, error) {
	l, err := RunListing(ctx)
	if err != nil {
		return nil, err
	}
	return l.Processes, nil
}

func RunListing(ctx tools.Context) (Listing, error) {
	if err := ctx.Validate(); err != nil {
		return Listing{}, err
	}
	opts, err := readOptions(ctx)
	if err != nil {
		return Listing{}, fmt.Errorf("%s: %w", Name, err)
	}
	if cached, ok := cachedListing(ctx); ok {
		return cached, nil
	}
	var l Listing
	switch {
	case strings.EqualFold(ctx.Profile.OS(), "windows"):
		l, err = runWindows(ctx, opts)
	case strings.EqualFold(ctx.Profile.OS(), "linux"):
		l.Processes, err = runLinux(ctx, opts)
		l.Closed = true
	default:
		return Listing{}, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	if err != nil {
		return Listing{}, err
	}
	keepListing(ctx, l)
	return copyListing(l), nil
}

// The Linux walk applies the PID set itself, so a narrowed listing must not
// answer a request with another set.
type cacheEntry struct {
	pids    string
	listing Listing
}

func cacheKey(ctx tools.Context) string {
	if strings.EqualFold(ctx.Profile.OS(), "linux") {
		return ctx.PIDs().Key()
	}
	return ""
}

func cachedListing(ctx tools.Context) (Listing, bool) {
	if ctx.Options == nil {
		return Listing{}, false
	}
	e, ok := ctx.Options[optionResultCache].(cacheEntry)
	if !ok || e.pids != cacheKey(ctx) {
		return Listing{}, false
	}
	return copyListing(e.listing), true
}

func keepListing(ctx tools.Context, l Listing) {
	if ctx.Options == nil {
		return
	}
	ctx.Options[optionResultCache] = cacheEntry{pids: cacheKey(ctx), listing: copyListing(l)}
}

func copyListing(l Listing) Listing {
	return Listing{Processes: append([]Process(nil), l.Processes...), Closed: l.Closed}
}

type runOptions struct {
	startFlink    uint64
	startFlinkSet bool
	sanity        bool
	activeOnly    bool
	crossChecker  CrossChecker
}

func readOptions(ctx tools.Context) (runOptions, error) {
	var o runOptions
	var err error
	if o.startFlink, o.startFlinkSet, err = ctx.UintOption(optionStartFlink); err != nil {
		return runOptions{}, err
	}
	if o.sanity, err = ctx.BoolOption(optionSanityFilter); err != nil {
		return runOptions{}, err
	}
	if o.activeOnly, err = ctx.BoolOption(optionActiveOnlyFilter); err != nil {
		return runOptions{}, err
	}
	if v, ok := ctx.Options[optionCrossChecker]; ok {
		checker, ok := v.(CrossChecker)
		if !ok {
			return runOptions{}, fmt.Errorf("option %q: %w: %T, want processlist.CrossChecker", optionCrossChecker, tools.ErrOptionType, v)
		}
		o.crossChecker = checker
	}
	return o, nil
}

func lookupOptionalField(ctx tools.Context, typeName string, fieldName string) optionalField {
	f, err := ctx.Symbols.Field(typeName, fieldName)
	if err != nil {
		return optionalField{}
	}
	return optionalField{offset: f.Offset, present: true}
}

func lookupNestedOptionalField(ctx tools.Context, parentType, parentField, childType, childField string) optionalField {
	parent := lookupOptionalField(ctx, parentType, parentField)
	child := lookupOptionalField(ctx, childType, childField)
	if !parent.present || !child.present {
		return optionalField{}
	}
	return optionalField{offset: parent.offset + child.offset, present: true}
}
