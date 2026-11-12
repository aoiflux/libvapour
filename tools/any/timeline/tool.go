package timeline

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

const Name = "any.timeline.list"

const (
	OptionToolFilter     = "any.timeline.list.tool_filter"
	OptionCreateBodyfile = "any.timeline.list.create_bodyfile"
	OptionRecordConfig   = "any.timeline.list.record_config"
)

const BodyfileName = "timeline.body"

var ownOptions = []string{OptionToolFilter, OptionCreateBodyfile, OptionRecordConfig}

var (
	ErrToolFilter   = errors.New("timeline: tool filter word matches no source")
	ErrRecordConfig = errors.New("timeline: recording the run configuration is not supported")
	ErrNoOutputDir  = errors.New("timeline: a body file needs " + tools.OptionOutputDir)
	ErrRowType      = errors.New("timeline: source returned rows of another type")
	ErrBodyTooLarge = errors.New("timeline: body file exceeds the artefact size limit")
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Gather the dated events of other tools' rows into one list in time order, optionally as a body file",
		},
		RunAny,
	)
}

type settings struct {
	words []string
	body  bool
}

func readSettings(ctx tools.Context) (settings, error) {
	var s settings
	var err error
	if s.words, err = ctx.StringListOption(OptionToolFilter); err != nil {
		return settings{}, fmt.Errorf("%s: %w", Name, err)
	}
	if s.body, err = ctx.BoolOption(OptionCreateBodyfile); err != nil {
		return settings{}, fmt.Errorf("%s: %w", Name, err)
	}
	record, err := ctx.BoolOption(OptionRecordConfig)
	if err != nil {
		return settings{}, fmt.Errorf("%s: %w", Name, err)
	}
	if record {
		return settings{}, fmt.Errorf("%s: %w", Name, ErrRecordConfig)
	}
	return s, nil
}

func profileOS(ctx tools.Context) (string, error) {
	osName := strings.ToLower(ctx.Profile.OS())
	if osName != "windows" && osName != "linux" {
		return "", fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	return osName, nil
}

func Collect(ctx tools.Context) (Result, error) {
	if err := ctx.Validate(); err != nil {
		return Result{}, err
	}
	s, err := readSettings(ctx)
	if err != nil {
		return Result{}, err
	}
	return collect(ctx, s)
}

func collect(ctx tools.Context, s settings) (Result, error) {
	osName, err := profileOS(ctx)
	if err != nil {
		return Result{}, err
	}
	chosen, err := choose(osName, s.words)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", Name, err)
	}
	if !ctx.PIDs().All() {
		ctx.AddDiagnostic("%s: pid option not applied: every source covers every process", Name)
	}
	return gather(ctx, chosen)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Entry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	s, err := readSettings(ctx)
	if err != nil {
		return nil, err
	}
	dir, haveDir := ctx.OutputDir()
	if s.body && !haveDir {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoOutputDir)
	}
	res, err := collect(ctx, s)
	if err != nil {
		return nil, err
	}
	if s.body {
		w, err := writeBody(dir, res.Entries, ctx.DumpLimit(), ctx.Bounds().NameAttempts)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		ctx.AddDiagnostic("%s: body file %s in %s: %d lines, %d entries not written: no seconds value after 1970",
			Name, w.name, dir, w.lines, w.skipped)
	}
	return res.Entries, nil
}
