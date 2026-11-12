package timeline

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
)

type source struct {
	tool      string
	os        string
	overrides map[string]any
	read      func(tools.Context, *recorder) error
}

type object struct {
	subject  string
	address  uint64
	physical uint64
}

type recorder struct {
	summary SourceSummary
	entries []Entry
}

func (r *recorder) row() { r.summary.Rows++ }

func (r *recorder) stamp(o object, ev Event, field string, t time.Time, present bool) {
	if !present || t.IsZero() {
		r.summary.Absent++
		return
	}
	t = t.UTC()
	if BeforeEpoch(t) {
		r.summary.BeforeEpoch++
	}
	r.summary.Entries++
	r.entries = append(r.entries, Entry{
		Time: t, Event: ev, Tool: r.summary.Tool, Field: field,
		Subject: o.subject, Address: o.address, Physical: o.physical,
	})
}

func rowsOf[T any](each func(*recorder, T)) func(tools.Context, *recorder) error {
	return func(ctx tools.Context, r *recorder) error {
		res, err := tools.Execute(ctx, r.summary.Tool)
		rows, ok := res.([]T)
		if res != nil && !ok {
			var want []T
			return fmt.Errorf("%w: %T, want %T", ErrRowType, res, want)
		}
		for _, row := range rows {
			r.row()
			each(r, row)
		}
		return err
	}
}

func osSources(osName string) []source {
	var out []source
	for _, s := range catalogue {
		if s.os == osName {
			out = append(out, s)
		}
	}
	return out
}

func Sources(osName string) []string {
	var out []string
	for _, s := range osSources(strings.ToLower(osName)) {
		out = append(out, s.tool)
	}
	return out
}

func choose(osName string, words []string) ([]source, error) {
	all := osSources(osName)
	if len(words) == 0 {
		return all, nil
	}
	for _, w := range words {
		if w == "" || !slices.ContainsFunc(all, func(s source) bool { return strings.Contains(s.tool, w) }) {
			return nil, fmt.Errorf("%w: %q (%s sources: %s)", ErrToolFilter, w, osName, strings.Join(Sources(osName), ", "))
		}
	}
	var out []source
	for _, s := range all {
		if slices.ContainsFunc(words, func(w string) bool { return strings.Contains(s.tool, w) }) {
			out = append(out, s)
		}
	}
	return out, nil
}

// Every source sees every process and none of the timeline's own options;
// all other options, caches included, are shared so that a tool run by two
// sources walks once.
func sourceContext(ctx tools.Context) tools.Context {
	sub := ctx.WithoutPIDFilter()
	options := make(map[string]any, len(sub.Options))
	for k, v := range sub.Options {
		options[k] = v
	}
	for _, k := range ownOptions {
		delete(options, k)
	}
	sub.Options = options
	return sub
}

func withOverrides(ctx tools.Context, overrides map[string]any) tools.Context {
	if len(overrides) == 0 {
		return ctx
	}
	options := make(map[string]any, len(ctx.Options)+len(overrides))
	for k, v := range ctx.Options {
		options[k] = v
	}
	for k, v := range overrides {
		options[k] = v
	}
	ctx.Options = options
	return ctx
}

func gather(ctx tools.Context, chosen []source) (Result, error) {
	sub := sourceContext(ctx)
	var res Result
	for _, s := range chosen {
		r := recorder{summary: SourceSummary{Tool: s.tool}}
		start := time.Now()
		err := s.read(withOverrides(sub, s.overrides), &r)
		r.summary.Elapsed = time.Since(start)
		if err != nil {
			r.summary.Failure = err
			if ctx.StrictMode() {
				return Result{}, fmt.Errorf("%s: source %s: run failed: %w", Name, s.tool, err)
			}
			ctx.AddDiagnostic("%s: source %s: run failed, %d rows kept: %v", Name, s.tool, r.summary.Rows, err)
		}
		res.Entries = append(res.Entries, r.entries...)
		res.Sources = append(res.Sources, r.summary)
	}
	Sort(res.Entries)
	return res, nil
}
