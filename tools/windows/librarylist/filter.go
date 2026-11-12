package librarylist

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const (
	OptionBase       = "windows.library.list.base"
	OptionName       = "windows.library.list.name"
	OptionIgnoreCase = "windows.library.list.ignore_case"
	OptionOffset     = "windows.library.list.offset"
)

type filter struct {
	base       uint64
	mask       uint64
	pattern    *regexp.Regexp
	ignoreCase bool
}

func readFilter(ctx tools.Context) (filter, error) {
	base, err := modulelist.BaseOption(ctx, OptionBase)
	if err != nil {
		return filter{}, err
	}
	ignoreCase, err := ctx.BoolOption(OptionIgnoreCase)
	if err != nil {
		return filter{}, err
	}
	pattern, err := ctx.PatternOption(OptionName, ignoreCase)
	if err != nil {
		return filter{}, err
	}
	if ignoreCase && pattern == nil {
		ctx.AddDiagnostic("%s: %s is set without %s and changes nothing", Name, OptionIgnoreCase, OptionName)
	}
	return filter{base: base, mask: modulelist.AddressMask(ctx), pattern: pattern, ignoreCase: ignoreCase}, nil
}

// A row whose names did not read cannot be shown to match, so the name
// filter drops it and says how many it dropped that way.
func (f filter) keep(d DLL) (keep, unknown bool) {
	if f.base != 0 && !modulelist.IsBase(f.base, d.Base, f.mask) {
		return false, false
	}
	if f.pattern == nil {
		return true, false
	}
	if (!d.NameUnreadable && f.pattern.MatchString(d.Name)) || (!d.FullPathUnreadable && f.pattern.MatchString(d.FullPath)) {
		return true, false
	}
	return false, d.NameUnreadable || d.FullPathUnreadable
}

func (f filter) apply(ctx tools.Context, rows []DLL) []DLL {
	if f.base == 0 && f.pattern == nil {
		return rows
	}
	out := make([]DLL, 0, len(rows))
	unknown := 0
	for _, d := range rows {
		keep, unk := f.keep(d)
		if keep {
			out = append(out, d)
		}
		if unk {
			unknown++
		}
	}
	var by []string
	if f.base != 0 {
		by = append(by, fmt.Sprintf("%s 0x%x", OptionBase, f.base))
	}
	if f.pattern != nil {
		text := strings.TrimPrefix(f.pattern.String(), "(?i)")
		if f.ignoreCase {
			text += " (case ignored)"
		}
		by = append(by, fmt.Sprintf("%s %q", OptionName, text))
	}
	ctx.AddDiagnostic("%s: %s keep %d of %d libraries", Name, strings.Join(by, " and "), len(out), len(rows))
	if unknown > 0 {
		ctx.AddDiagnostic("%s: %s dropped %d libraries whose names did not read", Name, OptionName, unknown)
	}
	if f.base != 0 && len(out) > 0 {
		modulelist.NoteCanonicalBase(ctx, Name, OptionBase, f.base, f.mask)
	}
	return out
}
