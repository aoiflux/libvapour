package modulelist

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/tools"
)

const (
	OptionBase = "windows.module.list.base"
	OptionName = "windows.module.list.name"
)

var ErrFilterUnsupported = errors.New("modulelist: the base and name options apply to a windows profile only")

type Filter struct {
	baseKey, nameKey string
	base             uint64
	name             string
	mask             uint64
}

// A name decoded from UTF-16 is always valid UTF-8, so text that is not can
// match no name, only bytes inside one.
func ReadFilter(ctx tools.Context, baseKey, nameKey string) (Filter, error) {
	base, err := BaseOption(ctx, baseKey)
	if err != nil {
		return Filter{}, err
	}
	name, err := ctx.StringOption(nameKey)
	if err != nil {
		return Filter{}, err
	}
	if !utf8.ValidString(name) {
		return Filter{}, fmt.Errorf("option %q: %w: the text is not UTF-8", nameKey, tools.ErrOptionType)
	}
	return Filter{baseKey: baseKey, nameKey: nameKey, base: base, name: name, mask: AddressMask(ctx)}, nil
}

func (f Filter) Active() bool { return f.base != 0 || f.name != "" }

// An unreadable name is kept under a name filter: a read failure must not
// hide the module the examiner asked for.
func (f Filter) Keeps(base uint64, name string, nameUnreadable bool) bool {
	if f.base != 0 && !IsBase(f.base, base, f.mask) {
		return false
	}
	return f.name == "" || nameUnreadable || strings.Contains(upcase(name), upcase(f.name))
}

// Windows compares file names without case, upcasing one UTF-16 unit at a
// time, so a character outside the Basic Multilingual Plane keeps its case.
func upcase(s string) string {
	return strings.Map(func(r rune) rune {
		if r > 0xffff {
			return r
		}
		return unicode.ToUpper(r)
	}, s)
}

func (f Filter) Report(ctx tools.Context, tool string, listed, total, unnamed int) {
	if !f.Active() {
		return
	}
	var by []string
	if f.base != 0 {
		by = append(by, fmt.Sprintf("%s 0x%x", f.baseKey, f.base))
	}
	if f.name != "" {
		by = append(by, fmt.Sprintf("%s %q", f.nameKey, f.name))
	}
	ctx.AddDiagnostic("%s: %s keep %d of %d modules", tool, strings.Join(by, " and "), listed, total)
	if f.name != "" && unnamed > 0 {
		ctx.AddDiagnostic("%s: %d of them are kept because BaseDllName does not read, whatever %s says", tool, unnamed, f.nameKey)
	}
	if f.base != 0 && listed > 0 {
		NoteCanonicalBase(ctx, tool, f.baseKey, f.base, f.mask)
	}
}

func BaseOption(ctx tools.Context, key string) (uint64, error) {
	base, set, err := ctx.UintOption(key)
	if err != nil {
		return 0, err
	}
	if set && base == 0 {
		ctx.AddDiagnostic("%s: 0 names no base: the option filters nothing", key)
	}
	return base, nil
}

// Paging ignores the bits above the mask, so the examiner may give a base in
// its sign-extended form or with those bits cleared; both name one module.
func IsBase(want, base, mask uint64) bool { return want == base || want == base&mask }

func NoteCanonicalBase(ctx tools.Context, tool, key string, want, mask uint64) {
	if want&mask == want {
		return
	}
	ctx.AddDiagnostic("%s: %s 0x%x is a sign-extended base; its masked form 0x%x names the same module", tool, key, want, want&mask)
}
