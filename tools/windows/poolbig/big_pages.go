package poolbig

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

const Name = "windows.pool.list_big"

const (
	OptionTags     = "windows.pool.list_big.tags"
	OptionShowFree = "windows.pool.list_big.show_free"
	retiredTag     = "windows.pool.list_big.tag"
)

var ErrTagOptionRenamed = errors.New("poolbig: option \"" + retiredTag + "\" is now \"" + OptionTags +
	"\", a list of tags")

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "List the kernel's table of pool allocations of a page or more, which carry no pool " +
				"header: address, tag, size, page kind, and whether the slot was freed",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type tableRead struct {
	rows    []Allocation
	loc     tableLocation
	unused  int
	missing int
}

func readTable(ctx tools.Context) (tableRead, error) {
	layout, err := resolveEntryLayout(ctx.Symbols)
	if err != nil {
		return tableRead{}, err
	}
	loc, err := locateTable(ctx.Symbols, ctx.Memory, uint64(ctx.Bounds().MaxTableEntries))
	if err != nil {
		return tableRead{}, err
	}
	entries, gaps := readEntries(ctx.Memory, loc, layout)
	for _, g := range gaps {
		err := fmt.Errorf("%s: table entries at 0x%x (%d bytes): not readable: %w", Name, g.address, g.bytes, g.err)
		if ctx.StrictMode() {
			return tableRead{}, err
		}
		ctx.AddDiagnostic("%v", err)
	}
	d := decoder{layout: layout}
	if layout.poolType.present {
		d.typeNames = poolTypeNames(ctx.Symbols)
		if d.typeNames == nil {
			ctx.AddDiagnostic("%s: _POOL_TYPE names not in the symbol table; PoolType shown as numbers", Name)
		}
	}
	out := tableRead{loc: loc, missing: int(loc.slots) - len(entries)}
	for _, e := range entries {
		a, ok := d.allocation(e)
		if !ok {
			out.unused++
			continue
		}
		out.rows = append(out.rows, a)
	}
	return out, nil
}

func ReadTable(ctx tools.Context) ([]Allocation, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	t, err := readTable(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return t.rows, nil
}

func Run(ctx tools.Context) ([]Allocation, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	if _, set := ctx.Options[retiredTag]; set {
		return nil, ErrTagOptionRenamed
	}
	wanted, err := ctx.StringListOption(OptionTags)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	showFreed, err := ctx.BoolOption(OptionShowFree)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	for _, tag := range wanted {
		if !possibleTag(tag) {
			ctx.AddDiagnostic("%s: tag %q matches no entry: a tag is 1 to 4 characters from 0x20 to 0x7e", Name, tag)
		}
	}

	t, err := readTable(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	slices.SortFunc(t.rows, compareAllocations)
	inUse, freed := 0, 0
	out := make([]Allocation, 0, len(t.rows))
	for _, a := range t.rows {
		if a.Freed {
			freed++
		} else {
			inUse++
		}
		if a.Freed && !showFreed || len(wanted) > 0 && !tagWanted(a.Tag, wanted) {
			continue
		}
		out = append(out, a)
	}
	ctx.AddDiagnostic("%s: table at 0x%x has %d slots: %d in use, %d freed, %d never used, %d not readable",
		Name, t.loc.base, t.loc.slots, inUse, freed, t.unused, t.missing)
	if !showFreed && freed > 0 {
		ctx.AddDiagnostic("%s: %d freed slots not listed; set %s to list them", Name, freed, OptionShowFree)
	}
	if len(wanted) > 0 {
		ctx.AddDiagnostic("%s: %d rows carry the tags %q", Name, len(out), wanted)
	}
	return out, nil
}

func possibleTag(tag string) bool {
	if len(tag) == 0 || len(tag) > 4 {
		return false
	}
	for i := 0; i < len(tag); i++ {
		if tag[i] < 0x20 || tag[i] > 0x7e {
			return false
		}
	}
	return true
}

// The options trim spaces from each item, so a tag that ends in spaces, such
// as "Mdl ", also matches its trimmed form.
func tagWanted(tag string, wanted []string) bool {
	trimmed := strings.TrimRight(tag, " ")
	for _, w := range wanted {
		if w == tag || w == trimmed {
			return true
		}
	}
	return false
}
