package filedump

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/handlelist"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const (
	OptionVirtAddr   = "windows.file.dump.virtaddr"
	OptionPhysAddr   = "windows.file.dump.physaddr"
	OptionFilter     = "windows.file.dump.filter"
	OptionIgnoreCase = "windows.file.dump.ignore_case"
)

var (
	ErrFilterWithAddress      = errors.New("filedump: a filter and an address are mutually exclusive")
	ErrNoPhysicalMemory       = errors.New("filedump: a physical address needs a physical memory layer")
	ErrFilterNeedsDeviceNames = errors.New("filedump: the filter matches device-prefixed names, and these " +
		"symbols cannot read device object names")
	ErrEmptyAddressList = errors.New("filedump: an address option names no address")
)

// selection is what the options ask for: given file objects, or every file
// object the processes reach, kept by name when a filter is set.
type selection struct {
	virtual, physical []uint64
	pattern           *regexp.Regexp
	ignoreCase        bool
}

func (s selection) addressed() bool { return len(s.virtual) > 0 || len(s.physical) > 0 }

func readSelection(ctx tools.Context) (selection, error) {
	var s selection
	var err error
	if s.virtual, err = addresses(ctx, OptionVirtAddr); err != nil {
		return selection{}, err
	}
	if s.physical, err = addresses(ctx, OptionPhysAddr); err != nil {
		return selection{}, err
	}
	if s.ignoreCase, err = ctx.BoolOption(OptionIgnoreCase); err != nil {
		return selection{}, err
	}
	if s.pattern, err = ctx.PatternOption(OptionFilter, s.ignoreCase); err != nil {
		return selection{}, err
	}
	switch {
	case s.pattern != nil && len(s.virtual) > 0:
		return selection{}, fmt.Errorf("%s: %s with %s: %w", Name, OptionFilter, OptionVirtAddr, ErrFilterWithAddress)
	case s.pattern != nil && len(s.physical) > 0:
		return selection{}, fmt.Errorf("%s: %s with %s: %w", Name, OptionFilter, OptionPhysAddr, ErrFilterWithAddress)
	case len(s.physical) > 0 && ctx.PhysicalMemory() == nil:
		return selection{}, fmt.Errorf("%s: %s: %w", Name, OptionPhysAddr, ErrNoPhysicalMemory)
	}
	if s.ignoreCase && s.pattern == nil {
		ctx.AddDiagnostic("%s: %s does nothing without %s", Name, OptionIgnoreCase, OptionFilter)
	}
	if s.addressed() && !ctx.PIDs().All() {
		ctx.AddDiagnostic("%s: pid is not applied: given addresses are carved without walking processes", Name)
	}
	return s, nil
}

// A key that is set must name an address: an empty list read as "unset"
// would carve every file object instead of none.
func addresses(ctx tools.Context, key string) ([]uint64, error) {
	list, err := ctx.UintListOption(key)
	if err != nil {
		return nil, err
	}
	if _, set := ctx.Options[key]; set && len(list) == 0 {
		return nil, fmt.Errorf("option %q: %w: %w", key, tools.ErrOptionType, ErrEmptyAddressList)
	}
	return list, nil
}

type ownerKey struct {
	address  uint64
	physical bool
}

type translator interface {
	Translate(virtualAddress uint64) (uint64, error)
}

// Each file object is carved once however often it is given: repeats, and a
// physical address the kernel maps at a given virtual address, are dropped.
func (s selection) owners(ctx tools.Context) []fileOwner {
	var out []fileOwner
	first := map[ownerKey]uint64{}
	keep := func(key string, given uint64, o fileOwner) {
		k := ownerKey{address: o.fileObject, physical: o.physical}
		if earlier, dup := first[k]; dup {
			ctx.AddDiagnostic("%s: %s 0x%x names file object 0x%x again (given first as 0x%x): carved once",
				Name, key, given, o.fileObject, earlier)
			return
		}
		first[k] = given
		out = append(out, o)
	}

	mask := modulelist.AddressMask(ctx)
	for _, v := range s.virtual {
		canonical := modulelist.CanonicalAddress(v, mask, ctx.Symbols.PointerSize())
		if v != canonical && v != v&mask {
			ctx.AddDiagnostic("%s: %s 0x%x is read as 0x%x: the paging mode translates %d address bits",
				Name, OptionVirtAddr, v, canonical, modulelist.AddressBits(mask))
		}
		keep(OptionVirtAddr, v, fileOwner{fileObject: canonical, addressed: true})
	}
	if len(s.physical) == 0 {
		return out
	}

	mapped := map[uint64]uint64{}
	if tr, ok := ctx.Memory.(translator); ok {
		for _, o := range out {
			if pa, err := tr.Translate(o.fileObject); err == nil {
				if _, seen := mapped[pa]; !seen {
					mapped[pa] = o.fileObject
				}
			}
		}
	} else if len(out) > 0 {
		ctx.AddDiagnostic("%s: kernel memory does not translate addresses: a %s and a %s of one file object are "+
			"both carved", Name, OptionVirtAddr, OptionPhysAddr)
	}
	end := ctx.PhysicalMemory().Size()
	for _, p := range s.physical {
		if va, ok := mapped[p]; ok {
			ctx.AddDiagnostic("%s: %s 0x%x is where %s 0x%x lies: carved once, through the virtual address",
				Name, OptionPhysAddr, p, OptionVirtAddr, va)
			continue
		}
		if p >= end {
			ctx.AddDiagnostic("%s: %s 0x%x lies past the end of physical memory at 0x%x: nothing read",
				Name, OptionPhysAddr, p, end)
			continue
		}
		keep(OptionPhysAddr, p, fileOwner{fileObject: p, physical: true, addressed: true})
	}
	return out
}

// The filter sees the name windows.handle.list shows for the file object, so
// what an examiner read there is what the filter matches. The filter never
// runs with given addresses, so the object is read through kernel memory. A
// relative name lost the file it was relative to (S30 4.2) and is not matched.
func fullName(ctx tools.Context, _ fields, _ *scan.ObjectNamer, _ memory.MemoryReader, fileObject uint64) (string, bool) {
	name, ok := handlelist.FileObjectName(ctx, fileObject)
	if !ok || !strings.HasPrefix(name, `\`) {
		return "", false
	}
	return name, true
}

type filterTally struct {
	tested, kept, unnamed int
}

func (s selection) reportFilter(ctx tools.Context, t filterTally) {
	if s.pattern == nil {
		return
	}
	text, how := s.pattern.String(), ""
	if s.ignoreCase {
		text, how = strings.TrimPrefix(text, "(?i)"), ", ignoring case"
	}
	ctx.AddDiagnostic("%s: %s %q%s keeps %d of %d file objects", Name, OptionFilter, text, how, t.kept, t.tested)
	if t.unnamed > 0 {
		ctx.AddDiagnostic("%s: %s leaves out %d file objects whose name does not read as a full device path", Name, OptionFilter,
			t.unnamed)
	}
}
