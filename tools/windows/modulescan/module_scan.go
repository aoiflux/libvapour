package modulescan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.module.scan"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find kernel loader entries by their pool allocations, entries the module list no longer links included",
		},
		RunAny,
	)
}

const (
	OptionBase = "windows.module.scan.base"
	OptionName = "windows.module.scan.name"
)

var (
	ErrNoLoaderEntry    = errors.New("modulescan: symbol table describes no loader entry type with DllBase, SizeOfImage and BaseDllName")
	ErrNoPhysicalMemory = errors.New("modulescan: no physical memory to scan")
)

type Module struct {
	Offset         uint64
	VirtualOffset  uint64
	OtherCopy      uint64
	Base           uint64
	Size           uint64
	Name           string
	NameUnreadable bool
	Path           string
	PathUnreadable bool
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type layout struct {
	entrySize, base, size, name, path uint64
	hasPath                           bool
	unicode                           util.UnicodeStringLayout
	width                             uint8
	systemStart                       uint64
}

func resolve(t symbols.SymbolTable, entry string) (layout, error) {
	l := layout{unicode: util.ResolveUnicodeStringLayout(t), width: t.PointerSize()}
	st, err := t.Struct(entry)
	if err != nil || st.Size == 0 {
		return l, ErrNoLoaderEntry
	}
	l.entrySize = st.Size
	for _, m := range []struct {
		member string
		at     *uint64
	}{{"DllBase", &l.base}, {"SizeOfImage", &l.size}, {"BaseDllName", &l.name}} {
		f, err := t.Field(entry, m.member)
		if err != nil {
			return l, fmt.Errorf("%s.%s: %w", entry, m.member, ErrNoLoaderEntry)
		}
		*m.at = f.Offset
	}
	if f, err := t.Field(entry, "FullDllName"); err == nil {
		l.path, l.hasPath = f.Offset, true
	}
	return l, nil
}

func Run(ctx tools.Context) ([]Module, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	filter, err := modulelist.ReadFilter(ctx, OptionBase, OptionName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysicalMemory)
	}
	pool := scan.ModuleFilterFor(ctx.Symbols)
	l, err := resolve(ctx.Symbols, pool.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !l.hasPath {
		ctx.AddDiagnostic("%s: %s has no FullDllName: paths are not read", Name, pool.Body)
	}
	if l.systemStart, err = modulelist.KernelSpaceStart(ctx, Name); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	headers, err := ctx.StructureScan(Name, pool)
	if err != nil {
		return nil, err
	}
	kernel := ctx.Memory
	placed, stats, err := scan.FindFilteredStructsPlaced(physical, headers, []scan.PoolFilter{pool},
		func(_ scan.PoolFilter, body uint64, _ scan.PoolHeader) (Module, bool) {
			return l.decode(physical, kernel, body)
		}, ctx.Bounds().Workers)
	if err != nil {
		return nil, fmt.Errorf("%s: pool tag %q: %w", Name, pool.Tag, err)
	}
	out := make([]Module, 0, len(placed))
	unnamed := 0
	for _, p := range placed {
		m := p.Row
		if !filter.Keeps(m.Base, m.Name, m.NameUnreadable) {
			continue
		}
		if m.NameUnreadable {
			unnamed++
		}
		m.Offset = p.Place.Body
		m.VirtualOffset = p.Place.BodyAddress()
		m.OtherCopy = p.OtherMappedBody()
		out = append(out, m)
	}
	ctx.AddDiagnostic("%s: %d loader entries from %d tag hits", Name, len(placed), stats.TagHits)
	filter.Report(ctx, Name, len(out), len(placed), unnamed)
	return out, nil
}

// A loader entry maps an image into system space at a page boundary with a
// nonzero size in whole pages; every listed entry on every capture does
// (S55 M2, M3), so an allocation that does not is not a loader entry.
func (l layout) decode(physical, kernel memory.MemoryReader, body uint64) (Module, bool) {
	raw, err := physical.ReadAt(body, l.entrySize)
	if err != nil || uint64(len(raw)) != l.entrySize {
		return Module{}, false
	}
	m := Module{Base: pointer(raw[l.base:], l.width), Size: uint64(binary.LittleEndian.Uint32(raw[l.size:]))}
	if m.Base < l.systemStart || m.Base&0xFFF != 0 || m.Size == 0 || m.Size&0xFFF != 0 {
		return Module{}, false
	}
	name, err := readSplit(raw[l.name:], kernel, l.unicode, l.width)
	m.Name, m.NameUnreadable = name, err != nil
	if l.hasPath {
		path, err := readSplit(raw[l.path:], kernel, l.unicode, l.width)
		m.Path, m.PathUnreadable = path, err != nil
	} else {
		m.PathUnreadable = true
	}
	return m, true
}

func pointer(b []byte, width uint8) uint64 {
	if width == 4 {
		return uint64(binary.LittleEndian.Uint32(b))
	}
	return binary.LittleEndian.Uint64(b)
}

var errString = errors.New("modulescan: UNICODE_STRING does not read")

func readSplit(raw []byte, kernel memory.MemoryReader, us util.UnicodeStringLayout, width uint8) (string, error) {
	length := uint64(binary.LittleEndian.Uint16(raw[us.LengthOffset:]))
	maximum := uint64(binary.LittleEndian.Uint16(raw[us.MaximumLengthOffset:]))
	buffer := pointer(raw[us.BufferOffset:], width)
	switch {
	case length == 0:
		return "", nil
	case length%2 != 0 || length > maximum || buffer == 0:
		return "", errString
	}
	b, err := kernel.ReadAt(buffer, length)
	if err != nil || uint64(len(b)) != length {
		return "", errString
	}
	return util.CountedText(util.DecodeUTF16LE(b)), nil
}

// An unread or reused buffer decodes to replacement or control characters.
func PlausibleName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
