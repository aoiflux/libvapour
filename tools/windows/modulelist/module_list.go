package modulelist

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.module.list"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the loaded kernel modules: the loader's PsLoadedModuleList on Windows, the module list on Linux",
		},
		RunAny,
	)
}

var (
	ErrNoLoaderEntry = errors.New("modulelist: symbol table describes no loader entry type")
	ErrNoListHead    = errors.New("modulelist: symbol table has no PsLoadedModuleList")
	ErrUnsupportedOS = errors.New("modulelist: profile is neither windows nor linux")
)

// Path, not Name, is the file a module was loaded from: kdcom.dll is loaded
// from \SystemRoot\system32\kd.dll on every capture measured (S55 M4).
type Module struct {
	Base     uint64
	Size     uint64
	InitSize uint64
	Name     string
	Entry    uint64
	Path     string

	NameUnreadable     bool
	PathUnreadable     bool
	BaseUnreadable     bool
	SizeUnreadable     bool
	InitSizeUnreadable bool

	Regions         []Region
	SeparateRegions bool
}

type Region struct {
	Kind string
	Base uint64
	Size uint64
}

func RunAny(ctx tools.Context) (any, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	filter, err := ReadFilter(ctx, OptionBase, OptionName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if filter.Active() && !isOS(ctx, "windows") {
		return nil, fmt.Errorf("%s: %s, %s: %w", Name, OptionBase, OptionName, ErrFilterUnsupported)
	}
	mods, err := Run(ctx)
	if err != nil || !filter.Active() {
		return mods, err
	}
	kept := make([]Module, 0, len(mods))
	unnamed := 0
	for _, m := range mods {
		if !filter.Keeps(m.Base, m.Name, m.NameUnreadable) {
			continue
		}
		kept = append(kept, m)
		if m.NameUnreadable {
			unnamed++
		}
	}
	filter.Report(ctx, Name, len(kept), len(mods), unnamed)
	return kept, nil
}

func Run(ctx tools.Context) ([]Module, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	switch {
	case isOS(ctx, "windows"):
		return loadedModules(ctx)
	case isOS(ctx, "linux"):
		return linuxModules(ctx)
	}
	return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrUnsupportedOS)
}

func isOS(ctx tools.Context, os string) bool { return strings.EqualFold(ctx.Profile.OS(), os) }

type loaderLayout struct {
	typeName string
	links    uint64
	dllBase  uint64
	size     symbols.IntField
	baseName uint64
	fullName uint64
	hasFull  bool
	unicode  util.UnicodeStringLayout
}

// The kernel's own type comes first. The process loader type has the same
// offsets for these members in every kernel table measured (S55 T2), and
// some tables describe only it.
var loaderTypes = []string{"_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY"}

const sizeOfImageBytes = 4

func readLoaderLayout(table symbols.SymbolTable) (loaderLayout, error) {
	l := loaderLayout{unicode: util.ResolveUnicodeStringLayout(table)}
	for _, name := range loaderTypes {
		if f, err := table.Field(name, "InLoadOrderLinks"); err == nil {
			l.typeName, l.links = name, f.Offset
			break
		}
	}
	if l.typeName == "" {
		return loaderLayout{}, ErrNoLoaderEntry
	}
	member := func(name string) (uint64, error) {
		f, err := table.Field(l.typeName, name)
		if err != nil {
			return 0, fmt.Errorf("%s.%s: %w", l.typeName, name, err)
		}
		return f.Offset, nil
	}
	var err error
	if l.dllBase, err = member("DllBase"); err != nil {
		return loaderLayout{}, err
	}
	if l.baseName, err = member("BaseDllName"); err != nil {
		return loaderLayout{}, err
	}
	if l.size, err = symbols.ResolveIntField(table, l.typeName, "SizeOfImage"); err != nil {
		f, ferr := table.Field(l.typeName, "SizeOfImage")
		if ferr != nil {
			return loaderLayout{}, err
		}
		l.size = symbols.IntField{Offset: f.Offset, Width: sizeOfImageBytes}
	}
	l.fullName, err = member("FullDllName")
	l.hasFull = err == nil
	return l, nil
}

func loadedModules(ctx tools.Context) ([]Module, error) {
	layout, err := readLoaderLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !layout.hasFull {
		ctx.AddDiagnostic("%s: %s has no FullDllName: module paths are not read", Name, layout.typeName)
	}
	head, err := ctx.Symbols.LookupSymbol("PsLoadedModuleList")
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", Name, ErrNoListHead, err)
	}
	links, err := winkernel.NativeListLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walker := winkernel.ListWalker{
		Tool:   Name,
		Memory: ctx.Memory,
		Layout: links,
		Limit:  ctx.Bounds().MaxListEntries,
		Strict: ctx.StrictMode(),
		Report: ctx.AddDiagnostic,
	}
	walk, err := walker.WalkRecovering(head.Address, "PsLoadedModuleList")
	if err != nil {
		return nil, err
	}
	if walk.Backward > 0 {
		ctx.AddDiagnostic("%s: PsLoadedModuleList head at 0x%x: %d of %d modules were reached only through Blink",
			Name, head.Address, walk.Backward, len(walk.Entries))
	}
	space := newSystemSpace(ctx)
	mods := make([]Module, 0, len(walk.Entries))
	for _, link := range walk.Entries {
		entry, ok := winkernel.Container(link, layout.links)
		if !ok {
			ctx.AddDiagnostic("%s: PsLoadedModuleList link 0x%x lies below the %s offset 0x%x: entry skipped",
				Name, link, layout.typeName, layout.links)
			continue
		}
		m := readEntry(ctx, layout, entry)
		space.check(ctx, m)
		mods = append(mods, m)
	}
	return mods, nil
}

func readEntry(ctx tools.Context, l loaderLayout, entry uint64) Module {
	m := Module{Entry: entry}
	unread := func(member string, err error) {
		ctx.AddDiagnostic("%s: %s at 0x%x: %s does not read: %v", Name, l.typeName, entry, member, err)
	}
	var err error
	if m.Base, err = ctx.Symbols.ReadPointer(ctx.Memory, entry+l.dllBase); err != nil {
		m.Base, m.BaseUnreadable = 0, true
		unread("DllBase", err)
	}
	if m.Size, err = l.size.Read(ctx.Memory, entry); err != nil {
		m.Size, m.SizeUnreadable = 0, true
		unread("SizeOfImage", err)
	}
	m.Name, m.NameUnreadable = readText(ctx, entry+l.baseName, l.unicode)
	m.PathUnreadable = true
	if l.hasFull {
		m.Path, m.PathUnreadable = readText(ctx, entry+l.fullName, l.unicode)
	}
	return m
}

func readText(ctx tools.Context, at uint64, layout util.UnicodeStringLayout) (string, bool) {
	s, err := util.ReadUnicodeString(ctx.Memory, at, layout, 0)
	if err != nil {
		return "", true
	}
	return s.Text(), false
}
