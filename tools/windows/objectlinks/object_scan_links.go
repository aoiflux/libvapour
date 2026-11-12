package objectlinks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.object.scan_links"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find symbolic link objects by their pool allocations, freed ones included, with each link's target or callback",
		},
		RunAny,
	)
}

var (
	ErrNotWindows       = errors.New("objectlinks: profile is not windows")
	ErrNoPhysicalMemory = errors.New("objectlinks: no physical memory to scan")
	ErrNoLinkType       = errors.New("objectlinks: symbol table lacks an _OBJECT_SYMBOLIC_LINK member")
	ErrTargetInvalid    = errors.New("objectlinks: LinkTarget Length is odd or above MaximumLength")
	ErrTargetUnread     = errors.New("objectlinks: LinkTarget buffer does not read")
)

type Symlink struct {
	Offset               uint64
	VirtualOffset        uint64
	OtherCopy            uint64
	Name                 string
	Target               string
	NameUnreadable       bool
	TargetUnreadable     bool
	Callback             bool
	CallbackRoutine      uint64
	CallbackContext      uint64
	CallbackModule       string
	CallbackSymbol       string
	CallbackUnowned      bool
	CreateTime           time.Time
	CreateTimeUnreadable bool
	TypeIndexFailed      bool
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

// Measured: a link whose Flags has this bit holds a routine and its context
// where other links hold LinkTarget (S69 M6).
const callbackFlag = 0x10

type layout struct {
	size       uint64
	created    uint64
	hasCreated bool
	target     uint64
	flags      symbols.IntField
	callback   bool
	routine    uint64
	context    uint64
	headerBody uint64
	unicode    util.UnicodeStringLayout
	namer      scan.ObjectNamer
	width      uint8
}

func resolve(t symbols.SymbolTable) (layout, error) {
	var l layout
	st, err := t.Struct("_OBJECT_SYMBOLIC_LINK")
	if err != nil || st.Size == 0 {
		return l, fmt.Errorf("_OBJECT_SYMBOLIC_LINK: %w", ErrNoLinkType)
	}
	l.size = st.Size
	target, err := t.Field("_OBJECT_SYMBOLIC_LINK", "LinkTarget")
	if err != nil {
		return l, fmt.Errorf("_OBJECT_SYMBOLIC_LINK.LinkTarget: %w", ErrNoLinkType)
	}
	l.target = target.Offset
	body, err := t.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return l, fmt.Errorf("_OBJECT_HEADER.Body: %w", ErrNoLinkType)
	}
	l.headerBody = body.Offset
	if f, err := t.Field("_OBJECT_SYMBOLIC_LINK", "CreationTime"); err == nil {
		l.created, l.hasCreated = f.Offset, true
	}
	flags, errF := symbols.ResolveIntField(t, "_OBJECT_SYMBOLIC_LINK", "Flags")
	routine, errR := t.Field("_OBJECT_SYMBOLIC_LINK", "Callback")
	context, errC := t.Field("_OBJECT_SYMBOLIC_LINK", "CallbackContext")
	if errF == nil && errR == nil && errC == nil {
		l.flags, l.routine, l.context, l.callback = flags, routine.Offset, context.Offset, true
	}
	l.unicode = util.ResolveUnicodeStringLayout(t)
	l.width = t.PointerSize()
	return l, nil
}

func Run(ctx tools.Context) ([]Symlink, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysicalMemory)
	}
	l, err := resolve(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	namer, named := scan.NewObjectNamer(ctx.Symbols)
	if !named {
		return nil, fmt.Errorf("%s: object header name info: %w", Name, ErrNoLinkType)
	}
	l.namer = namer
	if !l.hasCreated {
		ctx.AddDiagnostic("%s: symbol table lacks _OBJECT_SYMBOLIC_LINK.CreationTime: every CreateTime is unreadable", Name)
	}
	objects, identity, err := ctx.ExecutiveScan(Name, scan.SymlinkFilter, scan.TypeTag{})
	if err != nil {
		return nil, err
	}
	kernel := ctx.Memory
	half := modulelist.KernelHalfStart(ctx)
	objects = objects.PreferringNamed(kernel)
	placed, stats, err := scan.FindExecutiveObjectsPlaced(physical, scan.SymlinkFilter, objects, identity,
		func(body uint64) (Symlink, bool) { return l.decode(physical, kernel, half, body) }, ctx.Bounds().Workers)
	if err != nil {
		return nil, fmt.Errorf("%s: pool tag %q: %w", Name, scan.SymlinkFilter.Tag, err)
	}
	out := make([]Symlink, len(placed))
	for i, p := range placed {
		s := p.Row
		s.Offset = p.Place.Body
		s.VirtualOffset = p.Place.BodyAddress()
		s.OtherCopy = p.OtherMappedBody()
		s.TypeIndexFailed = p.TypeIndexFailed
		out[i] = s
	}
	attribute(ctx, out)
	ctx.AddDiagnostic("%s: %d symbolic links from %d tag hits (%s)", Name, len(out), stats.TagHits, stats.Describe())
	return out, nil
}

// A body is a link's when its LinkTarget is either a callback routine in
// kernel space or a UNICODE_STRING whose lengths ntdef.h allows; a body with
// neither and no readable name says nothing a row could show.
func (l layout) decode(physical, kernel memory.MemoryReader, half, body uint64) (Symlink, bool) {
	raw, err := physical.ReadAt(body, l.size)
	if err != nil || uint64(len(raw)) != l.size {
		return Symlink{}, false
	}
	var s Symlink
	if l.callback {
		if flags, err := l.flags.Decode(raw); err == nil && flags&callbackFlag != 0 {
			s.CallbackRoutine = pointer(raw[l.routine:], l.width)
			if s.CallbackRoutine < half {
				return Symlink{}, false
			}
			s.Callback = true
			s.CallbackContext = pointer(raw[l.context:], l.width)
		}
	}
	if !s.Callback {
		target, err := readText(raw[l.target:], kernel, l.unicode, l.width)
		switch {
		case errors.Is(err, ErrTargetInvalid):
			return Symlink{}, false
		case err != nil || !plausibleTarget(target):
			s.TargetUnreadable = true
		default:
			s.Target = target
		}
	}
	if l.hasCreated {
		t, ok := util.FiletimeToTime(binary.LittleEndian.Uint64(raw[l.created:]))
		s.CreateTime, s.CreateTimeUnreadable = t, !ok
	} else {
		s.CreateTimeUnreadable = true
	}
	if body >= l.headerBody {
		name, present, readable := l.namer.ReadName(physical, kernel, kernel, body-l.headerBody)
		switch {
		case !present:
		case !readable || !plausibleName(name):
			s.NameUnreadable = true
		default:
			s.Name = name
		}
	}
	if s.TargetUnreadable && (s.NameUnreadable || s.Name == "") {
		return Symlink{}, false
	}
	return s, true
}

func attribute(ctx tools.Context, links []Symlink) {
	n := 0
	for _, l := range links {
		if l.Callback {
			n++
		}
	}
	if n == 0 {
		return
	}
	mods, err := modulelist.Run(ctx)
	if err != nil {
		ctx.AddDiagnostic("%s: %d callback links left without a module: kernel modules: %v", Name, n, err)
		return
	}
	at := modulelist.NewAttributor(ctx, modulelist.Placed(ctx, Name, mods))
	unowned := 0
	for i := range links {
		if !links[i].Callback {
			continue
		}
		names := at.At(links[i].CallbackRoutine)
		if len(names) == 0 {
			links[i].CallbackUnowned = true
			unowned++
			continue
		}
		links[i].CallbackModule, links[i].CallbackSymbol = names[0].Module, names[0].Symbol
	}
	if unowned > 0 {
		ctx.AddDiagnostic("%s: %d of %d callback links have a routine outside every loaded module", Name, unowned, n)
	}
}

func pointer(b []byte, width uint8) uint64 {
	if width == 4 {
		return uint64(binary.LittleEndian.Uint32(b))
	}
	return binary.LittleEndian.Uint64(b)
}

// UNICODE_STRING (ntdef.h, Learn): Length and MaximumLength count bytes of
// UTF-16 and Length is not above MaximumLength. The descriptor comes from the
// scanned body; the characters live at a kernel address.
func readText(raw []byte, kernel memory.MemoryReader, us util.UnicodeStringLayout, width uint8) (string, error) {
	length := uint64(binary.LittleEndian.Uint16(raw[us.LengthOffset:]))
	maximum := uint64(binary.LittleEndian.Uint16(raw[us.MaximumLengthOffset:]))
	buffer := pointer(raw[us.BufferOffset:], width)
	switch {
	case length%2 != 0 || length > maximum:
		return "", ErrTargetInvalid
	case length == 0:
		return "", nil
	case buffer == 0:
		return "", ErrTargetUnread
	}
	b, err := kernel.ReadAt(buffer, length)
	if err != nil || uint64(len(b)) != length {
		return "", ErrTargetUnread
	}
	return util.DecodeCountedUTF16LE(b), nil
}

func printable(s string) bool {
	if strings.ContainsRune(s, utf8.RuneError) {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 }) < 0
}

// A link's name is one component of the object namespace, so it holds no
// backslash (Learn, Object Names); its target is a path. Neither held a
// control character or an undecodable unit in any link the measured
// directories reach (S69 M5).
func plausibleName(name string) bool {
	return name != "" && !strings.ContainsRune(name, '\\') && printable(name)
}

func plausibleTarget(target string) bool { return printable(target) }

func Plausible(name, target string) bool {
	return plausibleName(name) && plausibleTarget(target)
}
