package driverscan

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
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.driver.scan"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find driver objects by their pool allocations, unlinked ones included, with their image range and names",
		},
		RunAny,
	)
}

var (
	ErrNoDriverType     = errors.New("driverscan: symbol table lacks a _DRIVER_OBJECT or _DRIVER_EXTENSION member")
	ErrNoPhysicalMemory = errors.New("driverscan: no physical memory to scan")
	ErrStringUnread     = errors.New("driverscan: UNICODE_STRING does not read")
	ErrStringInvalid    = errors.New("driverscan: UNICODE_STRING Length is odd or above MaximumLength")
)

type Driver struct {
	Offset               uint64
	VirtualOffset        uint64
	OtherCopy            uint64
	Start                uint64
	Size                 uint64
	Name                 string
	NameUnreadable       bool
	ServiceKey           string
	ServiceKeyUnreadable bool
	ObjectName           string
	ObjectNameUnreadable bool
	TypeIndexFailed      bool
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type layout struct {
	size, objectSize                   uint64
	start, driverSize, name, extension uint64
	serviceKey                         uint64
	headerBody                         uint64
	unicode                            util.UnicodeStringLayout
	namer                              scan.ObjectNamer
	named                              bool
	maxName                            uint64
}

func resolve(t symbols.SymbolTable) (layout, error) {
	var l layout
	st, err := t.Struct("_DRIVER_OBJECT")
	if err != nil || st.Size == 0 {
		return l, fmt.Errorf("_DRIVER_OBJECT: %w", ErrNoDriverType)
	}
	l.objectSize = st.Size
	for _, m := range []struct {
		typ, member string
		at          *uint64
	}{
		{"_DRIVER_OBJECT", "Size", &l.size},
		{"_DRIVER_OBJECT", "DriverStart", &l.start},
		{"_DRIVER_OBJECT", "DriverSize", &l.driverSize},
		{"_DRIVER_OBJECT", "DriverName", &l.name},
		{"_DRIVER_OBJECT", "DriverExtension", &l.extension},
		{"_DRIVER_EXTENSION", "ServiceKeyName", &l.serviceKey},
		{"_OBJECT_HEADER", "Body", &l.headerBody},
	} {
		f, err := t.Field(m.typ, m.member)
		if err != nil {
			return l, fmt.Errorf("%s.%s: %w", m.typ, m.member, ErrNoDriverType)
		}
		*m.at = f.Offset
	}
	l.unicode = util.ResolveUnicodeStringLayout(t)
	l.namer, l.named = scan.NewObjectNamer(t)
	l.maxName = util.MaxUnicodeStringBytes
	return l, nil
}

func Run(ctx tools.Context) ([]Driver, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysicalMemory)
	}
	l, err := resolve(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !l.named {
		ctx.AddDiagnostic("%s: symbol table cannot locate object header names: ObjectName is not read", Name)
	}
	// wdm.h IO_TYPE_DRIVER is the Type of every driver object.
	tag := scan.ResolveTypeTag(ctx.Symbols, scan.IOTypeDriver, scan.Member{Struct: "_DRIVER_OBJECT", Field: "Type"})
	if !tag.Resolved {
		ctx.AddDiagnostic("%s: symbol table has no integer _DRIVER_OBJECT.Type: bodies are judged by their Size alone", Name)
	}
	objects, identity, err := ctx.ExecutiveScan(Name, scan.DriverFilter, tag)
	if err != nil {
		return nil, err
	}
	kernel := ctx.Memory
	width := ctx.Symbols.PointerSize()
	placed, stats, err := scan.FindExecutiveObjectsPlaced(physical, scan.DriverFilter, objects, identity,
		func(body uint64) (Driver, bool) { return l.decode(physical, kernel, width, body) }, ctx.Bounds().Workers)
	if err != nil {
		return nil, fmt.Errorf("%s: pool tag %q: %w", Name, scan.DriverFilter.Tag, err)
	}
	out := make([]Driver, len(placed))
	for i, p := range placed {
		d := p.Row
		d.Offset = p.Place.Body
		d.VirtualOffset = p.Place.BodyAddress()
		d.OtherCopy = p.OtherMappedBody()
		d.TypeIndexFailed = p.TypeIndexFailed
		out[i] = d
	}
	ctx.AddDiagnostic("%s: %d driver objects from %d tag hits (%s)", Name, len(out), stats.TagHits, stats.Describe())
	return out, nil
}

// The body is read in physical memory, where the scan found it; the strings
// and the extension it points to are kernel virtual addresses.
func (l layout) decode(physical, kernel memory.MemoryReader, width uint8, body uint64) (Driver, bool) {
	raw, err := physical.ReadAt(body, l.objectSize)
	if err != nil || uint64(len(raw)) != l.objectSize {
		return Driver{}, false
	}
	// Every driver object named in \Driver and \FileSystem carries
	// sizeof(_DRIVER_OBJECT) in Size (S64 D2).
	if uint64(binary.LittleEndian.Uint16(raw[l.size:])) != l.objectSize {
		return Driver{}, false
	}
	d := Driver{
		Start: pointer(raw[l.start:], width),
		Size:  uint64(binary.LittleEndian.Uint32(raw[l.driverSize:])),
	}
	name, err := readSplit(raw[l.name:], kernel, l.unicode, width, l.maxName)
	d.Name, d.NameUnreadable = name, err != nil
	ext := pointer(raw[l.extension:], width)
	if ext == 0 {
		d.ServiceKeyUnreadable = true
	} else {
		key, err := util.ReadUnicodeString(kernel, ext+l.serviceKey, l.unicode, l.maxName)
		d.ServiceKey, d.ServiceKeyUnreadable = key.Text(), err != nil
	}
	if l.named && body >= l.headerBody {
		obj, present, readable := l.namer.ReadName(physical, kernel, kernel, body-l.headerBody)
		d.ObjectName, d.ObjectNameUnreadable = obj, !present || !readable
	} else {
		d.ObjectNameUnreadable = true
	}
	return d, true
}

func pointer(b []byte, width uint8) uint64 {
	if width == 4 {
		return uint64(binary.LittleEndian.Uint32(b))
	}
	return binary.LittleEndian.Uint64(b)
}

// UNICODE_STRING (ntdef.h, Learn): Length and MaximumLength in bytes,
// Length not above MaximumLength, UTF-16 code units.
func readSplit(raw []byte, kernel memory.MemoryReader, us util.UnicodeStringLayout, width uint8, max uint64) (string, error) {
	length := uint64(binary.LittleEndian.Uint16(raw[us.LengthOffset:]))
	maximum := uint64(binary.LittleEndian.Uint16(raw[us.MaximumLengthOffset:]))
	buffer := pointer(raw[us.BufferOffset:], width)
	switch {
	case length == 0:
		return "", nil
	case length%2 != 0 || length > maximum || length > max:
		return "", ErrStringInvalid
	case buffer == 0:
		return "", ErrStringUnread
	}
	b, err := kernel.ReadAt(buffer, length)
	if err != nil || uint64(len(b)) != length {
		return "", ErrStringUnread
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

func Identified(driverName, objectName, serviceKey string) bool {
	return PlausibleName(driverName) || PlausibleName(objectName) || PlausibleName(serviceKey)
}
