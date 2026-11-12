package filescan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.file.scan"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find file objects by their pool allocations, freed ones included, with name, device and access",
		},
		RunAny,
	)
}

var (
	ErrNotWindows       = errors.New("filescan: profile is not windows")
	ErrNoPhysicalMemory = errors.New("filescan: no physical memory to scan")
	ErrNoFileType       = errors.New("filescan: symbol table lacks a _FILE_OBJECT member")
	ErrNameInvalid      = errors.New("filescan: FileName Length is odd or above MaximumLength")
	ErrNameUnread       = errors.New("filescan: FileName buffer does not read")
)

type File struct {
	Offset           uint64
	VirtualOffset    uint64
	OtherCopy        uint64
	Name             string
	NameUnreadable   bool
	Device           string
	DeviceUnreadable bool
	ReadAccess       bool
	WriteAccess      bool
	DeleteAccess     bool
	SharedRead       bool
	SharedWrite      bool
	SharedDelete     bool
	DeletePending    bool
	TypeIndexFailed  bool
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type layout struct {
	size       uint64
	sizeMember uint64
	device     uint64
	fileName   uint64
	flags      []flagMember
	headerBody uint64
	unicode    util.UnicodeStringLayout
	namer      scan.ObjectNamer
	width      uint8
}

type flagMember struct {
	offset uint64
	set    func(*File)
}

func resolve(t symbols.SymbolTable) (layout, error) {
	var l layout
	st, err := t.Struct("_FILE_OBJECT")
	if err != nil || st.Size == 0 {
		return l, fmt.Errorf("_FILE_OBJECT: %w", ErrNoFileType)
	}
	l.size = st.Size
	for _, m := range []struct {
		typ, member string
		at          *uint64
	}{
		{"_FILE_OBJECT", "Size", &l.sizeMember},
		{"_FILE_OBJECT", "DeviceObject", &l.device},
		{"_FILE_OBJECT", "FileName", &l.fileName},
		{"_OBJECT_HEADER", "Body", &l.headerBody},
	} {
		f, err := t.Field(m.typ, m.member)
		if err != nil {
			return l, fmt.Errorf("%s.%s: %w", m.typ, m.member, ErrNoFileType)
		}
		*m.at = f.Offset
	}
	for _, m := range []struct {
		member string
		set    func(*File)
	}{
		{"ReadAccess", func(f *File) { f.ReadAccess = true }},
		{"WriteAccess", func(f *File) { f.WriteAccess = true }},
		{"DeleteAccess", func(f *File) { f.DeleteAccess = true }},
		{"SharedRead", func(f *File) { f.SharedRead = true }},
		{"SharedWrite", func(f *File) { f.SharedWrite = true }},
		{"SharedDelete", func(f *File) { f.SharedDelete = true }},
		{"DeletePending", func(f *File) { f.DeletePending = true }},
	} {
		if f, err := t.Field("_FILE_OBJECT", m.member); err == nil && f.Offset < l.size {
			l.flags = append(l.flags, flagMember{offset: f.Offset, set: m.set})
		}
	}
	l.unicode = util.ResolveUnicodeStringLayout(t)
	l.width = t.PointerSize()
	return l, nil
}

func Run(ctx tools.Context) ([]File, error) {
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
		ctx.AddDiagnostic("%s: symbol table cannot locate object header names: Device is not read", Name)
	}
	l.namer = namer
	tag := scan.ResolveTypeTag(ctx.Symbols, scan.IOTypeFile, scan.Member{Struct: "_FILE_OBJECT", Field: "Type"})
	if !tag.Resolved {
		ctx.AddDiagnostic("%s: symbol table has no integer _FILE_OBJECT.Type: bodies are judged by their Size alone", Name)
	}
	objects, identity, err := ctx.ExecutiveScan(Name, scan.FileFilter, tag)
	if err != nil {
		return nil, err
	}
	// A freed file object can lose its header's TypeIndex while its body
	// still holds Type 5 (S31 M2); the row says so.
	identity.KeepIndexMismatch = tag.Resolved
	kernel := ctx.Memory
	half := modulelist.KernelHalfStart(ctx)
	placed, stats, err := scan.FindExecutiveObjectsPlaced(physical, scan.FileFilter, objects, identity,
		func(body uint64) (File, bool) { return l.decode(physical, kernel, half, named, body) }, ctx.Bounds().Workers)
	if err != nil {
		return nil, fmt.Errorf("%s: pool tag %q: %w", Name, scan.FileFilter.Tag, err)
	}
	out := make([]File, len(placed))
	for i, p := range placed {
		f := p.Row
		f.Offset = p.Place.Body
		f.VirtualOffset = p.Place.BodyAddress()
		f.OtherCopy = p.OtherMappedBody()
		f.TypeIndexFailed = p.TypeIndexFailed
		out[i] = f
	}
	ctx.AddDiagnostic("%s: %d file objects from %d tag hits (%s)", Name, len(out), stats.TagHits, stats.Describe())
	return out, nil
}

// FILE_OBJECT.Size is the structure's size (Learn) and DeviceObject the
// device the file is opened on, so it is a system-space address.
func (l layout) decode(physical, kernel memory.MemoryReader, half uint64, named bool, body uint64) (File, bool) {
	raw, err := physical.ReadAt(body, l.size)
	if err != nil || uint64(len(raw)) != l.size {
		return File{}, false
	}
	if uint64(binary.LittleEndian.Uint16(raw[l.sizeMember:])) != l.size {
		return File{}, false
	}
	device := pointer(raw[l.device:], l.width)
	if device < half {
		return File{}, false
	}
	var f File
	for _, m := range l.flags {
		if raw[m.offset] != 0 {
			m.set(&f)
		}
	}
	name, err := readText(raw[l.fileName:], kernel, l.unicode, l.width)
	f.Name, f.NameUnreadable = name, err != nil
	if named && device >= l.headerBody {
		d, present, readable := l.namer.ReadName(kernel, kernel, kernel, device-l.headerBody)
		f.Device, f.DeviceUnreadable = d, !present || !readable
	} else {
		f.DeviceUnreadable = true
	}
	return f, true
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
		return "", ErrNameInvalid
	case length == 0:
		return "", nil
	case buffer == 0:
		return "", ErrNameUnread
	}
	b, err := kernel.ReadAt(buffer, length)
	if err != nil || uint64(len(b)) != length {
		return "", ErrNameUnread
	}
	return util.DecodeCountedUTF16LE(b), nil
}

// FileName is valid only while the create request is processed (Learn,
// FILE_OBJECT), so the scan shows it as found. This is the test a reader
// applies to judge it: Windows file names hold no character below 0x20
// (Learn, Naming Files, Paths, and Namespaces) and a decoded name holds no
// U+FFFD.
func PlausibleName(name string) bool {
	if name == "" || strings.ContainsRune(name, utf8.RuneError) {
		return false
	}
	return strings.IndexFunc(name, func(r rune) bool { return r < 0x20 }) < 0
}
