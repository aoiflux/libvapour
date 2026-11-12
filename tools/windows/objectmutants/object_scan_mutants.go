package objectmutants

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
)

const Name = "windows.object.scan_mutants"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find named mutant objects by their pool allocations, freed ones included, with the thread that owns each",
		},
		RunAny,
	)
}

var (
	ErrNotWindows       = errors.New("objectmutants: profile is not windows")
	ErrNoPhysicalMemory = errors.New("objectmutants: no physical memory to scan")
	ErrNoMutantType     = errors.New("objectmutants: symbol table lacks a _KMUTANT member")
	ErrOwnerUnread      = errors.New("objectmutants: owner thread does not read")
)

type Mutant struct {
	Offset          uint64
	VirtualOffset   uint64
	OtherCopy       uint64
	Name            string
	NameUnreadable  bool
	OwnerThread     uint64
	OwnerPID        uint64
	OwnerTID        uint64
	OwnerUnreadable bool
	Abandoned       bool
	TypeIndexFailed bool
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type layout struct {
	size        uint64
	signal      uint64
	owner       uint64
	abandoned   symbols.IntField
	headerBody  uint64
	cid         uint64
	cidProcess  uint64
	cidThread   uint64
	ownerFields bool
	namer       scan.ObjectNamer
	width       uint8
}

func resolve(t symbols.SymbolTable) (layout, error) {
	var l layout
	st, err := t.Struct("_KMUTANT")
	if err != nil || st.Size == 0 {
		return l, fmt.Errorf("_KMUTANT: %w", ErrNoMutantType)
	}
	l.size = st.Size
	header, err := t.Field("_KMUTANT", "Header")
	if err != nil {
		return l, fmt.Errorf("_KMUTANT.Header: %w", ErrNoMutantType)
	}
	signal, err := t.Field("_DISPATCHER_HEADER", "SignalState")
	if err != nil {
		return l, fmt.Errorf("_DISPATCHER_HEADER.SignalState: %w", ErrNoMutantType)
	}
	l.signal = header.Offset + signal.Offset
	owner, err := t.Field("_KMUTANT", "OwnerThread")
	if err != nil {
		return l, fmt.Errorf("_KMUTANT.OwnerThread: %w", ErrNoMutantType)
	}
	l.owner = owner.Offset
	if l.abandoned, err = symbols.ResolveIntField(t, "_KMUTANT", "Abandoned"); err != nil {
		return l, fmt.Errorf("_KMUTANT.Abandoned: %w", ErrNoMutantType)
	}
	body, err := t.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return l, fmt.Errorf("_OBJECT_HEADER.Body: %w", ErrNoMutantType)
	}
	l.headerBody = body.Offset
	cid, errC := t.Field("_ETHREAD", "Cid")
	process, errP := t.Field("_CLIENT_ID", "UniqueProcess")
	thread, errT := t.Field("_CLIENT_ID", "UniqueThread")
	if errC == nil && errP == nil && errT == nil {
		l.cid, l.cidProcess, l.cidThread, l.ownerFields = cid.Offset, process.Offset, thread.Offset, true
	}
	l.width = t.PointerSize()
	return l, nil
}

func Run(ctx tools.Context) ([]Mutant, error) {
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
		return nil, fmt.Errorf("%s: object header name info: %w", Name, ErrNoMutantType)
	}
	l.namer = namer
	if !l.ownerFields {
		ctx.AddDiagnostic("%s: symbol table lacks _ETHREAD.Cid: owner ids are not read", Name)
	}
	tag := scan.ResolveTypeTag(ctx.Symbols, scan.MutantObject,
		scan.Member{Struct: "_KMUTANT", Field: "Header"}, scan.Member{Struct: "_DISPATCHER_HEADER", Field: "Type"})
	if !tag.Resolved {
		ctx.AddDiagnostic("%s: symbol table has no integer _DISPATCHER_HEADER.Type: bodies are judged by their state alone", Name)
	}
	objects, identity, err := ctx.ExecutiveScan(Name, scan.MutantFilter, tag)
	if err != nil {
		return nil, err
	}
	// A freed mutant can lose its header's TypeIndex while its body still
	// holds the dispatcher type (S31 M2); the row says so.
	identity.KeepIndexMismatch = tag.Resolved
	kernel := ctx.Memory
	half := modulelist.KernelHalfStart(ctx)
	unnamed, unproven := 0, 0
	placed, stats, err := scan.FindExecutiveObjectsPlaced(physical, scan.MutantFilter, objects, identity,
		func(body uint64) (found, bool) { return l.decode(physical, kernel, half, body) }, ctx.Bounds().Workers)
	if err != nil {
		return nil, fmt.Errorf("%s: pool tag %q: %w", Name, scan.MutantFilter.Tag, err)
	}
	out := make([]Mutant, 0, len(placed))
	for _, p := range placed {
		if !p.Row.named {
			unnamed++
			continue
		}
		// A header that fails TypeIndex and a name that does not read leave
		// nothing but a dispatcher byte to call the body a mutant (S69 M4).
		if p.TypeIndexFailed && p.Row.NameUnreadable {
			unproven++
			continue
		}
		m := p.Row.Mutant
		m.Offset = p.Place.Body
		m.VirtualOffset = p.Place.BodyAddress()
		m.OtherCopy = p.OtherMappedBody()
		m.TypeIndexFailed = p.TypeIndexFailed
		if m.OwnerThread != 0 && l.ownerFields {
			pid, tid, err := l.ownerIDs(kernel, m.OwnerThread)
			if err != nil {
				m.OwnerUnreadable = true
				ctx.AddDiagnostic("%s: mutant at 0x%x: owner thread at 0x%x: %v", Name, m.Offset, m.OwnerThread, err)
			}
			m.OwnerPID, m.OwnerTID = pid, tid
		} else if m.OwnerThread != 0 {
			m.OwnerUnreadable = true
		}
		out = append(out, m)
	}
	ctx.AddDiagnostic("%s: %d named mutants; not listed: %d without a name, %d of another TypeIndex whose name does "+
		"not read; from %d tag hits (%s)", Name, len(out), unnamed, unproven, stats.TagHits, stats.Describe())
	return out, nil
}

type found struct {
	Mutant
	named bool
}

// A mutex is signaled exactly when no thread owns it, and an owner may hold
// it through repeated waits (Learn, CreateMutexW and KeInitializeMutex): 1
// unowned, 0 and below owned (S69 M1). A body whose owner and state disagree
// is not a mutant's.
func (l layout) decode(physical, kernel memory.MemoryReader, half, body uint64) (found, bool) {
	raw, err := physical.ReadAt(body, l.size)
	if err != nil || uint64(len(raw)) != l.size {
		return found{}, false
	}
	signal := int32(binary.LittleEndian.Uint32(raw[l.signal:]))
	owner := pointer(raw[l.owner:], l.width)
	switch {
	case owner == 0 && signal != 1:
		return found{}, false
	case owner != 0 && (owner < half || signal > 0):
		return found{}, false
	}
	abandoned, err := l.abandoned.Decode(raw)
	if err != nil {
		return found{}, false
	}
	f := found{Mutant: Mutant{OwnerThread: owner, Abandoned: abandoned != 0}}
	if body < l.headerBody {
		return f, true
	}
	name, present, readable := l.namer.ReadName(physical, kernel, kernel, body-l.headerBody)
	if !present {
		return f, true
	}
	f.named = true
	if !readable || !PlausibleName(name) {
		f.NameUnreadable = true
		return f, true
	}
	f.Name = name
	return f, true
}

func (l layout) ownerIDs(kernel memory.MemoryReader, thread uint64) (pid, tid uint64, err error) {
	width := uint64(l.width)
	raw, err := kernel.ReadAt(thread+l.cid, max(l.cidProcess, l.cidThread)+width)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrOwnerUnread, err)
	}
	if uint64(len(raw)) < max(l.cidProcess, l.cidThread)+width {
		return 0, 0, ErrOwnerUnread
	}
	return pointer(raw[l.cidProcess:], l.width), pointer(raw[l.cidThread:], l.width), nil
}

func pointer(b []byte, width uint8) uint64 {
	if width == 4 {
		return uint64(binary.LittleEndian.Uint32(b))
	}
	return binary.LittleEndian.Uint64(b)
}

// CreateMutexW: the name below its Global or Local prefix "can contain any
// character except the backslash"; the object manager keeps that part as
// the name. Control characters and undecodable units never occur in a
// mutant name the measured handle tables reach (S69 M3).
func PlausibleName(name string) bool {
	if name == "" || strings.ContainsRune(name, '\\') || strings.ContainsRune(name, utf8.RuneError) {
		return false
	}
	return strings.IndexFunc(name, func(r rune) bool { return r < 0x20 }) < 0
}
