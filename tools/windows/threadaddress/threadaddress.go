package threadaddress

import (
	"errors"
	"strings"

	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/pesymbols"
)

var ErrOwnerNotListed = errors.New("threadaddress: owning process is not in the process list")

type Range struct {
	Start      uint64
	End        uint64
	Type       string
	Protection string
	Path       string
}

type RangeSource func(ctx tools.Context, p processlist.Process) ([]memoryranges.Mapping, error)

type ExportSource func(ctx tools.Context, m pesymbols.Module) ([]pe.Export, error)

type walk struct {
	ranges []memoryranges.Mapping
	err    error
}

type Spaces struct {
	procs   map[uint64]processlist.Process
	ranges  RangeSource
	exports ExportSource
	walked  map[uint64]walk
	named   map[exportKey]map[uint64]string

	vadCount     symbols.IntField
	haveVadCount bool
	secureAt     uint64
	haveSecure   bool

	ExportsUnread int
}

type exportKey struct{ eprocess, start uint64 }

func New(ctx tools.Context) (*Spaces, error) {
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		return nil, err
	}
	decoder, err := memoryranges.NewDecoder(ctx)
	if err != nil {
		return nil, err
	}
	return NewWith(ctx, procs, decoder.Mappings, pesymbols.Exports), nil
}

func NewWith(ctx tools.Context, procs []processlist.Process, ranges RangeSource, exports ExportSource) *Spaces {
	s := &Spaces{
		procs:   make(map[uint64]processlist.Process, len(procs)),
		ranges:  ranges,
		exports: exports,
		walked:  map[uint64]walk{},
		named:   map[exportKey]map[uint64]string{},
	}
	for _, p := range procs {
		s.procs[p.EPROCESS] = p
	}
	if f, err := symbols.ResolveIntField(ctx.Symbols, "_EPROCESS", "VadCount"); err == nil {
		s.vadCount, s.haveVadCount = f, true
	}
	// SecureState is a union the tables give no width for (S51 T4); its
	// first pointer-wide word is nonzero for a secure process.
	if pcb, err := ctx.Symbols.Field("_EPROCESS", "Pcb"); err == nil {
		if f, err := ctx.Symbols.Field("_KPROCESS", "SecureState"); err == nil {
			s.secureAt, s.haveSecure = pcb.Offset+f.Offset, true
		}
	}
	return s
}

func (s *Spaces) Owner(eprocess uint64) (processlist.Process, bool) {
	p, ok := s.procs[eprocess]
	return p, ok
}

func (s *Spaces) Ranges(ctx tools.Context, eprocess uint64) ([]memoryranges.Mapping, error) {
	if w, ok := s.walked[eprocess]; ok {
		return w.ranges, w.err
	}
	p, ok := s.procs[eprocess]
	if !ok {
		return nil, ErrOwnerNotListed
	}
	ranges, err := s.ranges(ctx, p)
	s.walked[eprocess] = walk{ranges, err}
	return ranges, err
}

// Without a recorded count the walk cannot be shown short, so it counts as
// whole.
func (s *Spaces) Short(ctx tools.Context, eprocess uint64, kept int) bool {
	if s.haveSecure {
		if v, err := ctx.Symbols.ReadPointer(ctx.Memory, eprocess+s.secureAt); err == nil && v != 0 {
			return true
		}
	}
	if !s.haveVadCount {
		return false
	}
	n, err := s.vadCount.Read(ctx.Memory, eprocess)
	return err == nil && n > uint64(kept)
}

func Holding(ranges []memoryranges.Mapping, address uint64) (Range, bool) {
	for _, m := range ranges {
		if m.Start <= address && address <= m.End {
			return Range{Start: m.Start, End: m.End, Type: m.Type, Protection: m.Protection, Path: m.Path}, true
		}
	}
	return Range{}, false
}

func UserAddress(pointerSize uint8, address uint64) bool {
	if pointerSize == 4 {
		return address < 0x80000000
	}
	return address>>63 == 0
}

func (s *Spaces) Export(ctx tools.Context, eprocess uint64, r Range, address uint64) string {
	if r.Type != memoryranges.KindImage {
		return ""
	}
	key := exportKey{eprocess, r.Start}
	names, ok := s.named[key]
	if !ok {
		names = s.readExports(ctx, eprocess, r)
		s.named[key] = names
	}
	return names[address]
}

func (s *Spaces) readExports(ctx tools.Context, eprocess uint64, r Range) map[uint64]string {
	p := s.procs[eprocess]
	name := r.Path
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	exports, err := s.exports(ctx, pesymbols.Module{PID: p.PID, ProcessName: p.Name, DirectoryTableBase: p.DirectoryTableBase,
		Name: name, Base: r.Start, Size: r.End - r.Start + 1})
	if err != nil {
		s.ExportsUnread++
		return nil
	}
	out := make(map[uint64]string, len(exports))
	for _, e := range exports {
		if e.Name == "" || e.Forwarder != "" || e.ForwarderUnreadable {
			continue
		}
		at := r.Start + uint64(e.RVA)
		if cur, taken := out[at]; !taken || e.Name < cur {
			out[at] = e.Name
		}
	}
	return out
}

type Place struct {
	Range  Range
	Mapped bool
	Export string
}

// A failed walk is returned so that the caller can name the owner; callers
// count it once per owner.
func (s *Spaces) Place(ctx tools.Context, eprocess, address uint64) (Place, error) {
	ranges, err := s.Ranges(ctx, eprocess)
	if err != nil {
		return Place{}, err
	}
	r, ok := Holding(ranges, address)
	if !ok {
		return Place{}, nil
	}
	return Place{Range: r, Mapped: true, Export: s.Export(ctx, eprocess, r, address)}, nil
}
