package subsection

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

type AvailablePage struct {
	PhysicalOffset uint64
	FileOffset     uint64
	PageSize       uint64
}

type fieldSet struct {
	controlAreaSize   uint64
	mmpteSize         uint64
	subBase           uint64
	ptesInSub         uint64
	nextSub           uint64
	startingSector    uint64
	subControlArea    uint64
	vadSubsection     uint64
	haveVadSubsection bool
	firstProtoPte     uint64
	haveFirstProto    bool
	startVPN          uint64
	haveStartVPN      bool
	startVPNHigh      uint64
	haveStartVPNHigh  bool
	endVPN            uint64
	haveEndVPN        bool
	endVPNHigh        uint64
	haveEndVPNHigh    bool
	lastContigPte     uint64
	haveLastContig    bool

	walk walkFields
}

type Resolver struct {
	reader memory.MemoryReader
	table  symbols.SymbolTable
	f      fieldSet
	bounds limits.Limits
}

func (r *Resolver) SetLimits(l limits.Limits) { r.bounds = l }

func NewResolver(reader memory.MemoryReader, table symbols.SymbolTable) (*Resolver, error) {
	det, ok := table.(symbols.DeterministicLookup)
	if !ok {
		return nil, errors.New("subsection: symbol table has no SizeOf")
	}

	caSize, err := det.SizeOf("_CONTROL_AREA")
	if err != nil {
		return nil, fmt.Errorf("size of _CONTROL_AREA: %w", err)
	}

	mmpteSize, err := det.SizeOf("_MMPTE")
	if err != nil || mmpteSize == 0 {
		mmpteSize = uint64(table.PointerSize())
	}

	f := fieldSet{controlAreaSize: caSize, mmpteSize: mmpteSize}
	for _, r := range []struct {
		field string
		dst   *uint64
	}{
		{"SubsectionBase", &f.subBase},
		{"PtesInSubsection", &f.ptesInSub},
		{"NextSubsection", &f.nextSub},
		{"StartingSector", &f.startingSector},
		{"ControlArea", &f.subControlArea},
	} {
		fld, err := table.Field("_SUBSECTION", r.field)
		if err != nil {
			return nil, fmt.Errorf("resolve _SUBSECTION.%s: %w", r.field, err)
		}
		*r.dst = fld.Offset
	}

	if fld, ferr := table.Field("_MMVAD", "Subsection"); ferr == nil {
		f.vadSubsection = fld.Offset
		f.haveVadSubsection = true
	}

	if fld, ferr := table.Field("_MMVAD", "FirstPrototypePte"); ferr == nil {
		f.firstProtoPte = fld.Offset
		f.haveFirstProto = true
	}
	if fld, ferr := table.Field("_MMVAD_SHORT", "StartingVpn"); ferr == nil {
		f.startVPN = fld.Offset
		f.haveStartVPN = true
	}
	if fld, ferr := table.Field("_MMVAD_SHORT", "StartingVpnHigh"); ferr == nil {
		f.startVPNHigh = fld.Offset
		f.haveStartVPNHigh = true
	}
	if fld, ferr := table.Field("_MMVAD_SHORT", "EndingVpn"); ferr == nil {
		f.endVPN = fld.Offset
		f.haveEndVPN = true
	}
	if fld, ferr := table.Field("_MMVAD_SHORT", "EndingVpnHigh"); ferr == nil {
		f.endVPNHigh = fld.Offset
		f.haveEndVPNHigh = true
	}

	f.walk = resolveWalkFields(table)
	if fld, ferr := table.Field("_MMVAD", "LastContiguousPte"); ferr == nil {
		f.lastContigPte = fld.Offset
		f.haveLastContig = true
	}

	return &Resolver{reader: reader, table: table, f: f}, nil
}

func (r *Resolver) AvailablePages(controlAreaVA uint64) ([]AvailablePage, error) {
	if controlAreaVA == 0 {
		return nil, errors.New("subsection: nil control area")
	}
	return r.walkSubsections(controlAreaVA+r.f.controlAreaSize, controlAreaVA, nil)
}

func (r *Resolver) ControlAreaFromVAD(vadVA uint64) (controlAreaVA, subsectionVA uint64, err error) {
	if !r.f.haveVadSubsection {
		return 0, 0, errors.New("subsection: no _MMVAD.Subsection in symbols")
	}
	if vadVA == 0 {
		return 0, 0, errors.New("subsection: nil vad")
	}
	subsectionVA, err = r.table.ReadPointer(r.reader, vadVA+r.f.vadSubsection)
	if err != nil {
		return 0, 0, fmt.Errorf("read _MMVAD.Subsection at 0x%x: %w", vadVA+r.f.vadSubsection, err)
	}
	if subsectionVA == 0 {
		return 0, 0, fmt.Errorf("subsection: vad 0x%x has no subsection (not file-backed)", vadVA)
	}
	controlAreaVA, err = r.table.ReadPointer(r.reader, subsectionVA+r.f.subControlArea)
	if err != nil {
		return 0, 0, fmt.Errorf("read _SUBSECTION.ControlArea at 0x%x: %w", subsectionVA+r.f.subControlArea, err)
	}
	if controlAreaVA == 0 {
		return 0, 0, fmt.Errorf("subsection: 0x%x has no control area", subsectionVA)
	}
	return controlAreaVA, subsectionVA, nil
}

func (r *Resolver) AvailablePagesFromVAD(vadVA uint64) ([]AvailablePage, error) {
	if !r.f.haveFirstProto || !r.f.haveStartVPN || !r.f.haveEndVPN {
		return nil, errors.New("subsection: view bounds need _MMVAD.FirstPrototypePte and " +
			"_MMVAD_SHORT.StartingVpn/EndingVpn")
	}
	controlAreaVA, subsectionVA, err := r.ControlAreaFromVAD(vadVA)
	if err != nil {
		return nil, err
	}
	startVPN, err := r.readVPN(vadVA+r.f.startVPN, vadVA+r.f.startVPNHigh, r.f.haveStartVPNHigh)
	if err != nil {
		return nil, fmt.Errorf("read _MMVAD_SHORT.StartingVpn at 0x%x: %w", vadVA+r.f.startVPN, err)
	}
	endVPN, err := r.readVPN(vadVA+r.f.endVPN, vadVA+r.f.endVPNHigh, r.f.haveEndVPNHigh)
	if err != nil {
		return nil, fmt.Errorf("read _MMVAD_SHORT.EndingVpn at 0x%x: %w", vadVA+r.f.endVPN, err)
	}
	if endVPN < startVPN {
		return nil, fmt.Errorf("subsection: vad 0x%x end vpn 0x%x precedes start 0x%x", vadVA, endVPN, startVPN)
	}
	firstProto, err := r.table.ReadPointer(r.reader, vadVA+r.f.firstProtoPte)
	if err != nil {
		return nil, fmt.Errorf("read _MMVAD.FirstPrototypePte at 0x%x: %w", vadVA+r.f.firstProtoPte, err)
	}
	if firstProto == 0 {
		return nil, fmt.Errorf("subsection: vad 0x%x has no prototype PTEs (not file-backed)", vadVA)
	}
	return r.walkSubsections(subsectionVA, controlAreaVA, &viewSpan{firstPTE: firstProto, pages: endVPN - startVPN + 1})
}

// A shared image page's leaf PTE holds only the prototype bit or the
// VAD-lookup sentinel (0xFFFFFFFF0000 on x64); the real PTE is in the VAD's
// prototype array. Opt-in only and never part of
// layers.IntelTranslator.Translate, since the CPU does not follow prototype
// PTEs. A non-resident target returns layers.UnmappedPageError, not zeroes.
func (r *Resolver) ResolveVA(vadVA, va uint64) (uint64, error) {
	if !r.f.haveFirstProto || !r.f.haveStartVPN {
		return 0, errors.New("subsection: VA resolution needs _MMVAD.FirstPrototypePte and _MMVAD_SHORT.StartingVpn")
	}
	if vadVA == 0 {
		return 0, errors.New("subsection: nil vad")
	}

	startVPN, err := r.readVPN(vadVA+r.f.startVPN, vadVA+r.f.startVPNHigh, r.f.haveStartVPNHigh)
	if err != nil {
		return 0, fmt.Errorf("read _MMVAD_SHORT.StartingVpn at 0x%x: %w", vadVA+r.f.startVPN, err)
	}
	pageVPN := va >> 12
	if pageVPN < startVPN {
		return 0, fmt.Errorf("subsection: va 0x%x below vad start vpn 0x%x", va, startVPN)
	}
	if r.f.haveEndVPN {
		if endVPN, eerr := r.readVPN(vadVA+r.f.endVPN, vadVA+r.f.endVPNHigh, r.f.haveEndVPNHigh); eerr == nil && pageVPN > endVPN {
			return 0, fmt.Errorf("subsection: va 0x%x above vad end vpn 0x%x", va, endVPN)
		}
	}
	index := pageVPN - startVPN

	firstProto, err := r.table.ReadPointer(r.reader, vadVA+r.f.firstProtoPte)
	if err != nil {
		return 0, fmt.Errorf("read _MMVAD.FirstPrototypePte at 0x%x: %w", vadVA+r.f.firstProtoPte, err)
	}
	if firstProto == 0 {
		return 0, fmt.Errorf("subsection: vad 0x%x has no prototype PTEs (not file-backed)", vadVA)
	}

	pteAddr := firstProto + index*r.f.mmpteSize
	// LastContiguousPte ends this array. A view that runs into the next
	// subsection continues in that subsection's own array, so what follows here
	// is unrelated pool (the kernel goes through MiGetProtoPteAddress); indexes
	// past it are refused. MM_ALLOCATION_FILLS_VAD (~3) means one array covers the
	// view, and a value below FirstPrototypePte bounds nothing, leaving the VAD
	// size as the bound.
	if r.f.haveLastContig {
		last, lerr := r.table.ReadPointer(r.reader, vadVA+r.f.lastContigPte)
		if lerr != nil {
			return 0, fmt.Errorf("read _MMVAD.LastContiguousPte at 0x%x: %w", vadVA+r.f.lastContigPte, lerr)
		}
		if last >= firstProto && pteAddr > last {
			return 0, fmt.Errorf("subsection: va 0x%x needs entry 0x%x, past LastContiguousPte 0x%x", va, pteAddr, last)
		}
	}
	pte, err := r.readMMPTE(pteAddr)
	if err != nil {
		return 0, fmt.Errorf("read prototype _MMPTE at 0x%x: %w", pteAddr, err)
	}
	return layers.ResolveProtoPTE(pte, va)
}

// The *VpnHigh members are one byte, so the 4-byte read is masked; otherwise
// EndingVpnHigh, CommitChargeHigh and SpareNT64VadUChar leak into the VPN and
// every real address is rejected. SymbolTable has no 1-byte read.
func (r *Resolver) readVPN(lowOffset, highOffset uint64, haveHigh bool) (uint64, error) {
	low, err := r.table.ReadUint32(r.reader, lowOffset)
	if err != nil {
		return 0, err
	}
	vpn := uint64(low)
	if haveHigh {
		if h, herr := r.table.ReadUint32(r.reader, highOffset); herr == nil {
			vpn |= uint64(h&0xff) << 32
		}
	}
	return vpn, nil
}

// Honours the entry width: 4 bytes on non-PAE x86, 8 otherwise.
func (r *Resolver) readMMPTE(addr uint64) (uint64, error) {
	if r.f.mmpteSize == 4 {
		v, err := r.table.ReadUint32(r.reader, addr)
		return uint64(v), err
	}
	return r.table.ReadUint64(r.reader, addr)
}

const prototypePage = uint64(0x1000)

var (
	ErrWalkFields    = errors.New("subsection: symbol table lacks a member the subsection walk needs")
	ErrNoSubsections = errors.New("subsection: no subsection points back to the control area")
	ErrListCut       = errors.New("subsection: subsection list cut")
	ErrExtent        = errors.New("subsection: extent does not fit the subsection's prototype ptes")
	ErrBudget        = errors.New("subsection: file pages exceed the segment's ptes")
)

const (
	imageSector = uint64(0x200)
	dataSector  = uint64(0x1000)
)

var errNotOwned = errors.New("subsection: ControlArea is another control area")

type walkFields struct {
	err error

	owner, base, ptes, next, sector, fullSectors symbols.IntField
	sectorHigh, endOffset                        symbols.IntField
	haveHigh, haveEnd                            bool
	flagsAt                                      uint64

	imageFlag symbols.IntField
	caFlagsAt uint64

	segment, totalPtes symbols.IntField
	haveSegment        bool

	valid, hardwareFrame, transition, prototype, transitionFrame symbols.IntField
}

func resolveWalkFields(table symbols.SymbolTable) walkFields {
	var w walkFields
	need := func(dst *symbols.IntField, typeName, member string) {
		if w.err != nil {
			return
		}
		f, err := symbols.ResolveIntField(table, typeName, member)
		if err != nil {
			w.err = fmt.Errorf("%w: %v", ErrWalkFields, err)
			return
		}
		*dst = f
	}
	need(&w.owner, "_SUBSECTION", "ControlArea")
	need(&w.base, "_SUBSECTION", "SubsectionBase")
	need(&w.ptes, "_SUBSECTION", "PtesInSubsection")
	need(&w.next, "_SUBSECTION", "NextSubsection")
	need(&w.sector, "_SUBSECTION", "StartingSector")
	need(&w.fullSectors, "_SUBSECTION", "NumberOfFullSectors")
	need(&w.imageFlag, "_MMSECTION_FLAGS", "Image")
	need(&w.valid, "_MMPTE_HARDWARE", "Valid")
	need(&w.hardwareFrame, "_MMPTE_HARDWARE", "PageFrameNumber")
	need(&w.transition, "_MMPTE_TRANSITION", "Transition")
	need(&w.prototype, "_MMPTE_TRANSITION", "Prototype")
	need(&w.transitionFrame, "_MMPTE_TRANSITION", "PageFrameNumber")
	if w.err != nil {
		return w
	}
	flags, err := table.Field("_CONTROL_AREA", "u")
	if err != nil {
		w.err = fmt.Errorf("%w: _CONTROL_AREA.u: %v", ErrWalkFields, err)
		return w
	}
	w.caFlagsAt = flags.Offset

	// 26100 names the flags member; 14393 and 19045 hold the same flags in an
	// unnamed union at the same offset.
	sub, err := table.Field("_SUBSECTION", "SubsectionFlags")
	if err != nil {
		sub, err = table.Field("_SUBSECTION", "u")
	}
	if err == nil {
		w.flagsAt = sub.Offset
		if f, ferr := symbols.ResolveIntField(table, "_MMSUBSECTION_FLAGS", "StartingSector4132"); ferr == nil {
			w.sectorHigh, w.haveHigh = f, true
		}
		if f, ferr := symbols.ResolveIntField(table, "_MMSUBSECTION_FLAGS", "SectorEndOffset"); ferr == nil {
			w.endOffset, w.haveEnd = f, true
		}
	}

	seg, serr := symbols.ResolveIntField(table, "_CONTROL_AREA", "Segment")
	total, terr := symbols.ResolveIntField(table, "_SEGMENT", "TotalNumberOfPtes")
	if serr == nil && terr == nil {
		w.segment, w.totalPtes, w.haveSegment = seg, total, true
	}
	return w
}

func bitsOf(f symbols.IntField, v uint64) uint64 {
	if f.BitOffset >= 64 {
		return 0
	}
	v >>= f.BitOffset
	if f.BitLength == 0 || f.BitLength >= 64 {
		return v
	}
	return v & (uint64(1)<<f.BitLength - 1)
}

func (w walkFields) resident(pte uint64) (uint64, bool) {
	switch {
	case bitsOf(w.valid, pte) != 0:
		return bitsOf(w.hardwareFrame, pte) * prototypePage, true
	case bitsOf(w.prototype, pte) == 0 && bitsOf(w.transition, pte) != 0:
		return bitsOf(w.transitionFrame, pte) * prototypePage, true
	}
	return 0, false
}

type viewSpan struct {
	firstPTE uint64
	pages    uint64
}

type extent struct {
	base, ptes, next uint64
	offset, bytes    uint64
	backed           uint64
}

func (r *Resolver) sectorUnit(controlAreaVA uint64) (uint64, error) {
	image, err := r.f.walk.imageFlag.Read(r.reader, controlAreaVA+r.f.walk.caFlagsAt)
	if err != nil {
		return 0, fmt.Errorf("subsection: control area at 0x%x: section flags: %w", controlAreaVA, err)
	}
	if image != 0 {
		return imageSector, nil
	}
	return dataSector, nil
}

func (r *Resolver) segmentBudget(controlAreaVA uint64) (uint64, bool, error) {
	w := r.f.walk
	if !w.haveSegment {
		return 0, false, nil
	}
	segment, err := w.segment.Read(r.reader, controlAreaVA)
	if err != nil {
		return 0, false, fmt.Errorf("subsection: control area at 0x%x: segment: %w", controlAreaVA, err)
	}
	if segment == 0 {
		return 0, false, fmt.Errorf("subsection: control area at 0x%x: segment is null", controlAreaVA)
	}
	total, err := w.totalPtes.Read(r.reader, segment)
	if err != nil {
		return 0, false, fmt.Errorf("subsection: segment at 0x%x: TotalNumberOfPtes: %w", segment, err)
	}
	return total, true, nil
}

func (r *Resolver) readExtent(at, controlAreaVA, unit uint64) (extent, error) {
	w := r.f.walk
	owner, err := w.owner.Read(r.reader, at)
	if err != nil {
		return extent{}, err
	}
	if owner != controlAreaVA {
		return extent{}, errNotOwned
	}
	var e extent
	var sector, high, full, end uint64
	for _, m := range []struct {
		f   symbols.IntField
		dst *uint64
	}{
		{w.base, &e.base}, {w.ptes, &e.ptes}, {w.next, &e.next}, {w.sector, &sector}, {w.fullSectors, &full},
	} {
		if *m.dst, err = m.f.Read(r.reader, at); err != nil {
			return extent{}, err
		}
	}
	if w.haveHigh {
		if high, err = w.sectorHigh.Read(r.reader, at+w.flagsAt); err != nil {
			return extent{}, err
		}
	}
	if w.haveEnd {
		if end, err = w.endOffset.Read(r.reader, at+w.flagsAt); err != nil {
			return extent{}, err
		}
	}
	if end >= unit {
		return extent{}, fmt.Errorf("%w: SectorEndOffset 0x%x is not below the 0x%x-byte sector", ErrExtent, end, unit)
	}
	e.offset = (sector | high<<32) * unit
	e.bytes = full*unit + end
	e.backed = (e.bytes + prototypePage - 1) / prototypePage
	if e.backed > e.ptes {
		return extent{}, fmt.Errorf("%w: %d file pages, %d prototype ptes", ErrExtent, e.backed, e.ptes)
	}
	if e.ptes > 0 && e.base > ^uint64(0)-(e.ptes-1)*r.f.mmpteSize {
		return extent{}, fmt.Errorf("%w: %d-entry array at 0x%x passes the end of the address space", ErrExtent, e.ptes, e.base)
	}
	return e, nil
}

// A view starts in the subsection whose array holds the VAD's first prototype
// pte and runs on through the following subsections for its page count.
func (r *Resolver) walkSubsections(startSubVA, controlAreaVA uint64, view *viewSpan) ([]AvailablePage, error) {
	if r.f.walk.err != nil {
		return nil, r.f.walk.err
	}
	unit, err := r.sectorUnit(controlAreaVA)
	if err != nil {
		return nil, err
	}
	budget, bounded, err := r.segmentBudget(controlAreaVA)
	if err != nil {
		return nil, err
	}
	limit := r.bounds.Effective().MaxListEntries
	seeking := view != nil
	var remaining uint64
	if view != nil {
		remaining = view.pages
	}
	var out []AvailablePage
	seen := map[uint64]bool{}
	for at, n := startSubVA, 0; at != 0; n++ {
		if seen[at] || n >= limit {
			return out, fmt.Errorf("%w at 0x%x: seen before or past %d subsections", ErrListCut, at, limit)
		}
		seen[at] = true
		e, err := r.readExtent(at, controlAreaVA, unit)
		switch {
		case errors.Is(err, errNotOwned) && n == 0:
			return nil, fmt.Errorf("%w: first subsection at 0x%x", ErrNoSubsections, at)
		case err != nil:
			return out, fmt.Errorf("%w at 0x%x: %w", ErrListCut, at, err)
		}
		if bounded {
			if e.backed > budget {
				return out, fmt.Errorf("%w: subsection at 0x%x needs %d, %d left", ErrBudget, at, e.backed, budget)
			}
			budget -= e.backed
		}
		first, last := uint64(0), e.ptes
		if seeking {
			switch {
			case view.firstPTE < e.base || (view.firstPTE-e.base)/r.f.mmpteSize >= e.ptes:
				last = 0
			case (view.firstPTE-e.base)%r.f.mmpteSize != 0:
				return nil, fmt.Errorf("subsection: first prototype pte 0x%x is not an entry of the array at 0x%x",
					view.firstPTE, e.base)
			default:
				first, seeking = (view.firstPTE-e.base)/r.f.mmpteSize, false
			}
		}
		if view != nil {
			last = min(last, first+remaining)
		}
		out = r.appendResident(out, e, first, min(last, e.backed))
		if view != nil && !seeking {
			if remaining -= last - first; remaining == 0 {
				return out, nil
			}
		}
		at = e.next
	}
	if seeking {
		return nil, fmt.Errorf("subsection: first prototype pte 0x%x is in no subsection of control area 0x%x",
			view.firstPTE, controlAreaVA)
	}
	return out, nil
}

func (r *Resolver) appendResident(out []AvailablePage, e extent, from, to uint64) []AvailablePage {
	size := r.f.mmpteSize
	for i := from; i < to; i++ {
		at := e.base + i*size
		pte, err := r.readMMPTE(at)
		if err != nil {
			// Every other entry in the page that holds this one fails the same way.
			if rest := (prototypePage - at%prototypePage) / size; rest > 1 {
				i += rest - 1
			}
			continue
		}
		frame, ok := r.f.walk.resident(pte)
		if !ok {
			continue
		}
		pos := i * prototypePage
		out = append(out, AvailablePage{PhysicalOffset: frame, FileOffset: e.offset + pos,
			PageSize: min(prototypePage, e.bytes-pos)})
	}
	return out
}
