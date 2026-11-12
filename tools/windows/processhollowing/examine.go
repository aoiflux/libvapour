package processhollowing

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/subsection"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

const pageSize = uint64(0x1000)

var (
	errNoPEB           = errors.New("no PEB")
	errSecure          = errors.New("secure process without a view at ImageBaseAddress")
	errTreeIncomplete  = errors.New("VAD tree incomplete")
	errImageBaseUnread = errors.New("ImageBaseAddress not read")
)

type skip struct {
	reason error
	cause  error
}

func (s *skip) Error() string {
	if s.cause == nil {
		return s.reason.Error()
	}
	return fmt.Sprintf("%v: %v", s.reason, s.cause)
}

func (s *skip) Unwrap() []error { return []error{s.reason, s.cause} }

type examiner struct {
	ctx      tools.Context
	l        layout
	ranges   memoryranges.Decoder
	files    memoryranges.FileNames
	named    bool
	sections *subsection.Resolver
	physical memory.MemoryReader

	unread         map[string]int
	sectionUnread  int
	sectionChecked int
	sectionNotPE   int
}

func newExaminer(ctx tools.Context) (*examiner, error) {
	l, err := resolveLayout(ctx)
	if err != nil {
		return nil, err
	}
	ranges, err := memoryranges.NewDecoder(ctx)
	if err != nil {
		return nil, err
	}
	e := &examiner{ctx: ctx, l: l, ranges: ranges, unread: map[string]int{}}
	if e.files, err = memoryranges.ResolveFileNames(ctx); err == nil {
		e.named = true
	} else {
		ctx.AddDiagnostic("%s: view file names not read, file rules not applied: %v", Name, err)
	}
	e.physical = ctx.PhysicalMemory()
	if e.physical != nil {
		if r, err := subsection.NewResolver(ctx.Memory, ctx.Symbols); err == nil {
			r.SetLimits(ctx.Limits)
			e.sections = r
		} else {
			ctx.AddDiagnostic("%s: section header pages not read, %s not applied: %v", Name, FindingHeaderDiffersFromFile, err)
		}
	}
	return e, nil
}

func (e *examiner) report() {
	if len(e.unread) > 0 {
		keys := make([]string, 0, len(e.unread))
		for k := range e.unread {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, e.unread[k]))
		}
		e.ctx.AddDiagnostic("%s: comparisons not made because a value did not read: %s", Name, strings.Join(parts, ", "))
	}
	if e.sections != nil {
		e.ctx.AddDiagnostic("%s: %d section header pages compared, %d not resident or not read, %d not a PE header",
			Name, e.sectionChecked, e.sectionUnread, e.sectionNotPE)
	}
}

type process struct {
	p           processlist.Process
	space       memory.MemoryReader
	imageBase   uint64
	sectionBase uint64
	ranges      []memoryranges.Mapping
	at          *memoryranges.Mapping
	rows        []Row
}

func (pr *process) add(f Finding, detail string) {
	r := Row{PID: pr.p.PID, Process: util.ReplaceInvalidUTF8(pr.p.Name), EPROCESS: pr.p.EPROCESS, Finding: f,
		ImageBaseAddress: pr.imageBase, SectionBaseAddress: pr.sectionBase, Detail: detail}
	if pr.at != nil {
		r.RangeStart, r.RangeEnd, r.RangeType = pr.at.Start, pr.at.End, pr.at.Type
		r.Protection, r.Path = pr.at.Protection, pr.at.Path
	}
	pr.rows = append(pr.rows, r)
}

func (e *examiner) pointer(r memory.MemoryReader, at uint64) (uint64, error) {
	return e.ctx.Symbols.ReadPointer(r, at)
}

func (e *examiner) examine(p processlist.Process) ([]Row, *skip) {
	ctx, l := e.ctx, e.l
	peb, err := e.pointer(ctx.Memory, p.EPROCESS+l.peb)
	if err != nil {
		return nil, &skip{reason: errors.New("PEB pointer not read"), cause: err}
	}
	if peb == 0 {
		return nil, &skip{reason: errNoPEB}
	}
	pr := &process{p: p}
	if pr.sectionBase, err = e.pointer(ctx.Memory, p.EPROCESS+l.sectionBase); err != nil {
		return nil, &skip{reason: errors.New("SectionBaseAddress not read"), cause: err}
	}
	if pr.space, err = ctx.ProcessSpace(p.DirectoryTableBase); err != nil {
		return nil, &skip{reason: errImageBaseUnread, cause: err}
	}
	if pr.imageBase, err = e.pointer(pr.space, peb+l.imageBase); err != nil {
		return nil, &skip{reason: errImageBaseUnread, cause: err}
	}
	if pr.ranges, err = e.ranges.Mappings(ctx, p); err != nil {
		return nil, &skip{reason: errors.New("VAD tree not read"), cause: err}
	}
	pr.at = holding(pr.ranges, pr.imageBase)
	if pr.at == nil {
		if e.incomplete(p, len(pr.ranges)) {
			return nil, &skip{reason: errTreeIncomplete}
		}
		if e.secure(p) {
			return nil, &skip{reason: errSecure}
		}
		pr.add(FindingImageBaseUnmapped, fmt.Sprintf("%d ranges listed", len(pr.ranges)))
	}
	view := e.rangeRules(pr)
	e.sectionBaseRules(pr)
	if view {
		ca := e.fileRules(pr)
		e.headerRules(pr, ca)
	}
	return pr.rows, nil
}

func holding(ranges []memoryranges.Mapping, address uint64) *memoryranges.Mapping {
	for i := range ranges {
		if ranges[i].Start <= address && address <= ranges[i].End {
			return &ranges[i]
		}
	}
	return nil
}

func (e *examiner) incomplete(p processlist.Process, listed int) bool {
	if !e.l.haveVadCount {
		return false
	}
	n, err := e.l.vadCount.Read(e.ctx.Memory, p.EPROCESS)
	return err == nil && n > uint64(listed)
}

func (e *examiner) secure(p processlist.Process) bool {
	if !e.l.secure.ok {
		return false
	}
	v, err := e.ctx.Symbols.ReadUint64(e.ctx.Memory, p.EPROCESS+e.l.secure.at)
	return err == nil && v != 0
}

type imageness int

const (
	notImage imageness = iota
	isImage
	imageUnknown
)

func (e *examiner) imageness(m memoryranges.Mapping) imageness {
	switch m.Type {
	case memoryranges.KindImage:
		return isImage
	case memoryranges.KindPrivate:
		return notImage
	}
	if !m.PrivateMemoryKnown || m.PrivateMemory || !e.named || !e.l.haveCAImage {
		return imageUnknown
	}
	mf, _ := e.files.Resolve(e.ctx, m.VadAddress)
	if mf.ControlArea == 0 {
		return imageUnknown
	}
	v, err := e.l.caImage.Read(e.ctx.Memory, mf.ControlArea)
	switch {
	case err != nil:
		return imageUnknown
	case v != 0:
		return isImage
	}
	return notImage
}

func (e *examiner) rangeRules(pr *process) bool {
	at := pr.at
	if at == nil {
		return false
	}
	starts := at.Start == pr.imageBase
	if !starts {
		pr.add(FindingImageBaseInsideRange, fmt.Sprintf("range starts 0x%x below ImageBaseAddress", pr.imageBase-at.Start))
	}
	kind := e.imageness(*at)
	if kind == notImage {
		pr.add(FindingImageBaseNotImage, fmt.Sprintf("%s range, %s", at.Type, at.Protection))
	}
	return starts && kind != notImage
}

func (e *examiner) sectionBaseRules(pr *process) {
	if pr.sectionBase == pr.imageBase {
		return
	}
	pr.add(FindingSectionBaseDiffers, "")
	for _, m := range pr.ranges {
		if m.Start == pr.sectionBase && e.imageness(m) != notImage {
			return
		}
	}
	if e.incomplete(pr.p, len(pr.ranges)) {
		e.unread["image view at SectionBaseAddress (VAD tree incomplete)"]++
		return
	}
	pr.add(FindingSectionBaseUnmapped, "")
}

func (e *examiner) fileName(fo uint64) (string, bool) {
	if !e.l.fileName.ok || fo == 0 {
		return "", false
	}
	s, err := util.ReadUnicodeString(e.ctx.Memory, fo+e.l.fileName.at, e.l.unicode, util.MaxUnicodeStringBytes)
	if err != nil {
		e.unread["ImageFilePointer FileName"]++
		return "", false
	}
	return s.Text(), true
}

func (e *examiner) auditName(p processlist.Process) (string, bool) {
	if !e.l.audit.ok || !e.l.auditName.ok {
		return "", false
	}
	info, err := e.pointer(e.ctx.Memory, p.EPROCESS+e.l.audit.at)
	if err != nil {
		e.unread["SeAuditProcessCreationInfo"]++
		return "", false
	}
	if info == 0 {
		return "", false
	}
	s, err := util.ReadUnicodeString(e.ctx.Memory, info+e.l.auditName.at, e.l.unicode, util.MaxUnicodeStringBytes)
	if err != nil {
		e.unread["SeAuditProcessCreationInfo name"]++
		return "", false
	}
	return s.Text(), true
}

func (e *examiner) fileRules(pr *process) uint64 {
	if !e.named {
		return 0
	}
	ctx, l, p := e.ctx, e.l, pr.p
	mf, _ := e.files.Resolve(ctx, pr.at.VadAddress)
	ca := mf.ControlArea
	viewName, haveView := mf.Path, mf.FileObject != 0 && !mf.NameUnreadable && mf.Path != ""

	var fo uint64
	if l.filePointer.ok {
		v, err := e.pointer(ctx.Memory, p.EPROCESS+l.filePointer.at)
		if err != nil {
			e.unread["ImageFilePointer"]++
		}
		fo = v
	}
	if fo != 0 && ca != 0 && l.fileSections.ok && l.imageSection.ok {
		image, err := e.imageSectionOf(fo)
		switch {
		case err != nil:
			e.unread["ImageFilePointer image section"]++
		case image != ca:
			pr.add(FindingControlAreaDiffers, fmt.Sprintf("ImageFilePointer 0x%x has image section 0x%x, the view has control area 0x%x", fo, image, ca))
		}
	}
	if l.sectionObject.ok && l.sectionCA.ok && ca != 0 {
		e.sectionObjectRule(pr, ca)
	}

	fpName, haveFP := e.fileName(fo)
	audit, haveAudit := e.auditName(p)
	names := []namedPath{}
	if haveView {
		names = append(names, namedPath{"view file", viewName})
	}
	if haveFP && fpName != "" {
		names = append(names, namedPath{"ImageFilePointer", fpName})
	}
	if haveAudit && audit != "" {
		names = append(names, namedPath{"SeAuditProcessCreationInfo", audit})
	}
	if detail, differ := lastComponentsDiffer(names); differ {
		pr.add(FindingFileNameDiffers, detail)
	}
	reference := ""
	switch {
	case haveAudit && audit != "":
		reference = audit
	case haveView:
		reference = viewName
	}
	if reference != "" && l.nameCapacity > 0 {
		if !imageFileNameMatches(p.Name, lastComponent(reference), l.nameCapacity) {
			pr.add(FindingImageFileNameDiffers, fmt.Sprintf("ImageFileName %q, file %q", util.ReplaceInvalidUTF8(p.Name), lastComponent(reference)))
		}
	}
	return ca
}

func (e *examiner) imageSectionOf(fo uint64) (uint64, error) {
	sop, err := e.pointer(e.ctx.Memory, fo+e.l.fileSections.at)
	if err != nil {
		return 0, err
	}
	if sop == 0 {
		return 0, nil
	}
	return e.pointer(e.ctx.Memory, sop+e.l.imageSection.at)
}

func (e *examiner) sectionObjectRule(pr *process, ca uint64) {
	s, err := e.pointer(e.ctx.Memory, pr.p.EPROCESS+e.l.sectionObject.at)
	if err != nil {
		e.unread["SectionObject"]++
		return
	}
	if s == 0 {
		return
	}
	held, err := e.pointer(e.ctx.Memory, s+e.l.sectionCA.at)
	if err != nil {
		e.unread["SectionObject control area"]++
		return
	}
	if held != ca {
		pr.add(FindingSectionObjectDiffers, fmt.Sprintf("SectionObject 0x%x holds control area 0x%x, the view has 0x%x", s, held, ca))
	}
}

func (e *examiner) headerRules(pr *process, ca uint64) {
	mapped, err := pr.space.ReadAt(pr.imageBase, pageSize)
	if err != nil || uint64(len(mapped)) < pageSize {
		e.unread["header page at ImageBaseAddress"]++
		return
	}
	h, err := pe.ParseHeaders(mapped)
	if err != nil {
		e.mappedNotPE(pr, ca, err)
		return
	}
	if h.Optional.ImageBase != pr.imageBase {
		pr.add(FindingHeaderImageBaseDiffers, fmt.Sprintf("header ImageBase 0x%x", h.Optional.ImageBase))
	}
	if size, span := pageAligned(uint64(h.Optional.SizeOfImage)), pr.at.End-pr.at.Start+1; size > span {
		pr.add(FindingImageSizeExceedsRange, fmt.Sprintf("SizeOfImage 0x%x, range 0x%x", h.Optional.SizeOfImage, span))
	}
	if e.sections == nil || ca == 0 {
		return
	}
	file, ok := e.sectionHeaderPage(ca)
	if !ok {
		e.sectionUnread++
		return
	}
	differ, err := headerDifferences(mapped, file)
	if err != nil {
		e.sectionNotPE++
		return
	}
	e.sectionChecked++
	if len(differ) > 0 {
		pr.add(FindingHeaderDiffersFromFile, strings.Join(differ, ", "))
	}
}

// A header page that is not PE in the view and not PE in the section's own
// page is the capture's copy of one frame (measured: all zero), not a change
// the process made.
func (e *examiner) mappedNotPE(pr *process, ca uint64, why error) {
	if e.sections != nil && ca != 0 {
		if file, ok := e.sectionHeaderPage(ca); ok {
			if _, err := pe.ParseHeaders(file); err == nil {
				pr.add(FindingHeaderNotPE, why.Error())
				return
			}
		}
	}
	e.unread["header page at ImageBaseAddress not PE, section header page not PE or not resident"]++
}

func pageAligned(n uint64) uint64 { return (n + pageSize - 1) &^ (pageSize - 1) }

func (e *examiner) sectionHeaderPage(ca uint64) ([]byte, bool) {
	pages, _ := e.sections.AvailablePages(ca)
	for _, pg := range pages {
		if pg.FileOffset != 0 {
			continue
		}
		size := min(pg.PageSize, pageSize)
		b, err := e.physical.ReadAt(pg.PhysicalOffset, size)
		if err != nil || uint64(len(b)) < size {
			return nil, false
		}
		return b, true
	}
	return nil, false
}
