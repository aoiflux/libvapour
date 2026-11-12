// A stream's bytes can sit in three caches: the data and image section
// control areas give physical pages through their subsections, the shared
// cache map gives kernel views. Each cache becomes its own artefact (S19).
package filedump

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/subsection"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/handlelist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.file.dump"

const (
	cacheDataSection  = "DataSectionObject"
	cacheImageSection = "ImageSectionObject"
	cacheSharedMap    = "SharedCacheMap"
)

const fileObjectType = 5

const (
	deviceCDROM             = 0x02
	deviceCDROMFileSystem   = 0x03
	deviceDisk              = 0x07
	deviceDiskFileSystem    = 0x08
	deviceNetworkFileSystem = 0x14
	deviceVirtualDisk       = 0x24
	deviceDVD               = 0x33
	deviceDFSFileSystem     = 0x35
	deviceDFSVolume         = 0x36
)

var fileDevices = map[uint64]bool{
	deviceCDROM: true, deviceCDROMFileSystem: true, deviceDisk: true, deviceDiskFileSystem: true,
	deviceNetworkFileSystem: true, deviceVirtualDisk: true, deviceDVD: true, deviceDFSFileSystem: true,
	deviceDFSVolume: true,
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Carve cached file contents from _FILE_OBJECT section caches",
		},
		RunAny,
	)
}

var (
	ErrNoOutputDir   = errors.New("filedump: no output directory (set " + tools.OptionOutputDir + ")")
	ErrLayout        = errors.New("filedump: symbol table lacks a member the file checks need")
	ErrFileUnread    = errors.New("filedump: file object does not read")
	ErrNotFileObject = errors.New("filedump: Type or Size is not a file object's")
	ErrDeviceUnread  = errors.New("filedump: device object does not read")
	ErrNoFiles       = errors.New("filedump: device type holds no files")
	ErrSegment       = errors.New("filedump: segment does not point back to the control area")
	ErrSectionFlags  = errors.New("filedump: section flags do not fit the pointer the control area came from")
	ErrOtherStream   = errors.New("filedump: file pointer does not name a file object of this stream")
	ErrCacheMapNode  = errors.New("filedump: node type or size is not a shared cache map's")
	ErrCacheMapSizes = errors.New("filedump: shared cache map sizes break 0 <= FileSize <= SectionSize")
)

type Artifact struct {
	FileObject         uint64
	MemoryObject       uint64
	FileObjectPhysical bool
	Cache              string
	BeingDeleted       bool
	Name               string
	NameUnreadable     bool
	PID                uint64
	Process            string

	FileName      string
	FileSize      uint64
	FileSizeKnown bool
	Size          uint64
	Captured      uint64
	Gaps          extract.GapMap
	Withheld      extract.GapMap
	Pages         int

	Skipped string
}

func (a Artifact) Written() bool { return a.Skipped == "" }

func (a Artifact) Complete() bool { return a.Written() && len(a.Gaps) == 0 && len(a.Withheld) == 0 }

func RunAny(ctx tools.Context) (any, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	sel, err := readSelection(ctx)
	if err != nil {
		return nil, err
	}
	return run(ctx, sel)
}

func Run(ctx tools.Context) ([]Artifact, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return run(ctx, selection{})
}

func checkContext(ctx tools.Context) error {
	if err := ctx.Validate(); err != nil {
		return err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	return nil
}

type fileOwner struct {
	fileObject uint64
	physical   bool
	addressed  bool
	pid        uint64
	process    string
}

func (o fileOwner) reader(ctx tools.Context) memory.MemoryReader {
	if o.physical {
		return ctx.PhysicalMemory()
	}
	return ctx.Memory
}

func (o fileOwner) option() string {
	if o.physical {
		return OptionPhysAddr
	}
	return OptionVirtAddr
}

func (o fileOwner) artifactName(ctx tools.Context, object uint64, view, label string) string {
	scope := extract.Kernel
	if o.physical {
		scope = extract.Physical
	}
	return extract.Name{Kind: extract.KindFile, Scope: scope, Width: ctx.Symbols.PointerSize(),
		Addresses: []uint64{o.fileObject, object}, Labels: []string{view, label}, Ext: extract.ExtBytes}.String()
}

type runState struct {
	ctx       tools.Context
	f         fields
	outputDir string
	resolver  *subsection.Resolver
	cache     *cacheReader
	namer     *scan.ObjectNamer
	rejected  map[string]int
	streams   map[uint64]uint64
	cut       error
}

func run(ctx tools.Context, sel selection) ([]Artifact, error) {
	outputDir, ok := ctx.OutputDir()
	if !ok {
		return nil, ErrNoOutputDir
	}
	f, err := resolveFields(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	resolver, err := subsection.NewResolver(ctx.Memory, ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: subsection resolver: %w", Name, err)
	}
	resolver.SetLimits(ctx.Limits)
	st := &runState{ctx: ctx, f: f, outputDir: outputDir, resolver: resolver, cache: newCacheReader(ctx),
		rejected: map[string]int{}, streams: map[uint64]uint64{}}
	if st.cache.err != nil {
		ctx.AddDiagnostic("%s: shared cache maps not read: %v", Name, st.cache.err)
	}
	if n, ok := scan.NewObjectNamer(ctx.Symbols); ok {
		st.namer = &n
	}
	if sel.pattern != nil && (st.namer == nil || !f.hasObjectHeaderBody || f.fileObjectDeviceObject == 0) {
		return nil, fmt.Errorf("%s: %s: %w", Name, OptionFilter, ErrFilterNeedsDeviceNames)
	}

	var owners []fileOwner
	if sel.addressed() {
		owners = sel.owners(ctx)
	} else {
		owners = fileObjects(ctx, f, resolver)
	}

	out := make([]Artifact, 0, 64)
	seen := map[ownerKey]bool{}
	var tally filterTally
	for _, owner := range owners {
		key := ownerKey{address: owner.fileObject, physical: owner.physical}
		if seen[key] {
			continue
		}
		seen[key] = true
		src := owner.reader(ctx)
		if sel.pattern != nil {
			tally.tested++
			full, ok := fullName(ctx, f, st.namer, src, owner.fileObject)
			if !ok {
				tally.unnamed++
				continue
			}
			if !sel.pattern.MatchString(full) {
				continue
			}
			tally.kept++
		}
		out = append(out, st.carveFileObject(owner, src)...)
	}
	sel.reportFilter(ctx, tally)
	st.reportRejected()
	if st.cut != nil && ctx.StrictMode() {
		return out, fmt.Errorf("%s: %w", Name, st.cut)
	}
	return out, nil
}

func (st *runState) reject(owner fileOwner, what string, err error) {
	if owner.addressed {
		st.ctx.AddDiagnostic("%s: %s 0x%x not carved: %s: %v", Name, owner.option(), owner.fileObject, what, err)
		return
	}
	st.rejected[what+": "+rootReason(err)]++
}

func rootReason(err error) string {
	for _, s := range []error{ErrFileUnread, ErrNotFileObject, ErrDeviceUnread, ErrNoFiles, ErrSegment, ErrSectionFlags,
		ErrOtherStream, ErrCacheMapNode, ErrCacheMapSizes} {
		if errors.Is(err, s) {
			return s.Error()
		}
	}
	return err.Error()
}

func (st *runState) reportRejected() {
	keys := make([]string, 0, len(st.rejected))
	for k := range st.rejected {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		st.ctx.AddDiagnostic("%s: %d not carved: %s", Name, st.rejected[k], k)
	}
}

func (st *runState) carveFileObject(owner fileOwner, src memory.MemoryReader) []Artifact {
	ctx, f := st.ctx, st.f
	if err := checkFileObject(ctx, f, src, owner.fileObject); err != nil {
		st.reject(owner, "file object", err)
		return nil
	}
	sop, err := f.foSOP.Read(src, owner.fileObject)
	if err != nil {
		st.reject(owner, "file object", fmt.Errorf("%w: SectionObjectPointer: %v", ErrFileUnread, err))
		return nil
	}
	if sop == 0 {
		if owner.addressed {
			ctx.AddDiagnostic("%s: %s 0x%x not carved: no SectionObjectPointer, so nothing cached", Name,
				owner.option(), owner.fileObject)
		}
		return nil
	}
	if first, dup := st.streams[sop]; dup {
		if owner.addressed {
			ctx.AddDiagnostic("%s: %s 0x%x is a stream already carved through file object 0x%x", Name,
				owner.option(), owner.fileObject, first)
		}
		return nil
	}
	st.streams[sop] = owner.fileObject

	name, readable := readUnicodeString(ctx, f, src, owner.fileObject+f.fileObjectFileName)
	label := nameWithDevice(ctx, f, st.namer, src, owner.fileObject, name, readable)
	switch {
	case label == "":
		ctx.AddDiagnostic("%s: file object at 0x%x: FileName and device name do not read, artefacts carry no name",
			Name, owner.fileObject)
	case !readable:
		ctx.AddDiagnostic("%s: file object at 0x%x: FileName does not read, artefacts named after the device %s",
			Name, owner.fileObject, label)
	}

	row := func(cache string, object uint64, view string) Artifact {
		return Artifact{FileObject: owner.fileObject, MemoryObject: object, FileObjectPhysical: owner.physical,
			Cache: cache, Name: name, NameUnreadable: !readable, PID: owner.pid, Process: owner.process,
			FileName: owner.artifactName(ctx, object, view, label)}
	}

	pointers := map[string]uint64{}
	for cache, member := range map[string]symbols.IntField{
		cacheDataSection: f.sopData, cacheImageSection: f.sopImage, cacheSharedMap: f.sopCache,
	} {
		if v, err := member.Read(ctx.Memory, sop); err == nil {
			pointers[cache] = v
		} else {
			ctx.AddDiagnostic("%s: section object pointers at 0x%x: %s: %v", Name, sop, cache, err)
		}
	}

	size, sizeKnown := uint64(0), false
	var out []Artifact
	var mapRow *Artifact
	if scm := pointers[cacheSharedMap]; scm != 0 && st.cache.err == nil {
		art := row(cacheSharedMap, scm, extract.ViewCache)
		fileSize, err := st.cache.check(f, scm, sop)
		if err != nil {
			art.Skipped = err.Error()
			st.reject(owner, "shared cache map", err)
		} else {
			size, sizeKnown = fileSize, true
		}
		mapRow = &art
	}
	if !sizeKnown {
		size, sizeKnown = fcbFileSize(ctx, f, src, owner.fileObject)
	}

	for _, c := range []struct {
		cache, view string
		image       bool
	}{
		{cacheDataSection, extract.ViewData, false},
		{cacheImageSection, extract.ViewImage, true},
	} {
		ca := pointers[c.cache]
		if ca == 0 {
			continue
		}
		art := row(c.cache, ca, c.view)
		art.FileSize, art.FileSizeKnown = size, sizeKnown
		deleting, err := checkControlArea(ctx, f, ca, c.image, sop)
		art.BeingDeleted = deleting
		if err != nil {
			art.Skipped = err.Error()
			st.reject(owner, "control area", err)
		} else {
			st.carveSection(&art)
		}
		out = append(out, art)
	}
	if mapRow != nil {
		mapRow.FileSize, mapRow.FileSizeKnown = size, sizeKnown
		if mapRow.Skipped == "" {
			st.carveCacheMap(mapRow, pointers[cacheSharedMap])
		}
		out = append(out, *mapRow)
	}
	return out
}

func (st *runState) carveSection(art *Artifact) {
	ctx := st.ctx
	physical := ctx.PhysicalMemory()
	if physical == nil {
		art.Skipped = "no physical memory layer, and control-area pages are physical"
		ctx.AddDiagnostic("%s: %s at 0x%x: %s", Name, art.Cache, art.MemoryObject, art.Skipped)
		return
	}
	pages, err := st.resolver.AvailablePages(art.MemoryObject)
	if err != nil {
		if len(pages) == 0 {
			art.Skipped = err.Error()
			ctx.AddDiagnostic("%s: %s at 0x%x: %v", Name, art.Cache, art.MemoryObject, err)
			return
		}
		st.cut = err
		ctx.AddDiagnostic("%s: %s at 0x%x: pages after the cut are not carved: %v", Name, art.Cache,
			art.MemoryObject, err)
	}
	chunks := make([]chunk, 0, len(pages))
	for _, p := range pages {
		chunks = append(chunks, chunk{source: p.PhysicalOffset, fileOffset: p.FileOffset, size: p.PageSize})
	}
	writeChunks(ctx, st.outputDir, physical, chunks, art)
}

func (st *runState) carveCacheMap(art *Artifact, scm uint64) {
	views := st.cache.views(scm, art.FileSize)
	chunks := make([]chunk, 0, len(views))
	for _, v := range views {
		chunks = append(chunks, chunk{source: v.address, fileOffset: v.offset, size: v.size})
	}
	writeChunks(st.ctx, st.outputDir, st.ctx.Memory, chunks, art)
}

// VADs find mapped files whose handle is closed; handles find open files
// never mapped. Process order decides which process a shared stream is
// credited to.
func fileObjects(ctx tools.Context, f fields, resolver *subsection.Resolver) []fileOwner {
	procs, err := processlist.Run(ctx)
	if err != nil {
		ctx.AddDiagnostic("%s: process list: %v", Name, err)
		return nil
	}
	pids := ctx.PIDs()
	byHandle := handleFileObjects(ctx, f)
	var out []fileOwner
	for _, proc := range procs {
		if !pids.Keep(proc.PID) {
			continue
		}
		for _, fo := range byHandle[proc.PID] {
			out = append(out, fileOwner{fileObject: fo, pid: proc.PID, process: proc.Name})
		}
		vads, err := memoryranges.ProcessVADs(ctx, proc)
		if err != nil {
			ctx.AddDiagnostic("%s: pid %d: VADs: %v", Name, proc.PID, err)
			continue
		}
		for _, vad := range vads {
			// A short VAD has no Subsection member to read.
			if !vad.IsMMVAD() {
				continue
			}
			ca, _, err := resolver.ControlAreaFromVAD(vad.Base)
			if err != nil || ca == 0 {
				continue
			}
			raw, err := f.caFilePointer.Read(ctx.Memory, ca)
			if fo := raw &^ f.refMask; err == nil && fo != 0 {
				out = append(out, fileOwner{fileObject: fo, pid: proc.PID, process: proc.Name})
			}
		}
	}
	return out
}

// A handle's Object is the object header; the body follows at Body.
func handleFileObjects(ctx tools.Context, f fields) map[uint64][]uint64 {
	if !f.hasObjectHeaderBody {
		ctx.AddDiagnostic("%s: handle tables not read: no _OBJECT_HEADER.Body in the symbols", Name)
		return nil
	}
	entries, err := handlelist.Run(ctx)
	if err != nil {
		ctx.AddDiagnostic("%s: handle tables not read: %v", Name, err)
		return nil
	}
	out := map[uint64][]uint64{}
	for _, h := range entries {
		if strings.EqualFold(h.TypeName, "File") && h.Object != 0 {
			out[h.PID] = append(out[h.PID], h.Object+f.objectHeaderBody)
		}
	}
	return out
}

type chunk struct {
	source     uint64
	fileOffset uint64
	size       uint64
}

// Offsets come from the image. Bytes past the file size are not the file's,
// and anything past the dump ceiling is withheld rather than written.
func writeChunks(ctx tools.Context, outputDir string, reader memory.MemoryReader, chunks []chunk, art *Artifact) {
	ceiling := min(ctx.DumpLimit(), uint64(math.MaxInt64))
	fileEnd := uint64(math.MaxUint64)
	if art.FileSizeKnown {
		fileEnd = art.FileSize
	}
	var withheld extract.Coverage
	kept := make([]chunk, 0, len(chunks))
	for _, c := range chunks {
		if c.size == 0 || c.fileOffset >= fileEnd {
			continue
		}
		c.size = min(c.size, fileEnd-c.fileOffset)
		if c.fileOffset >= ceiling {
			withheld.Add(c.fileOffset, c.size)
			continue
		}
		if c.size > ceiling-c.fileOffset {
			withheld.Add(ceiling, c.size-(ceiling-c.fileOffset))
			c.size = ceiling - c.fileOffset
		}
		kept = append(kept, c)
	}
	if art.FileSizeKnown && art.FileSize > ceiling {
		withheld.Add(ceiling, art.FileSize-ceiling)
	}
	if held := withheld.Covered(); len(held) > 0 {
		art.Withheld = held
		ctx.AddDiagnostic("%s: %s at 0x%x: bytes from 0x%x lie past the %d-byte dump ceiling and are not written "+
			"(raise %s)", Name, art.Cache, art.MemoryObject, held[0].Start, ceiling, tools.OptionMaxDumpSize)
	}
	art.Pages = len(kept)
	if len(kept) == 0 {
		art.Skipped = "nothing resident"
		return
	}

	file, err := extract.CreateNew(outputDir, art.FileName)
	if err != nil {
		art.Skipped = err.Error()
		ctx.AddDiagnostic("%s: %s at 0x%x: %v", Name, art.Cache, art.MemoryObject, err)
		return
	}
	var covered extract.Coverage
	total := uint64(0)
	for _, c := range kept {
		data, gaps := extract.ReadPadded(reader, c.source, c.size)
		if _, err := file.WriteAt(data, int64(c.fileOffset)); err != nil {
			file.Close()
			extract.RemoveArtifact(outputDir, art.FileName)
			art.Skipped = err.Error()
			ctx.AddDiagnostic("%s: %s at 0x%x: %v", Name, art.Cache, art.MemoryObject, err)
			return
		}
		total = max(total, c.fileOffset+c.size)
		addCovered(&covered, c, gaps)
	}
	if art.FileSizeKnown {
		total = min(art.FileSize, ceiling)
	}
	err = file.Truncate(int64(total))
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		extract.RemoveArtifact(outputDir, art.FileName)
		art.Skipped = err.Error()
		ctx.AddDiagnostic("%s: %s at 0x%x: %v", Name, art.Cache, art.MemoryObject, err)
		return
	}
	if covered.Bytes() == 0 {
		extract.RemoveArtifact(outputDir, art.FileName)
		art.Skipped = "no cached page reads"
		return
	}
	art.Size = total
	art.Captured = covered.Bytes()
	art.Gaps = covered.Holes(total)
}

func addCovered(covered *extract.Coverage, c chunk, gaps extract.GapMap) {
	cursor := c.source
	for _, g := range gaps {
		if g.Start > cursor {
			covered.Add(c.fileOffset+(cursor-c.source), g.Start-cursor)
		}
		cursor = max(cursor, g.End())
	}
	if stop := c.source + c.size; cursor < stop {
		covered.Add(c.fileOffset+(cursor-c.source), stop-cursor)
	}
}

type fields struct {
	fileObjectFileName     uint64
	fileObjectDeviceObject uint64
	fileObjectSectionPtr   uint64

	objectHeaderBody    uint64
	hasObjectHeaderBody bool

	unicodeLength uint64
	unicodeBuffer uint64

	foType, foSize, foDevice, foSOP symbols.IntField
	foStructSize                    uint64
	foFsContext, fcbFileSize        symbols.IntField
	haveFileSize                    bool
	deviceType                      symbols.IntField

	sopData, sopImage, sopCache symbols.IntField

	caSegment, caFilePointer symbols.IntField
	caFlagsAt                uint64
	flagImage, flagFile      symbols.IntField
	flagDeleting             symbols.IntField
	segControlArea           symbols.IntField

	refMask uint64
}

func resolveFields(table symbols.SymbolTable) (fields, error) {
	var f fields
	var err error
	need := func(dst *symbols.IntField, typeName, member string) {
		if err != nil {
			return
		}
		var e error
		if *dst, e = symbols.ResolveIntField(table, typeName, member); e != nil {
			err = fmt.Errorf("%w: %v", ErrLayout, e)
		}
	}
	need(&f.foType, "_FILE_OBJECT", "Type")
	need(&f.foSize, "_FILE_OBJECT", "Size")
	need(&f.foDevice, "_FILE_OBJECT", "DeviceObject")
	need(&f.foSOP, "_FILE_OBJECT", "SectionObjectPointer")
	need(&f.deviceType, "_DEVICE_OBJECT", "DeviceType")
	need(&f.sopData, "_SECTION_OBJECT_POINTERS", "DataSectionObject")
	need(&f.sopImage, "_SECTION_OBJECT_POINTERS", "ImageSectionObject")
	need(&f.sopCache, "_SECTION_OBJECT_POINTERS", "SharedCacheMap")
	need(&f.caSegment, "_CONTROL_AREA", "Segment")
	need(&f.caFilePointer, "_CONTROL_AREA", "FilePointer")
	need(&f.flagImage, "_MMSECTION_FLAGS", "Image")
	need(&f.flagFile, "_MMSECTION_FLAGS", "File")
	need(&f.flagDeleting, "_MMSECTION_FLAGS", "BeingDeleted")
	need(&f.segControlArea, "_SEGMENT", "ControlArea")
	var refCount symbols.IntField
	need(&refCount, "_EX_FAST_REF", "RefCnt")
	if err != nil {
		return f, err
	}
	f.refMask = uint64(1)<<refCount.BitLength - 1

	offset := func(typeName, member string) uint64 {
		if err != nil {
			return 0
		}
		fld, e := table.Field(typeName, member)
		if e != nil {
			err = fmt.Errorf("%w: %v", ErrLayout, e)
		}
		return fld.Offset
	}
	f.fileObjectFileName = offset("_FILE_OBJECT", "FileName")
	f.fileObjectDeviceObject = offset("_FILE_OBJECT", "DeviceObject")
	f.fileObjectSectionPtr = offset("_FILE_OBJECT", "SectionObjectPointer")
	f.caFlagsAt = offset("_CONTROL_AREA", "u")
	f.unicodeLength = offset("_UNICODE_STRING", "Length")
	f.unicodeBuffer = offset("_UNICODE_STRING", "Buffer")
	if err != nil {
		return f, err
	}
	st, serr := table.Struct("_FILE_OBJECT")
	if serr != nil || st.Size == 0 {
		return f, fmt.Errorf("%w: size of _FILE_OBJECT", ErrLayout)
	}
	f.foStructSize = st.Size

	if fld, e := table.Field("_OBJECT_HEADER", "Body"); e == nil {
		f.objectHeaderBody, f.hasObjectHeaderBody = fld.Offset, true
	}
	fsc, e1 := symbols.ResolveIntField(table, "_FILE_OBJECT", "FsContext")
	size, e2 := symbols.ResolveIntField(table, "_FSRTL_ADVANCED_FCB_HEADER", "FileSize")
	if e1 == nil && e2 == nil {
		f.foFsContext, f.fcbFileSize, f.haveFileSize = fsc, size, true
	}
	return f, nil
}

func checkFileObject(ctx tools.Context, f fields, src memory.MemoryReader, fo uint64) error {
	kind, err := f.foType.Read(src, fo)
	if err != nil {
		return fmt.Errorf("%w: Type: %v", ErrFileUnread, err)
	}
	size, err := f.foSize.Read(src, fo)
	if err != nil {
		return fmt.Errorf("%w: Size: %v", ErrFileUnread, err)
	}
	if kind != fileObjectType || size != f.foStructSize {
		return fmt.Errorf("%w: Type %d, Size %d", ErrNotFileObject, kind, size)
	}
	device, err := f.foDevice.Read(src, fo)
	if err != nil || device == 0 {
		return fmt.Errorf("%w: DeviceObject 0x%x", ErrDeviceUnread, device)
	}
	deviceType, err := f.deviceType.Read(ctx.Memory, device)
	if err != nil {
		return fmt.Errorf("%w: device at 0x%x: %v", ErrDeviceUnread, device, err)
	}
	if !fileDevices[deviceType] {
		return fmt.Errorf("%w: DeviceType 0x%x", ErrNoFiles, deviceType)
	}
	return nil
}

func streamOf(ctx tools.Context, f fields, ref uint64) uint64 {
	fo := ref &^ f.refMask
	if fo == 0 {
		return 0
	}
	sop, err := f.foSOP.Read(ctx.Memory, fo)
	if err != nil {
		return 0
	}
	return sop
}

// A control area being deleted is still carved: its pages may still be the
// file's, and the row's flag leaves the judgement to the examiner. FilePointer
// is null only where BeingDeleted is set (S19 M3), so a null pointer is taken
// as the delete's own clearing; a pointer to another stream still refuses it.
func checkControlArea(ctx tools.Context, f fields, ca uint64, image bool, sop uint64) (bool, error) {
	segment, err := f.caSegment.Read(ctx.Memory, ca)
	if err != nil {
		return false, fmt.Errorf("%w: Segment: %v", ErrSegment, err)
	}
	if segment == 0 {
		return false, fmt.Errorf("%w: Segment is null", ErrSegment)
	}
	back, err := f.segControlArea.Read(ctx.Memory, segment)
	if err != nil || back != ca {
		return false, fmt.Errorf("%w: segment at 0x%x names 0x%x", ErrSegment, segment, back)
	}
	flags := ca + f.caFlagsAt
	isImage, err1 := f.flagImage.Read(ctx.Memory, flags)
	isFile, err2 := f.flagFile.Read(ctx.Memory, flags)
	deleting, err3 := f.flagDeleting.Read(ctx.Memory, flags)
	if err := errors.Join(err1, err2, err3); err != nil {
		return false, fmt.Errorf("%w: %v", ErrSectionFlags, err)
	}
	if isFile == 0 || (isImage != 0) != image {
		return false, fmt.Errorf("%w: File %d, Image %d", ErrSectionFlags, isFile, isImage)
	}
	ref, err := f.caFilePointer.Read(ctx.Memory, ca)
	if err != nil {
		return deleting != 0, fmt.Errorf("%w: FilePointer: %v", ErrOtherStream, err)
	}
	cleared := deleting != 0 && ref&^f.refMask == 0
	if got := streamOf(ctx, f, ref); got != sop && !cleared {
		return deleting != 0, fmt.Errorf("%w: FilePointer 0x%x", ErrOtherStream, ref)
	}
	return deleting != 0, nil
}

func fcbFileSize(ctx tools.Context, f fields, src memory.MemoryReader, fo uint64) (uint64, bool) {
	if !f.haveFileSize {
		return 0, false
	}
	header, err := f.foFsContext.Read(src, fo)
	if err != nil || header == 0 {
		return 0, false
	}
	// An empty file has no cached page, so a size of 0 bounds nothing (S19 O9).
	size, err := f.fcbFileSize.Read(ctx.Memory, header)
	if err != nil || int64(size) <= 0 {
		return 0, false
	}
	return size, true
}

// Length is 16 bits; a zero Length is a real empty name.
func readUnicodeString(ctx tools.Context, f fields, src memory.MemoryReader, addr uint64) (string, bool) {
	raw, err := ctx.Symbols.ReadUint32(src, addr+f.unicodeLength)
	if err != nil {
		return "", false
	}
	length := uint64(raw & 0xFFFF)
	if length == 0 {
		return "", true
	}
	buffer, err := ctx.Symbols.ReadPointer(src, addr+f.unicodeBuffer)
	if err != nil || buffer == 0 {
		return "", false
	}
	text, err := ctx.Memory.ReadAt(buffer, length)
	if err != nil {
		return "", false
	}
	return util.DecodeUTF16LEZ(text), true
}

func nameWithDevice(ctx tools.Context, f fields, namer *scan.ObjectNamer, src memory.MemoryReader, fo uint64, name string, readable bool) string {
	if !readable {
		name = ""
	}
	if strings.ContainsAny(name, `\/`) {
		return name
	}
	if namer == nil || !f.hasObjectHeaderBody {
		return name
	}
	device, err := ctx.Symbols.ReadPointer(src, fo+f.fileObjectDeviceObject)
	if err != nil || device < f.objectHeaderBody {
		return name
	}
	if dev := namer.Name(ctx.Memory, ctx.Memory, ctx.Memory, device-f.objectHeaderBody); dev != "" {
		return `\Device\` + dev + name
	}
	return name
}
