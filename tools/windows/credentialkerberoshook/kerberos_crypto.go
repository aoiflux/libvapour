// Kerberos in lsass.exe calls each encryption type's routines through the
// entries that cryptdll.dll keeps in one table. A routine pointer that leaves
// the module that registered its entry is the mark of an in-memory hook (S23).
package credentialkerberoshook

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/subsection"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.credential.check_kerberos_hook"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the Kerberos encryption types registered in lsass.exe and flag any routine pointer outside the module that registered it",
		},
		RunAny,
	)
}

const (
	lsassImage    = "lsass.exe"
	tableModule   = "cryptdll.dll"
	pointerLength = 8
)

var (
	ErrPointerSize     = errors.New("credentialkerberoshook: the entry layout is measured for 8-byte pointers only")
	ErrNoLSASS         = errors.New("credentialkerberoshook: no lsass.exe in the process list")
	ErrMappingsUnread  = errors.New("credentialkerberoshook: address-space mappings do not read")
	ErrNoTableModule   = errors.New("credentialkerberoshook: cryptdll.dll is not mapped")
	ErrTableNotFound   = errors.New("credentialkerberoshook: crypto-system table not located")
	ErrCountUnread     = errors.New("credentialkerberoshook: crypto-system count does not read")
	ErrCountRange      = errors.New("credentialkerberoshook: crypto-system count above the registration limit")
	ErrEntryUnread     = errors.New("credentialkerberoshook: crypto-system entry does not read")
	ErrHeadOutsideView = errors.New("credentialkerberoshook: table or count outside the cryptdll.dll view")
)

type Routine struct {
	Slot       Slot
	Address    uint64
	Module     string
	Kind       string
	Redirected bool
}

type Row struct {
	PID                uint64
	Process            string
	EPROCESS           uint64
	TableAddress       uint64
	TableSource        Source
	Index              int
	EntryAddress       uint64
	EncryptionType     int32
	EncryptionTypeName string
	Name               string
	NameUnreadable     bool
	RegisteredBy       string
	Routines           []Routine
	Redirected         bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	if ctx.Symbols.PointerSize() != pointerLength {
		return nil, fmt.Errorf("%s: %w", Name, ErrPointerSize)
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, err
	}
	decoder, err := memoryranges.NewDecoder(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", Name, ErrMappingsUnread, err)
	}
	r := run{ctx: ctx, decoder: decoder}
	if res, err := subsection.NewResolver(ctx.Memory, ctx.Symbols); err == nil {
		res.SetLimits(ctx.Limits)
		r.resolver = res
	}

	pids := ctx.PIDs()
	var rows []Row
	found := false
	for _, p := range procs {
		if !strings.EqualFold(p.Name, lsassImage) || !pids.Keep(p.PID) {
			continue
		}
		found = true
		got, err := r.process(p)
		if err != nil {
			if ctx.StrictMode() {
				return nil, err
			}
			ctx.AddDiagnostic("%v", err)
		}
		rows = append(rows, got...)
	}
	if !found && pids.All() {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: %w", Name, ErrNoLSASS)
		}
		ctx.AddDiagnostic("%s: %v", Name, ErrNoLSASS)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		if a.EPROCESS != b.EPROCESS {
			return a.EPROCESS < b.EPROCESS
		}
		return a.Index < b.Index
	})
	return rows, nil
}

type run struct {
	ctx      tools.Context
	decoder  memoryranges.Decoder
	resolver *subsection.Resolver
}

func (r run) fail(p processlist.Process, what string, err error) error {
	return fmt.Errorf("%s: process %d at 0x%x: %s: %w", Name, p.PID, p.EPROCESS, what, err)
}

func (r run) failAt(p processlist.Process, object string, at uint64, what string, err error) error {
	return fmt.Errorf("%s: process %d %s at 0x%x: %s: %w", Name, p.PID, object, at, what, err)
}

func (r run) process(p processlist.Process) ([]Row, error) {
	space, err := r.ctx.ProcessSpace(p.DirectoryTableBase)
	if err != nil {
		return nil, r.fail(p, "address space", err)
	}
	maps, err := r.decoder.Mappings(r.ctx, p)
	if err != nil {
		return nil, r.fail(p, "mappings", fmt.Errorf("%w: %v", ErrMappingsUnread, err))
	}
	views := newViewIndex(maps)
	var firstErr error
	for _, m := range views.named(tableModule) {
		rows, err := r.table(p, space, views, m)
		if err == nil || errors.Is(err, ErrEntryUnread) {
			return rows, err
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = r.fail(p, "table module", ErrNoTableModule)
	}
	return nil, firstErr
}

func (r run) table(p processlist.Process, space memory.MemoryReader, views viewIndex, m memoryranges.Mapping) ([]Row, error) {
	image := imageReader{space: space, physical: r.ctx.PhysicalMemory(), resolver: r.resolver,
		vad: m.VadAddress, start: m.Start, end: m.End}
	head, err := r.locate(image, m)
	if err != nil {
		return nil, r.failAt(p, tableModule, m.Start, "locate the crypto-system table", err)
	}
	if !inside(m, head.count, 4) || !inside(m, head.array, entrySize) {
		return nil, r.failAt(p, "crypto-system table", head.array, "check its place", ErrHeadOutsideView)
	}
	raw, err := space.ReadAt(head.count, 4)
	if err != nil || len(raw) != 4 {
		return nil, r.failAt(p, "crypto-system count", head.count, "read", fmt.Errorf("%w: %v", ErrCountUnread, err))
	}
	count := uint64(binary.LittleEndian.Uint32(raw))
	if count > maxEntries {
		return nil, r.failAt(p, "crypto-system count", head.count, fmt.Sprintf("check %d", count), ErrCountRange)
	}
	if !inside(m, head.array, count*entrySize) {
		return nil, r.failAt(p, "crypto-system table", head.array, "check its place", ErrHeadOutsideView)
	}

	rows := make([]Row, 0, count)
	var unread error
	for i := range count {
		at := head.array + i*entrySize
		b, err := space.ReadAt(at, entrySize)
		e, ok := decodeEntry(b)
		if err != nil || !ok {
			if unread == nil {
				unread = r.failAt(p, "crypto-system entry", at, "read", fmt.Errorf("%w: %v", ErrEntryUnread, err))
			}
			continue
		}
		rows = append(rows, r.row(p, image, views, m, head, int(i), at, e))
	}
	return rows, unread
}

// The table's pages are written when cryptdll registers its entries, so they
// are read through the process's own page tables only (S23 4.2).
func (r run) locate(image imageReader, m memoryranges.Mapping) (tableHead, error) {
	h, err := extract.ReadHeaders(image, m.Start)
	if err != nil {
		return tableHead{}, fmt.Errorf("%w: pe headers: %v", ErrTableNotFound, err)
	}
	read := pe.MappedReader(image, m.Start, h.Optional.SizeOfImage)
	head, symErr := r.headFromSymbols(h, read, m.Start)
	if symErr == nil {
		return head, nil
	}
	head, codeErr := r.headFromExport(h, read, image, m.Start)
	if codeErr == nil {
		return head, nil
	}
	return tableHead{}, fmt.Errorf("%w: symbols: %v; code: %v", ErrTableNotFound, symErr, codeErr)
}

func (r run) headFromSymbols(h *pe.Headers, read pe.ReadRVA, base uint64) (tableHead, error) {
	if r.ctx.LoadPDB == nil {
		return tableHead{}, errors.New("no symbol loader")
	}
	dir, err := h.ReadDataDirectory(read, pe.DirectoryEntryDebug)
	if err != nil {
		return tableHead{}, err
	}
	cv, err := pe.ReadCodeView(read, dir)
	if err != nil {
		return tableHead{}, err
	}
	fp := autoload.Fingerprint{PDBName: cv.PDBName(), GUID: autoload.FormatGUID(cv.GUID[:]), Age: cv.Age}
	table, err := r.ctx.LoadPDB(fp)
	if err != nil {
		return tableHead{}, err
	}
	if table == nil {
		return tableHead{}, fmt.Errorf("no table for %s", fp)
	}
	array, err := table.LookupSymbol(symbolTable)
	if err != nil {
		return tableHead{}, err
	}
	count, err := table.LookupSymbol(symbolCount)
	if err != nil {
		return tableHead{}, err
	}
	return tableHead{count: base + count.Address, array: base + array.Address, source: SourceSymbols}, nil
}

func (r run) headFromExport(h *pe.Headers, read pe.ReadRVA, image imageReader, base uint64) (tableHead, error) {
	dir, err := h.ReadDataDirectory(read, pe.DirectoryEntryExport)
	if err != nil {
		return tableHead{}, err
	}
	exports, err := pe.ParseExports(read, dir, r.ctx.Bounds())
	if err != nil {
		return tableHead{}, err
	}
	at, ok := pe.LookupExport(exports, locateRoutine, base)
	if !ok {
		return tableHead{}, fmt.Errorf("no export %s", locateRoutine)
	}
	if at < image.start || at > image.end {
		return tableHead{}, fmt.Errorf("export %s at 0x%x outside the view", locateRoutine, at)
	}
	n := min(uint64(locateWindow), image.end-at+1)
	code, err := image.ReadAt(at, n)
	if err != nil {
		return tableHead{}, err
	}
	head, ok := headFromLocateCode(code, at)
	if !ok {
		return tableHead{}, fmt.Errorf("%s at 0x%x does not decode to a count, a table and a shift of %d", locateRoutine, at, entryShift)
	}
	return head, nil
}

func (r run) row(p processlist.Process, image imageReader, views viewIndex, table memoryranges.Mapping,
	head tableHead, index int, at uint64, e entry) Row {
	row := Row{
		PID: p.PID, Process: p.Name, EPROCESS: p.EPROCESS,
		TableAddress: head.array, TableSource: head.source, Index: index, EntryAddress: at,
		EncryptionType: e.encryptionType, EncryptionTypeName: encryptionTypeName(e.encryptionType),
		NameUnreadable: true,
	}
	home := table
	if m, ok := views.at(e.name); ok && m.Path != "" {
		home = m
	}
	row.RegisteredBy = baseName(home.Path)
	if name, ok := r.readName(image, views, e.name); ok {
		row.Name, row.NameUnreadable = name, false
	}
	for _, p := range e.routines {
		rt := Routine{Slot: p.slot, Address: p.address, Redirected: p.address < home.Start || p.address > home.End}
		if m, ok := views.at(p.address); ok {
			rt.Module, rt.Kind = baseName(m.Path), m.Type
		}
		row.Redirected = row.Redirected || rt.Redirected
		row.Routines = append(row.Routines, rt)
	}
	return row
}

// A name inside an image view is read the way the view's code is; one
// anywhere else is read through the process's page tables only.
func (r run) readName(image imageReader, views viewIndex, at uint64) (string, bool) {
	if at == 0 {
		return "", false
	}
	var reader memory.MemoryReader = image.space
	if m, ok := views.at(at); ok && m.Path != "" {
		reader = imageReader{space: image.space, physical: image.physical, resolver: image.resolver,
			vad: m.VadAddress, start: m.Start, end: m.End}
	}
	limit := uint64(r.ctx.Bounds().MaxNameBytes) &^ 1
	var buf []byte
	for scanned := 0; uint64(len(buf)) < limit; {
		chunk := min(limit-uint64(len(buf)), tools.PageSize-(at+uint64(len(buf)))%tools.PageSize)
		b, err := reader.ReadAt(at+uint64(len(buf)), chunk)
		if err != nil {
			return "", false
		}
		buf = append(buf, b...)
		for ; scanned+1 < len(buf); scanned += 2 {
			if buf[scanned] == 0 && buf[scanned+1] == 0 {
				return util.DecodeUTF16LEZ(buf[:scanned]), true
			}
		}
	}
	return "", false
}

func inside(m memoryranges.Mapping, at, n uint64) bool {
	if at < m.Start || at > m.End {
		return false
	}
	return n == 0 || n-1 <= m.End-at
}

func baseName(p string) string {
	if p == "" {
		return ""
	}
	return path.Base(strings.ReplaceAll(p, `\`, "/"))
}
