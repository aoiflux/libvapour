package pesymbols

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
)

// RSDS, GUID (16 bytes), age (4 bytes), then the NUL-terminated PDB path.
const (
	codeViewMagic      = "RSDS"
	codeViewGUIDAt     = 4
	codeViewAgeAt      = 20
	codeViewPathAt     = 24
	codeViewPathLength = 260
)

// The scan is for a record the debug directory no longer leads to. Readable
// pages that follow one another are searched as one run, so a record that
// crosses a page boundary is found; a page that does not read ends the run.
func FindPDBRecord(r memory.MemoryReader, base, size uint64, pdbName string) (autoload.Fingerprint, bool) {
	if size == 0 || pdbName == "" {
		return autoload.Fingerprint{}, false
	}
	end := base + size
	if end < base {
		end = ^uint64(0)
	}
	var run []byte
	for page := base &^ (tools.PageSize - 1); page < end; {
		next := page + tools.PageSize
		lo, hi := max(page, base), end
		if next > page {
			hi = min(next, end)
		}
		if data, err := r.ReadAt(lo, hi-lo); err == nil && uint64(len(data)) == hi-lo {
			run = append(run, data...)
		} else {
			if fp, ok := recordIn(run, pdbName); ok {
				return fp, true
			}
			run = run[:0]
		}
		if next <= page {
			break
		}
		page = next
	}
	return recordIn(run, pdbName)
}

func recordIn(run []byte, pdbName string) (autoload.Fingerprint, bool) {
	magic := []byte(codeViewMagic)
	for from := 0; ; {
		i := bytes.Index(run[from:], magic)
		if i < 0 {
			return autoload.Fingerprint{}, false
		}
		at := from + i
		from = at + 1
		if path, ok := codeViewPath(run[at:]); ok && pdbFileNameIs(path, pdbName) {
			return autoload.Fingerprint{
				PDBName: pdbName,
				GUID:    autoload.FormatGUID(run[at+codeViewGUIDAt : at+codeViewAgeAt]),
				Age:     binary.LittleEndian.Uint32(run[at+codeViewAgeAt:]),
			}, true
		}
	}
}

func codeViewPath(rec []byte) (string, bool) {
	if len(rec) <= codeViewPathAt {
		return "", false
	}
	tail := rec[codeViewPathAt:min(len(rec), codeViewPathAt+codeViewPathLength)]
	n := bytes.IndexByte(tail, 0)
	if n <= 0 {
		return "", false
	}
	return string(tail[:n]), true
}

// The path may be just the file name or a build-machine path ending in it.
func pdbFileNameIs(path, pdbName string) bool {
	return strings.EqualFold(path[strings.LastIndexAny(path, `\/`)+1:], pdbName)
}

// pdbSet loads each instance's PDB once per fingerprint and remembers the
// fingerprints that did not load, so one missing PDB is reported once.
type pdbSet struct {
	tables   map[autoload.Fingerprint]symbols.SymbolTable
	failed   map[autoload.Fingerprint]bool
	loaded   bool
	unread   int
	firstErr error
}

func newPDBSet() *pdbSet {
	return &pdbSet{tables: map[autoload.Fingerprint]symbols.SymbolTable{}, failed: map[autoload.Fingerprint]bool{}}
}

// The PDB name comes from the CodeView record, not the module name: the
// 32-bit ntdll.dll names wntdll.pdb.
func (s *pdbSet) table(ctx tools.Context, m Module) symbols.SymbolTable {
	if ctx.LoadPDB == nil {
		return nil
	}
	fp, err := fingerprint(ctx, m)
	if err != nil {
		s.unread++
		if s.firstErr == nil {
			s.firstErr = fmt.Errorf("%s at 0x%x in pid %d: %w", m.Name, m.Base, m.PID, err)
		}
		return nil
	}
	if t, ok := s.tables[fp]; ok {
		return t
	}
	if s.failed[fp] {
		return nil
	}
	t, err := ctx.LoadPDB(fp)
	if err != nil || t == nil {
		s.failed[fp] = true
		ctx.AddDiagnostic("%s: %s in pid %d: PDB %s %s age %d not loaded, exports used: %v", Name, m.Name, m.PID,
			fp.PDBName, fp.GUID, fp.Age, err)
		return nil
	}
	s.tables[fp], s.loaded = t, true
	return t
}

func (s *pdbSet) report(ctx tools.Context, module string) {
	if s.loaded || s.unread == 0 {
		return
	}
	ctx.AddDiagnostic("%s: %s: no CodeView record reads in %d mappings, exports used: first: %v", Name, module,
		s.unread, s.firstErr)
}

func fingerprint(ctx tools.Context, m Module) (autoload.Fingerprint, error) {
	reader, err := instanceReader(ctx, m)
	if err != nil {
		return autoload.Fingerprint{}, err
	}
	headers, err := extract.ReadHeaders(reader, m.Base)
	if err != nil {
		return autoload.Fingerprint{}, err
	}
	span := m.Size
	if span == 0 {
		span = uint64(headers.Optional.SizeOfImage)
	}
	read := ReadRVAAt(reader, m.Base, span)
	dir, err := headers.ReadDataDirectory(read, pe.DirectoryEntryDebug)
	if err != nil {
		return autoload.Fingerprint{}, fmt.Errorf("debug data directory: %w", err)
	}
	cv, err := pe.ReadCodeView(read, dir)
	if err != nil {
		return autoload.Fingerprint{}, err
	}
	return autoload.Fingerprint{PDBName: cv.PDBName(), GUID: autoload.FormatGUID(cv.GUID[:]), Age: cv.Age}, nil
}
