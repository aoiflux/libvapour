package linuxmodule

import (
	"errors"

	"github.com/aoiflux/libvapour/extract"
)

type FileState string

const (
	FileNone    FileState = "none"
	FileWritten FileState = "written"
	FileFailed  FileState = "failed"
)

// Row is the S07 section 7 module row.
type Row struct {
	Address      uint64
	Name         string
	State        string
	Source       string
	Base         uint64
	CoreSize     uint64
	InitSize     uint64
	Taints       string
	TaintsUnread bool
	Parameters   string
	File         string
	FileState    FileState
}

type RowOptions struct {
	Tool string
	Diag func(format string, args ...any)
	// Dump writes each module's ELF rebuild (S08) to Dir, up to Cap bytes a file.
	Dump bool
	Dir  string
	Cap  uint64
	// Canonical gives an address in canonical form for artefact names (S00 3),
	// since the model may hold masked addresses (S54 4.1 step 3).
	Canonical func(uint64) uint64
}

// Rows builds one row per module. Only a failed file write is an error.
func (m *Model) Rows(mods []Module, src Source, o RowOptions) ([]Row, error) {
	diag := o.Diag
	if diag == nil {
		diag = func(string, ...any) {}
	}
	out := make([]Row, 0, len(mods))
	for _, mod := range mods {
		row := Row{Address: mod.Address, Name: mod.Name, State: mod.State.String(), Source: src.String(),
			Base: mod.Base(), CoreSize: mod.CoreSize(), InitSize: mod.InitSize(), FileState: FileNone,
			TaintsUnread: mod.TaintsUnread}
		if mod.HasTaints && !mod.TaintsUnread {
			row.Taints = TaintNames(m.Taints(mod.Taints))
		}
		if ps, err := m.Parameters(mod); err != nil {
			diag("%s: module %s at %#x: parameters: %v", o.Tool, mod.Name, mod.Address, err)
		} else {
			if ps.Unread > 0 || ps.Capped {
				diag("%s: module %s at %#x: %d parameters do not read, capped %v", o.Tool, mod.Name, mod.Address,
					ps.Unread, ps.Capped)
			}
			row.Parameters = ps.Text()
		}
		if o.Dump {
			rb, err := m.RebuildELF(mod, o.Cap)
			if err != nil {
				diag("%s: module %s at %#x: ELF rebuild: %v", o.Tool, mod.Name, mod.Address, err)
				row.FileState = FileFailed
			} else {
				row.File = FileName(mod, m.width, o.Canonical)
				if err := WriteFile(o.Dir, row.File, rb.File); err != nil {
					return nil, err
				}
				row.FileState = FileWritten
				ReportRebuild(diag, o.Tool, mod, rb)
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// ReportRebuild puts what a rebuild left out into diagnostics.
func ReportRebuild(diag func(string, ...any), tool string, mod Module, rb Rebuild) {
	if len(rb.Dropped) > 0 {
		diag("%s: module %s at %#x: %d sections outside live module memory left out of the file", tool, mod.Name,
			mod.Address, len(rb.Dropped))
	}
	if rb.Skipped > 0 {
		diag("%s: module %s at %#x: %d section entries do not read", tool, mod.Name, mod.Address, rb.Skipped)
	}
	if rb.Capped {
		diag("%s: module %s at %#x: section entries stop at Limits.MaxTableEntries", tool, mod.Name, mod.Address)
	}
	if rb.ZeroPages > 0 {
		diag("%s: module %s at %#x: %d pages do not read and are written as zeros", tool, mod.Name, mod.Address,
			rb.ZeroPages)
	}
	if rb.NoSymbols {
		diag("%s: module %s at %#x: no symbol table; the file has an empty .symtab", tool, mod.Name, mod.Address)
	}
	if rb.AttrsDisordered {
		diag("%s: module %s at %#x: section entries stop where the pointer list leaves the array", tool, mod.Name,
			mod.Address)
	}
}

// FileName is the S00 artefact name of a module's ELF rebuild.
func FileName(mod Module, width uint64, canonical func(uint64) uint64) string {
	addr := mod.Address
	if canonical != nil {
		addr = canonical(addr)
	}
	return extract.Name{Kind: extract.KindModule, Scope: extract.Kernel, Width: uint8(width),
		Addresses: []uint64{addr}, Labels: []string{mod.Name}, Ext: extract.ExtELF}.String()
}

// WriteFile writes a new artefact and removes it again if the write fails.
func WriteFile(dir, name string, data []byte) error {
	f, err := extract.CreateNew(dir, name)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return errors.Join(werr, extract.RemoveArtifact(dir, name))
	}
	return nil
}
