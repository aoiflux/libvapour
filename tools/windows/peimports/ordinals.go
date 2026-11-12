package peimports

import (
	"strings"

	"github.com/aoiflux/libvapour/pe/peparse"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/librarylist"
	"github.com/aoiflux/libvapour/tools/windows/pesymbols"
)

// An ordinal import has no name in the importing image. The name comes from
// the export directory of the library as the same process mapped it, and
// only from a mapping of the same width as the importer: 32-bit and 64-bit
// builds of one DLL number their exports differently.
type ordinalNamer struct {
	ctx     tools.Context
	listed  bool
	listErr error
	byProc  map[uint64][]librarylist.DLL
	exports map[mappingKey]map[uint16]string
}

type mappingKey struct{ dtb, base uint64 }

func newOrdinalNamer(ctx tools.Context) *ordinalNamer {
	return &ordinalNamer{ctx: ctx, exports: map[mappingKey]map[uint16]string{}}
}

func (o *ordinalNamer) name(p processlist.Process, library string, pe32Plus bool, ordinal uint16) (string, string) {
	if d, ok := o.mapping(p, library, !pe32Plus); ok {
		if n := o.exportNames(d)[ordinal]; n != "" {
			return n, OrdinalFromExports
		}
	}
	if n, ok := peparse.OrdinalName(library, pe32Plus, ordinal); ok {
		return n, OrdinalFromTable
	}
	return "", ""
}

func (o *ordinalNamer) mapping(p processlist.Process, library string, wow64 bool) (librarylist.DLL, bool) {
	if !o.listed {
		o.listed = true
		dlls, err := librarylist.Run(o.ctx)
		o.listErr = err
		o.byProc = map[uint64][]librarylist.DLL{}
		for _, d := range dlls {
			o.byProc[d.EPROCESS] = append(o.byProc[d.EPROCESS], d)
		}
	}
	for _, d := range o.byProc[p.EPROCESS] {
		if d.Wow64 == wow64 && !d.NameUnreadable && d.Base != 0 && strings.EqualFold(d.Name, library) {
			return d, true
		}
	}
	return librarylist.DLL{}, false
}

func (o *ordinalNamer) exportNames(d librarylist.DLL) map[uint16]string {
	key := mappingKey{d.DirectoryTableBase, d.Base}
	if names, ok := o.exports[key]; ok {
		return names
	}
	var names map[uint16]string
	exports, err := pesymbols.Exports(o.ctx, pesymbols.Module{PID: d.PID, ProcessName: d.ProcName,
		DirectoryTableBase: d.DirectoryTableBase, Name: strings.ToLower(d.Name), Base: d.Base, Size: d.Size})
	if err == nil {
		names = map[uint16]string{}
		for _, e := range exports {
			if _, taken := names[uint16(e.Ordinal)]; e.Name != "" && e.Ordinal <= 0xFFFF && !taken {
				names[uint16(e.Ordinal)] = e.Name
			}
		}
	}
	o.exports[key] = names
	return names
}

func (o *ordinalNamer) report(ctx tools.Context) {
	if o.listErr != nil {
		ctx.AddDiagnostic("%s: process modules not listed, ordinal imports named from the ordinal table only: %v", Name, o.listErr)
	}
}
