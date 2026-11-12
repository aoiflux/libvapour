package servicerecord

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/pesymbols"
	"github.com/aoiflux/libvapour/util"
)

const scmImage = "services.exe"

type target struct {
	pid, eprocess uint64
	space         memory.MemoryReader
	private       []addressRange
	image         addressRange
}

func findTargets(ctx tools.Context, tool string) ([]target, error) {
	if ctx.Symbols.PointerSize() != pointerSize {
		return nil, fmt.Errorf("%s: pointer size %d: %w", tool, ctx.Symbols.PointerSize(), ErrPointerSize)
	}
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", tool, err)
	}
	files, filesErr := memoryranges.ResolveFileNames(ctx)
	if filesErr != nil {
		ctx.AddDiagnostic("%s: mapped file names not resolved, the services.exe image is not located: %v", tool, filesErr)
	}
	var out []target
	found := 0
	for _, p := range procs {
		if !strings.EqualFold(util.ReplaceInvalidUTF8(p.Name), scmImage) {
			continue
		}
		found++
		t, err := openTarget(ctx, p, files, filesErr == nil)
		if err != nil {
			err = fmt.Errorf("%s: %s pid %d at 0x%x: %w", tool, scmImage, p.PID, p.EPROCESS, err)
			if ctx.StrictMode() {
				return nil, err
			}
			ctx.AddDiagnostic("%v", err)
			continue
		}
		if t.image.end == 0 {
			ctx.AddDiagnostic("%s: %s pid %d at 0x%x: image VAD not found", tool, scmImage, p.PID, p.EPROCESS)
		}
		out = append(out, t)
	}
	if found == 0 {
		return nil, fmt.Errorf("%s: %w", tool, ErrNoServicesProcess)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: %d %s processes, none readable: %w", tool, found, scmImage, ErrNoServicesProcess)
	}
	return out, nil
}

func openTarget(ctx tools.Context, p processlist.Process, files memoryranges.FileNames, haveFiles bool) (target, error) {
	t := target{pid: p.PID, eprocess: p.EPROCESS}
	space, err := ctx.ProcessSpace(p.DirectoryTableBase)
	if err != nil {
		return t, fmt.Errorf("address space not read: %w", err)
	}
	t.space = space
	vads, err := memoryranges.ProcessVADs(ctx, p)
	if err != nil {
		return t, fmt.Errorf("VADs not read: %w", err)
	}
	for _, v := range vads {
		if v.End < v.Start {
			continue
		}
		r := addressRange{start: v.Start, end: v.End + 1}
		if v.PrivateMemoryKnown && v.PrivateMemory {
			t.private = append(t.private, r)
			continue
		}
		if haveFiles && t.image.end == 0 {
			if name, ok := files.Name(ctx, v.Base); ok && strings.HasSuffix(strings.ToLower(name), `\`+scmImage) {
				t.image = r
			}
		}
	}
	sort.Slice(t.private, func(i, j int) bool { return t.private[i].start < t.private[j].start })
	return t, nil
}

// The fingerprint comes from the image's own CodeView record (S34 2).
func (t target) pdb(ctx tools.Context) (symbols.SymbolTable, error) {
	if ctx.LoadPDB == nil {
		return nil, errNoPDBLoader
	}
	if t.image.end == 0 {
		return nil, errNoImage
	}
	headers, err := extract.ReadHeaders(t.space, t.image.start)
	if err != nil {
		return nil, fmt.Errorf("PE headers: %w", err)
	}
	read := pesymbols.ReadRVAAt(t.space, t.image.start, t.image.end-t.image.start)
	dir, err := headers.ReadDataDirectory(read, pe.DirectoryEntryDebug)
	if err != nil {
		return nil, fmt.Errorf("debug directory: %w", err)
	}
	cv, err := pe.ReadCodeView(read, dir)
	if err != nil {
		return nil, err
	}
	return ctx.LoadPDB(autoload.Fingerprint{PDBName: cv.PDBName(), GUID: autoload.FormatGUID(cv.GUID[:]), Age: cv.Age})
}
