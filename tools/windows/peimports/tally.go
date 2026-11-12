package peimports

import (
	"errors"
	"maps"
	"slices"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
)

// Counts, not one line per process: a capture has hundreds of processes and
// the same few causes.
type tally struct {
	noSpace, noPEB, pebUnread, baseUnread, fromSection int
	noImports, libraryUnread, functionUnread           int
	image, parts                                       map[string]int
}

func newTally() *tally { return &tally{image: map[string]int{}, parts: map[string]int{}} }

func failure(err error) string {
	switch {
	case errors.Is(err, extract.ErrHeadersUnreadable):
		return "headers do not read"
	case errors.Is(err, pe.ErrNotPE), errors.Is(err, pe.ErrNoNTSignature), errors.Is(err, pe.ErrUnsupportedOptionalMagic):
		return "not a PE image"
	case errors.Is(err, pe.ErrUnreadable), errors.Is(err, pe.ErrOutsideImage):
		return "image bytes do not read"
	case errors.Is(err, pe.ErrUnterminatedString):
		return "a name has no NUL"
	case errors.Is(err, pe.ErrReservedThunkBits):
		return "a lookup entry sets reserved bits"
	case errors.Is(err, pe.ErrImportLimit):
		return "the import directory exceeds a limit"
	}
	return err.Error()
}

func (t *tally) report(ctx tools.Context) {
	note := func(n int, what string) {
		if n > 0 {
			ctx.AddDiagnostic("%s: %d %s", Name, n, what)
		}
	}
	note(t.noSpace, "processes passed over: their address space does not open")
	note(t.noPEB, "processes passed over: no PEB")
	note(t.pebUnread, "processes whose PEB ImageBaseAddress does not read")
	note(t.fromSection, "main images found through _EPROCESS.SectionBaseAddress")
	note(t.baseUnread, "processes passed over: main image base does not read")
	for _, why := range slices.Sorted(maps.Keys(t.image)) {
		note(t.image[why], "main images passed over: "+why)
	}
	note(t.noImports, "main images have no import directory")
	for _, why := range slices.Sorted(maps.Keys(t.parts)) {
		note(t.parts[why], "import directory parts passed over: "+why)
	}
	note(t.libraryUnread, "import descriptors whose library name does not read: rows flagged")
	note(t.functionUnread, "imports whose hint/name entry does not read: rows flagged")
}
