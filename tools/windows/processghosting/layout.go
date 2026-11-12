package processghosting

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/util"
)

var ErrLayout = errors.New("processghosting: symbol table lacks a member the image file checks need")

type layout struct {
	sectionBase   uint64
	deletePending uint64
	fileName      uint64

	filePointer     uint64
	haveFilePointer bool

	caFlags         uint64
	haveCAFlags     bool
	image           symbols.IntField
	haveImage       bool
	deleteOnClose   symbols.IntField
	haveDelete      bool
	filePointerNull symbols.IntField
	haveNull        bool

	unicode util.UnicodeStringLayout
}

func resolveLayout(ctx tools.Context) (layout, error) {
	t := ctx.Symbols
	var l layout
	for _, r := range []struct {
		dst         *uint64
		typ, member string
	}{
		{&l.sectionBase, "_EPROCESS", "SectionBaseAddress"},
		{&l.deletePending, "_FILE_OBJECT", "DeletePending"},
		{&l.fileName, "_FILE_OBJECT", "FileName"},
	} {
		f, err := t.Field(r.typ, r.member)
		if err != nil {
			return layout{}, fmt.Errorf("%w: %s.%s: %w", ErrLayout, r.typ, r.member, err)
		}
		*r.dst = f.Offset
	}
	if f, err := t.Field("_EPROCESS", "ImageFilePointer"); err == nil {
		l.filePointer, l.haveFilePointer = f.Offset, true
	}
	if f, err := t.Field("_CONTROL_AREA", "u"); err == nil {
		l.caFlags, l.haveCAFlags = f.Offset, true
		flag := func(member string) (symbols.IntField, bool) {
			v, err := symbols.ResolveIntField(t, "_MMSECTION_FLAGS", member)
			if err != nil {
				return symbols.IntField{}, false
			}
			v.Offset += l.caFlags
			return v, true
		}
		l.image, l.haveImage = flag("Image")
		l.deleteOnClose, l.haveDelete = flag("DeleteOnClose")
		l.filePointerNull, l.haveNull = flag("FilePointerNull")
	}
	l.unicode = util.ResolveUnicodeStringLayout(t)
	return l, nil
}
