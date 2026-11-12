package processhollowing

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

var ErrLayout = errors.New("processhollowing: symbol table lacks a member the image checks need")

type optional struct {
	at uint64
	ok bool
}

func offsetOf(t symbols.SymbolTable, path ...string) optional {
	var at uint64
	for i := 0; i+1 < len(path); i += 2 {
		f, err := t.Field(path[i], path[i+1])
		if err != nil {
			return optional{}
		}
		at += f.Offset
	}
	return optional{at: at, ok: true}
}

type layout struct {
	peb         uint64
	sectionBase uint64
	imageBase   uint64

	filePointer   optional
	sectionObject optional
	sectionCA     optional
	audit         optional
	auditName     optional
	secure        optional
	vadCount      symbols.IntField
	haveVadCount  bool

	fileName     optional
	fileSections optional
	imageSection optional
	caImage      symbols.IntField
	haveCAImage  bool

	nameCapacity int
	unicode      util.UnicodeStringLayout
}

func resolveLayout(ctx tools.Context) (layout, error) {
	t := ctx.Symbols
	var l layout
	for _, r := range []struct {
		dst         *uint64
		typ, member string
	}{
		{&l.peb, "_EPROCESS", "Peb"},
		{&l.sectionBase, "_EPROCESS", "SectionBaseAddress"},
		{&l.imageBase, "_PEB", "ImageBaseAddress"},
	} {
		f, err := t.Field(r.typ, r.member)
		if err != nil {
			return layout{}, fmt.Errorf("%w: %s.%s: %w", ErrLayout, r.typ, r.member, err)
		}
		*r.dst = f.Offset
	}
	l.filePointer = offsetOf(t, "_EPROCESS", "ImageFilePointer")
	l.sectionObject = offsetOf(t, "_EPROCESS", "SectionObject")
	l.sectionCA = offsetOf(t, "_SECTION", "u1")
	l.audit = offsetOf(t, "_EPROCESS", "SeAuditProcessCreationInfo", "_SE_AUDIT_PROCESS_CREATION_INFO", "ImageFileName")
	l.auditName = offsetOf(t, "_OBJECT_NAME_INFORMATION", "Name")
	for _, member := range []string{"SecureState", "SecurePid"} {
		if l.secure = offsetOf(t, "_EPROCESS", "Pcb", "_KPROCESS", member); l.secure.ok {
			break
		}
	}
	if f, err := symbols.ResolveIntField(t, "_EPROCESS", "VadCount"); err == nil {
		l.vadCount, l.haveVadCount = f, true
	}
	l.fileName = offsetOf(t, "_FILE_OBJECT", "FileName")
	l.fileSections = offsetOf(t, "_FILE_OBJECT", "SectionObjectPointer")
	l.imageSection = offsetOf(t, "_SECTION_OBJECT_POINTERS", "ImageSectionObject")
	if u := offsetOf(t, "_CONTROL_AREA", "u"); u.ok {
		if f, err := symbols.ResolveIntField(t, "_MMSECTION_FLAGS", "Image"); err == nil {
			f.Offset += u.at
			l.caImage, l.haveCAImage = f, true
		}
	}
	if name, err := symbols.ResolveCharArray(t, "_EPROCESS", "ImageFileName", processlist.WindowsImageNameLength); err == nil {
		l.nameCapacity = int(name.Length) - 1
	}
	l.unicode = util.ResolveUnicodeStringLayout(t)
	return l, nil
}
