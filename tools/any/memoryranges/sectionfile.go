package memoryranges

import (
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/util"
)

type FileNames struct {
	private     symbols.IntField
	havePrivate bool
	tagDelta    uint64
	haveTag     bool

	subsection  uint64
	controlArea uint64
	filePointer uint64
	fileFlag    symbols.IntField
	haveFile    bool
	refMask     uint64
	fileName    uint64
	unicode     util.UnicodeStringLayout
}

type MappedFile struct {
	ControlArea    uint64
	FileObject     uint64
	Path           string
	NameUnreadable bool
	NoFile         bool
}

// S19 T2 measures RefCnt as bits 0..3 on 64-bit kernels; the 32-bit width is
// not measured (S24 O4).
const (
	refBits64 = 4
	refBits32 = 3
)

func ResolveFileNames(ctx tools.Context) (FileNames, error) {
	t := ctx.Symbols
	var f FileNames
	var err error
	if f.subsection, err = required(t, "_MMVAD", "Subsection"); err != nil {
		return f, err
	}
	if f.controlArea, err = required(t, "_SUBSECTION", "ControlArea"); err != nil {
		return f, err
	}
	if f.filePointer, err = required(t, "_CONTROL_AREA", "FilePointer"); err != nil {
		return f, err
	}
	if f.fileName, err = required(t, "_FILE_OBJECT", "FileName"); err != nil {
		return f, err
	}
	f.private, f.havePrivate = flagMember(t, "PrivateMemory")
	f.tagDelta, f.haveTag = poolTagDelta(t)
	if u, ok := offsetOf(t, "_CONTROL_AREA", "u"); ok {
		if flag, ok := memberField(t, "_MMSECTION_FLAGS", "File", ulongWidth); ok {
			flag.Offset += u
			f.fileFlag, f.haveFile = flag, true
		}
	}
	bits := uint64(refBits64)
	if t.PointerSize() == 4 {
		bits = refBits32
	}
	if rc, err := t.Field("_EX_FAST_REF", "RefCnt"); err == nil && rc.Type.BitLength > 0 {
		bits = uint64(rc.Type.BitOffset) + uint64(rc.Type.BitLength)
	}
	f.refMask = 1<<bits - 1
	f.unicode = util.ResolveUnicodeStringLayout(t)
	return f, nil
}

// known is false when neither PrivateMemory nor the pool tag reads, so the
// VAD may or may not map a file.
func (f FileNames) sectionView(ctx tools.Context, vadBase uint64) (view, known bool) {
	if f.havePrivate {
		v, err := f.private.Read(ctx.Memory, vadBase)
		return err == nil && v == 0, err == nil
	}
	l := vadLayout{tagDelta: f.tagDelta, haveTag: f.haveTag}
	tag := l.tag(ctx, vadBase)
	return sectionTag(tag), tag != ""
}

// Subsection lies past the end of an _MMVAD_SHORT, so it is read only for a
// section view (S24 4.6 step 2). NoFile is set only where the VAD is shown to
// map no file; a read that fails leaves it clear.
func (f FileNames) Resolve(ctx tools.Context, vadBase uint64) (MappedFile, bool) {
	view, known := f.sectionView(ctx, vadBase)
	if !view {
		return MappedFile{NoFile: known}, false
	}
	sub, err := ctx.Symbols.ReadPointer(ctx.Memory, vadBase+f.subsection)
	if err != nil || sub == 0 {
		return MappedFile{}, false
	}
	ca, err := ctx.Symbols.ReadPointer(ctx.Memory, sub+f.controlArea)
	if err != nil || ca == 0 {
		return MappedFile{}, false
	}
	out := MappedFile{ControlArea: ca}
	if f.haveFile {
		v, err := f.fileFlag.Read(ctx.Memory, ca)
		if err != nil || v == 0 {
			out.NoFile = err == nil
			return out, false
		}
	}
	ref, err := ctx.Symbols.ReadPointer(ctx.Memory, ca+f.filePointer)
	if err != nil || ref&^f.refMask == 0 {
		out.NoFile = err == nil
		return out, false
	}
	out.FileObject = ref &^ f.refMask
	name, err := util.ReadUnicodeString(ctx.Memory, out.FileObject+f.fileName, f.unicode, util.MaxUnicodeStringBytes)
	if err != nil {
		out.NameUnreadable = true
		return out, true
	}
	out.Path = name.Text()
	return out, true
}

func (f FileNames) Name(ctx tools.Context, vadBase uint64) (string, bool) {
	m, ok := f.Resolve(ctx, vadBase)
	if !ok || m.NameUnreadable || m.Path == "" {
		return "", false
	}
	return m.Path, true
}

func (f FileNames) Of(ctx tools.Context, vadBase uint64) string {
	m, _ := f.Resolve(ctx, vadBase)
	return m.Path
}

func fileNamesFor(ctx tools.Context) (FileNames, bool) {
	f, err := ResolveFileNames(ctx)
	if err != nil {
		ctx.AddDiagnostic("%s: VAD file names not read: %v", walkLabel(ctx), fmt.Errorf("layout: %w", err))
		return FileNames{}, false
	}
	return f, true
}
