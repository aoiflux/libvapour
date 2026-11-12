package gui_test

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
)

const (
	protoImageBase   = uint64(0xfffff80135ed0000)
	protoDebugRVA    = uint32(0x3000)
	protoCodeViewRVA = uint32(0x3100)
	protoDebugSlot   = 0x98 + 112 + 6*8

	entryValid      = uint64(1) << 0
	entryPrototype  = uint64(1) << 10
	entryTransition = uint64(1) << 11
	readOnly        = uint64(1) << 5
)

// The inverse of the debug record's GUID text: a little-endian uint32, two
// little-endian uint16, then eight bytes in order.
func guidBytes(t testing.TB, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 16 {
		t.Fatalf("guid %q", s)
	}
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:], binary.BigEndian.Uint32(raw[0:]))
	binary.LittleEndian.PutUint16(out[4:], binary.BigEndian.Uint16(raw[4:]))
	binary.LittleEndian.PutUint16(out[6:], binary.BigEndian.Uint16(raw[6:]))
	copy(out[8:], raw[8:])
	return out
}

func win32kBaseImage(t testing.TB, guid string, age uint32) []byte {
	t.Helper()
	img := testsupport.BuildExportingPE(protoImageBase, nil)
	binary.LittleEndian.PutUint32(img[protoDebugSlot:], protoDebugRVA)
	binary.LittleEndian.PutUint32(img[protoDebugSlot+4:], 28)
	rec := append([]byte("RSDS"), guidBytes(t, guid)...)
	rec = binary.LittleEndian.AppendUint32(rec, age)
	rec = append(rec, "win32kbase.pdb\x00"...)
	e := img[protoDebugRVA:]
	binary.LittleEndian.PutUint32(e[12:], 2)
	binary.LittleEndian.PutUint32(e[16:], uint32(len(rec)))
	binary.LittleEndian.PutUint32(e[20:], protoCodeViewRVA)
	copy(img[protoCodeViewRVA:], rec)
	return img
}

// mem7's layout (S57 M10): the header page's kernel leaf is a prototype
// entry whose target is a transition entry; the debug directory's page here
// has a valid target.
type prototypeImage struct {
	k     *testsupport.S64Kernel
	array uint64
}

func newPrototypeImage(t testing.TB, img []byte) prototypeImage {
	t.Helper()
	k := testsupport.NewS64Kernel()
	k.AddModule("win32kbase.sys", protoImageBase, uint64(len(img)))
	p := prototypeImage{k: k, array: k.Alloc(0x1000)}
	p.page(img, 0, entryTransition|readOnly)
	p.page(img, uint64(protoDebugRVA), entryValid)
	return p
}

func (p prototypeImage) page(img []byte, rva, kind uint64) {
	frame := p.k.Memory.AllocPage()
	p.k.Memory.WriteAt(frame, img[rva:rva+0x1000])
	slot := p.array + rva/0x1000*8
	p.k.U64(slot, frame|kind)
	p.k.Kernel.SetEntry(protoImageBase+rva, slot<<16|entryPrototype)
}

func openPrototype(t testing.TB, ctx tools.Context) error {
	t.Helper()
	diagnostics(&ctx)
	_, err := gui.Open(ctx, tool)
	return err
}

func TestAWin32kBaseHeaderOnPrototypePagesIdentifiesByRecord(t *testing.T) {
	l := gui.Layouts()[2]
	p := newPrototypeImage(t, win32kBaseImage(t, l.GUID, l.Age))
	err := openPrototype(t, p.k.Context())
	// The fixture's kernel table stops at the module list, so an identified
	// layout fails on the object types the tools read next.
	if !errors.Is(err, gui.ErrNoKernelTypes) || errors.Is(err, gui.ErrNoDebugRecord) || errors.Is(err, gui.ErrUnsupportedVersion) {
		t.Fatalf("err %v, want the layout identified", err)
	}
}

func TestAPrototypePageRecordThatNamesNoLayoutIsUnsupported(t *testing.T) {
	const other = "0123456789ABCDEF0123456789ABCDEF"
	p := newPrototypeImage(t, win32kBaseImage(t, other, 3))
	err := openPrototype(t, p.k.Context())
	if !errors.Is(err, gui.ErrUnsupportedVersion) || !strings.Contains(err.Error(), other+"-3") {
		t.Fatalf("err %v, want the record read through the prototype entries", err)
	}
}

func TestAPrototypeEntryThatIsNotResidentRefusesTheCapture(t *testing.T) {
	l := gui.Layouts()[2]
	p := newPrototypeImage(t, win32kBaseImage(t, l.GUID, l.Age))
	// A subsection entry: the page is in the file, not in memory.
	p.k.U64(p.array, 0x81012791d7400000|entryPrototype|readOnly)
	err := openPrototype(t, p.k.Context())
	if !errors.Is(err, gui.ErrNoDebugRecord) || !strings.Contains(err.Error(), "prototype entry at") {
		t.Fatalf("err %v, want the refusal", err)
	}
}

func TestAPrototypeEntryOutsideSystemSpaceIsNotFollowed(t *testing.T) {
	l := gui.Layouts()[2]
	p := newPrototypeImage(t, win32kBaseImage(t, l.GUID, l.Age))
	p.k.Kernel.SetEntry(protoImageBase, uint64(0x7ff000001000)<<16|entryPrototype)
	err := openPrototype(t, p.k.Context())
	if !errors.Is(err, gui.ErrNoDebugRecord) || !errors.Is(err, gui.ErrNotSystemSpace) {
		t.Fatalf("err %v, want the refusal", err)
	}
}

func TestWithoutPhysicalMemoryAPrototypePageIsNotRead(t *testing.T) {
	l := gui.Layouts()[2]
	p := newPrototypeImage(t, win32kBaseImage(t, l.GUID, l.Age))
	ctx := p.k.Context()
	delete(ctx.Options, tools.OptionPhysicalMemory)
	if err := openPrototype(t, ctx); !errors.Is(err, gui.ErrNoDebugRecord) {
		t.Fatalf("err %v, want the refusal", err)
	}
}

// Arbitrary leaf and target entries for the header page: the open never
// panics, never succeeds past identification here, and never follows a
// prototype entry outside system space.
func FuzzPrototypeHeaderEntries(f *testing.F) {
	l := gui.Layouts()[2]
	p := newPrototypeImage(f, win32kBaseImage(f, l.GUID, l.Age))
	leaf := p.array<<16 | entryPrototype
	target, err := p.k.Context().Memory.ReadAt(p.array, 8)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(leaf, binary.LittleEndian.Uint64(target))
	f.Add(leaf, uint64(0x81012791d7400000|entryPrototype))
	f.Add(uint64(0x7ff000001000)<<16|entryPrototype, uint64(0))
	f.Add(uint64(0), uint64(0))
	f.Fuzz(func(t *testing.T, leaf, target uint64) {
		p.k.Kernel.SetEntry(protoImageBase, leaf)
		p.k.U64(p.array, target)
		err := openPrototype(t, p.k.Context())
		if err == nil {
			t.Fatal("opened without the kernel types")
		}
		if at := uint64(int64(leaf) >> 16); leaf&entryValid == 0 && leaf&entryPrototype != 0 &&
			at < testsupport.S64SystemStart && !errors.Is(err, gui.ErrNoDebugRecord) {
			t.Fatalf("leaf 0x%x names 0x%x outside system space, yet %v", leaf, at, err)
		}
	})
}
