package memory

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

func openCore(s elfSpec) (*SegmentedReader, error) {
	return openELFCore(s.build(), limits.Default())
}

var (
	vmcoreNote   = elfNoteSpec{noteVMCore, 0, []byte("OSRELEASE=6.17.0\n")}
	prstatusNote = elfNoteSpec{noteOwnerCore, 1, make([]byte, 336)}
)

func TestAKernelCoreServesItsLoadSegmentsByPhysicalAddress(t *testing.T) {
	low, high := pattern(0x100, 1), pattern(0x80, 2)
	for _, shape := range []elfSpec{{wide: true}, {wide: false}, {wide: true, big: true}, {wide: false, big: true}, {wide: true, extendedPh: true}} {
		s := shape
		s.notes = []elfNoteSpec{prstatusNote, vmcoreNote}
		s.loads = []elfLoadSpec{{phys: 0x10000, data: high}, {phys: 0x1000, data: low, mem: 0x200}}
		r, err := openCore(s)
		if err != nil {
			t.Fatalf("%+v: %v", shape, err)
		}
		if got, err := r.ReadAt(0x1000, 0x100); err != nil || !bytes.Equal(got, low) {
			t.Errorf("%+v low: %v", shape, err)
		}
		if got, err := r.ReadAt(0x10000, 0x80); err != nil || !bytes.Equal(got, high) {
			t.Errorf("%+v high: %v", shape, err)
		}
		if _, err := r.ReadAt(0x1100, 1); !errors.Is(err, ErrUnmapped) {
			t.Errorf("%+v: memory size past file size served: %v", shape, err)
		}
	}
}

func TestACoreWithOnlyRegisterNotesIsRead(t *testing.T) {
	r, err := openCore(elfSpec{wide: true, notes: []elfNoteSpec{prstatusNote}, loads: []elfLoadSpec{{phys: 0, data: pattern(8, 1)}}})
	if err != nil || r.Size() != 8 {
		t.Fatalf("%v", err)
	}
	if _, err := openCore(elfSpec{wide: true, loads: []elfLoadSpec{{phys: 0x1000, data: pattern(8, 1)}}}); err != nil {
		t.Errorf("no notes: %v", err)
	}
}

func TestAProcessCoreIsRefusedWhateverItsAddresses(t *testing.T) {
	for _, typ := range []uint32{noteAuxv, noteSigInfo, noteFileMap} {
		s := elfSpec{wide: true, notes: []elfNoteSpec{prstatusNote, {noteOwnerCore, typ, make([]byte, 16)}},
			loads: []elfLoadSpec{{phys: 0, data: pattern(16, 1)}, {phys: 0, data: pattern(16, 2)}}}
		if _, err := openCore(s); !errors.Is(err, ErrProcessCore) {
			t.Errorf("type 0x%x: %v, want ErrProcessCore", typ, err)
		}
	}
}

func TestOnlyTheKernelsOwnerNameMarksAProcessNote(t *testing.T) {
	s := elfSpec{wide: true, notes: []elfNoteSpec{{"LINUX", noteAuxv, make([]byte, 8)}}, loads: []elfLoadSpec{{phys: 0x1000, data: pattern(8, 1)}}}
	if _, err := openCore(s); err != nil {
		t.Errorf("another owner's type 6: %v", err)
	}
	s.notes = []elfNoteSpec{{noteOwnerCore, noteAuxv, make([]byte, 8)}, vmcoreNote}
	if _, err := openCore(s); err != nil {
		t.Errorf("VMCOREINFO beside a process note: %v", err)
	}
	s.noteAlign = 8
	s.notes = []elfNoteSpec{vmcoreNote}
	if _, err := openCore(s); err != nil {
		t.Errorf("8-byte note alignment: %v", err)
	}
}

func TestASegmentInsideAnotherIsTheSameMemory(t *testing.T) {
	ram := pattern(0x1000, 3)
	s := elfSpec{wide: true, notes: []elfNoteSpec{vmcoreNote}, loads: []elfLoadSpec{
		{phys: 0x1000, data: ram}, {phys: 0x1400, data: ram[0x400:0x800]}, {phys: ^uint64(0), data: pattern(32, 4)},
	}}
	r, err := openCore(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Segments()) != 1 || r.Size() != 0x2000 {
		t.Errorf("segments %+v", r.Segments())
	}
	notes := strings.Join(r.containerNotes(), "; ")
	if !strings.Contains(notes, "inside another") || !strings.Contains(notes, "no physical address") {
		t.Errorf("notes %q", notes)
	}
}

func TestCoresThatCannotBeServedAreRefused(t *testing.T) {
	one := []elfLoadSpec{{phys: 0x1000, data: pattern(0x100, 1)}}
	cases := map[string]image{
		"not a core":      elfSpec{wide: true, fileType: 2, loads: one}.build(),
		"partial overlap": elfSpec{wide: true, loads: []elfLoadSpec{{phys: 0x1000, data: pattern(0x100, 1)}, {phys: 0x1080, data: pattern(0x100, 2)}}}.build(),
		"no physical":     elfSpec{wide: true, loads: []elfLoadSpec{{phys: ^uint64(0), data: pattern(8, 1)}}}.build(),
		"no headers":      elfSpec{wide: true}.build(),
		"class":           func() image { f := elfSpec{wide: true, loads: one}.build(); f[4] = 3; return f }(),
		"encoding":        func() image { f := elfSpec{wide: true, loads: one}.build(); f[5] = 0; return f }(),
		"truncated":       elfSpec{wide: true, loads: one}.build()[:0x100],
		"header only":     image(elfMagic + "\x02\x01\x01"),
	}
	for name, file := range cases {
		if _, err := openELFCore(file, limits.Default()); !errors.Is(err, ErrELFCore) {
			t.Errorf("%s: %v, want ErrELFCore", name, err)
		}
	}
}

func TestNoteWalkAndProgramTableKeepToTheirLimits(t *testing.T) {
	many := make([]elfNoteSpec, 5)
	for i := range many {
		many[i] = prstatusNote
	}
	s := elfSpec{wide: true, notes: many, loads: []elfLoadSpec{{phys: 0x1000, data: pattern(8, 1)}}}
	l := limits.Default()
	l.MaxListEntries = 4
	if _, err := openELFCore(s.build(), l); !errors.Is(err, ErrELFCore) {
		t.Errorf("note cap: %v", err)
	}
	l = limits.Default()
	l.MaxBufferBytes = 64
	if _, err := openELFCore(s.build(), l); !errors.Is(err, ErrELFCore) {
		t.Errorf("note segment cap: %v", err)
	}
	l = limits.Default()
	l.MaxTableEntries = 1
	if _, err := openELFCore(s.build(), l); !errors.Is(err, ErrELFCore) {
		t.Errorf("program header cap: %v", err)
	}
}
