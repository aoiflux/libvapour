package linuxtracetest

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/memory"
)

// S80 rule L1: a member lies inside its record, a pointer or scalar sits on
// its natural alignment, and no two members overlap.
func TestEveryDeclaredRecordKeepsLayoutRuleL1(t *testing.T) {
	k := NewKernel()
	k.AddTask(Task{PID: 1, TGID: 1, Comm: "init"})
	k.DeclareXArray()
	table, err := k.Table.Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range keys(k.Table.records) {
		st, _ := table.Struct(name)
		type span struct{ from, to uint64 }
		var spans []span
		for _, f := range st.Fields {
			w, err := table.FieldSize(name, f.Name)
			if err != nil {
				t.Errorf("%s.%s: %v", name, f.Name, err)
				continue
			}
			if f.Offset+w > st.Size {
				t.Errorf("%s.%s ends at %#x, past %#x", name, f.Name, f.Offset+w, st.Size)
			}
			_, recordErr := table.Struct(f.Type.Name)
			scalar := f.Type.IsPointer || !f.Type.IsArray && recordErr != nil
			if scalar && (w == 2 || w == 4 || w == 8) && f.Offset%w != 0 {
				t.Errorf("%s.%s at %#x is not %d-byte aligned", name, f.Name, f.Offset, w)
			}
			spans = append(spans, span{f.Offset, f.Offset + w})
		}
		slices.SortFunc(spans, func(a, b span) int { return cmp.Compare(a.from, b.from) })
		for i := 1; i < len(spans); i++ {
			if spans[i].from < spans[i-1].to {
				t.Errorf("%s: members at %#x and %#x overlap", name, spans[i-1].from, spans[i].from)
			}
		}
	}
}

func TestTheIDRFindsEachEntryByID(t *testing.T) {
	k := NewKernel()
	idr := k.Alloc(IDRSize)
	entries := make([]uint64, 70)
	for i := range entries {
		entries[i] = Heap + 0x100000 + uint64(i)*0x40
	}
	k.IDR(idr, entries)
	read := func(a uint64) uint64 {
		b, err := k.Mem.ReadAt(a, 8)
		if err != nil {
			t.Fatal(err)
		}
		return binary.LittleEndian.Uint64(b)
	}
	for i, want := range entries {
		id := uint64(i) + 1
		leaf := read(read(idr+XAHead)&^3+XANodeSlots+id>>6*8) &^ 3
		if got := read(leaf + XANodeSlots + id%64*8); got != want {
			t.Errorf("id %d = %#x, want %#x", id, got, want)
		}
	}
}

func TestBuildClosesTheModuleAndTaskLists(t *testing.T) {
	k := NewKernel()
	mod := k.AddModule(Module{Name: "ext4", Base: ModuleArea + 0x10000, Size: 0x8000, Text: 0x4000})
	hidden := k.AddModule(Module{Name: "rootkit", Hidden: true})
	leader, threads := k.AddTask(Task{PID: 5, TGID: 5, Comm: "a", Threads: []Task{{PID: 6, TGID: 5}}})
	if _, _, err := k.Build(nil); err != nil {
		t.Fatal(err)
	}
	read := func(a uint64) uint64 {
		b, _ := k.Mem.ReadAt(a, 8)
		return binary.LittleEndian.Uint64(b)
	}
	if read(ModulesHead) != mod+ModuleList || read(mod+ModuleList) != ModulesHead || read(hidden+ModuleList) != 0 {
		t.Error("the modules list is not [ext4]")
	}
	if read(InitTask+TaskTasks) != leader+TaskTasks || read(threads[0]+TaskSignal) != read(leader+TaskSignal) {
		t.Error("the task list or the thread group is wrong")
	}
}

func TestMemoryCountsReadsAndRefusesHoles(t *testing.T) {
	m := NewMemory()
	m.Str(Heap+pageSize-2, "abc")
	if b, err := m.ReadAt(Heap+pageSize-2, 4); err != nil || string(b) != "abc\x00" || m.Reads != 1 {
		t.Fatalf("across a page: %q, %v, %d reads", b, err, m.Reads)
	}
	if _, err := m.ReadAt(Heap+8*pageSize, 1); !errors.Is(err, memory.ErrOutOfBounds) {
		t.Errorf("a hole: %v", err)
	}
}

func FuzzMemoryWriteReadsBack(f *testing.F) {
	f.Add(uint64(Heap), []byte("x"))
	f.Add(uint64(pageSize-1), []byte("across"))
	f.Fuzz(func(t *testing.T, at uint64, data []byte) {
		if len(data) == 0 || len(data) > 3*pageSize || at+uint64(len(data))-1 < at {
			return
		}
		m := NewMemory()
		m.Write(at, data)
		got, err := m.ReadAt(at, uint64(len(data)))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("read back %x, %v", got, err)
		}
	})
}
