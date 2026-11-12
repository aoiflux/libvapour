package kerntest

import (
	"bytes"
	"cmp"
	"errors"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

// checkLayout holds S80 rule L1 for one table: a member lies inside its
// record, a pointer or scalar sits on its natural alignment, and two members
// overlap only when one holds the other, as union or alias members do.
func checkLayout(t *testing.T, table *symbols.Table, names []string) {
	t.Helper()
	for _, name := range names {
		st, err := table.Struct(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		type span struct {
			name     string
			from, to uint64
		}
		var spans []span
		for _, f := range st.Fields {
			if f.Type.BitLength != 0 || f.Type.Name == "" && !f.Type.IsPointer {
				continue
			}
			w, err := table.FieldSize(name, f.Name)
			if err != nil {
				t.Errorf("%s.%s: %v", name, f.Name, err)
				continue
			}
			if f.Offset+w > st.Size {
				t.Errorf("%s.%s ends at %#x, past the record size %#x", name, f.Name, f.Offset+w, st.Size)
			}
			_, recordErr := table.Struct(f.Type.Name)
			scalar := f.Type.IsPointer || !f.Type.IsArray && recordErr != nil
			if scalar && (w == 2 || w == 4 || w == 8) && f.Offset%w != 0 {
				t.Errorf("%s.%s at %#x is not %d-byte aligned", name, f.Name, f.Offset, w)
			}
			spans = append(spans, span{f.Name, f.Offset, f.Offset + w})
		}
		slices.SortFunc(spans, func(a, b span) int {
			if c := cmp.Compare(a.from, b.from); c != 0 {
				return c
			}
			return cmp.Compare(b.to, a.to)
		})
		for i := 1; i < len(spans); i++ {
			a, b := spans[i-1], spans[i]
			if b.from < a.to && b.to > a.to {
				t.Errorf("%s: %s [%#x,%#x) and %s [%#x,%#x) overlap", name, a.name, a.from, a.to, b.name, b.from, b.to)
			}
		}
	}
}

func TestTheModuleTypesKeepLayoutRuleL1(t *testing.T) {
	f := NewFixture(0)
	table := f.Types.Table(t)
	checkLayout(t, table.Table, slices.Sorted(func(yield func(string) bool) {
		for n := range f.Types.records {
			if !yield(n) {
				return
			}
		}
	}))
}

func TestMemoryReadsBackAcrossPagesAndRefusesHoles(t *testing.T) {
	m := NewMemory()
	at := uint64(Data + PageSize - 3)
	m.Write(at, []byte("abcdef"))
	if b, err := m.ReadAt(at, 6); err != nil || string(b) != "abcdef" {
		t.Fatalf("across a page: %q, %v", b, err)
	}
	if _, err := m.ReadAt(Data+4*PageSize, 1); !errors.Is(err, memory.ErrOutOfBounds) {
		t.Errorf("an unmapped page: %v", err)
	}
	if _, err := m.ReadAt(^uint64(0)-1, 4); !errors.Is(err, memory.ErrOutOfBounds) {
		t.Errorf("a read wrapping the address space: %v", err)
	}
	m.Unmap(at)
	if _, err := m.ReadAt(at, 1); err == nil {
		t.Error("an unmapped page still reads")
	}
}

func TestTheModuleFixtureLinksAndShifts(t *testing.T) {
	const shift = 0x200000
	f := NewFixture(shift)
	mod := uint64(ModuleArea + 0x10000)
	f.AddModule(ModuleSpec{At: mod, Name: "lkm", Base: ModuleArea + 0x80000, TextSize: 0x1000})
	head := uint64(ModulesSym + shift)
	if next := f.read64(head); next != mod+ModList || f.read64(mod+ModList) != head || f.read64(head+8) != mod+ModList {
		t.Errorf("modules list next %#x", next)
	}
	if f.read64(KsetStruct+shift) != mod+ModMkobj+KobjEntry {
		t.Error("the module is not on the kset")
	}
	table := f.Types.Table(t)
	table.Shift = shift
	if s, err := table.LookupSymbol("modules"); err != nil || s.Address != head {
		t.Errorf("modules at %#x, %v", s.Address, err)
	}
	if got := table.SymbolsAt(f.ParamOpsAt("param_ops_int")); len(got) != 1 || got[0].Name != "param_ops_int" {
		t.Errorf("symbols at param_ops_int: %+v", got)
	}
	b, _ := f.Mem.ReadAt(TaintFlags+shift+12*taintFlagSize, 3)
	if !bytes.Equal(b, []byte{'O', ' ', 1}) {
		t.Errorf("taint bit 12 = %q, want O for an out-of-tree module", b)
	}
}

func FuzzMemoryWriteReadsBack(f *testing.F) {
	f.Add(uint64(Data), []byte("x"))
	f.Add(uint64(PageSize-1), []byte("across"))
	f.Fuzz(func(t *testing.T, at uint64, data []byte) {
		if len(data) == 0 || len(data) > 3*PageSize || at+uint64(len(data))-1 < at {
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
