package imagevmcoreinfo

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols/autoload"
	lt "github.com/aoiflux/libvapour/symbols/linuxkernel/linuxtest"
	"github.com/aoiflux/libvapour/tools"
)

func run(buf []byte, strict bool) ([]Row, []string, error) {
	var diags []string
	opts := map[string]any{tools.OptionPhysicalMemory: memory.MemoryReader(&lt.Memory{Buf: buf}), "diagnostics": &diags}
	if strict {
		opts["strict"] = true
	}
	rows, err := Run(tools.Context{Options: opts})
	return rows, diags, err
}

func TestEveryNoteIsListedWithTheKernelsText(t *testing.T) {
	buf := make([]byte, 0x3000)
	lt.PutNote(buf, 0x100, "OSRELEASE=6.17.0\nSYMBOL(swapper_pg_dir)=ffffffff9a20c000\nNUMBER(phys_base)=-1\n")
	lt.PutNote(buf, 0x2000, "OSRELEASE=6.17.0\nCRASHTIME=1700000000\n")
	rows, diags, err := run(buf, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{
		{Offset: 0x100, Key: "OSRELEASE", Value: "6.17.0"},
		{Offset: 0x100, Key: "SYMBOL(swapper_pg_dir)", Value: "ffffffff9a20c000"},
		{Offset: 0x100, Key: "NUMBER(phys_base)", Value: "-1"},
		{Offset: 0x2000, Key: "OSRELEASE", Value: "6.17.0"},
		{Offset: 0x2000, Key: "CRASHTIME", Value: "1700000000"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows\n got %+v\nwant %+v", rows, want)
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestACutLineIsMarked(t *testing.T) {
	buf := make([]byte, 0x1000)
	long := "BUILD-ID=" + strings.Repeat("a", 75)
	lt.PutNote(buf, 0x100, "OSRELEASE=6.17.0\n"+long[:79]+"PAGESIZE=4096\n")
	rows, diags, err := run(buf, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 || !rows[1].Cut || rows[1].Value != long[len("BUILD-ID="):79] {
		t.Errorf("rows %+v", rows)
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "note at 0x100: 1 lines were cut") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestADamagedCopyIsADiagnosticOrInStrictModeAnError(t *testing.T) {
	buf := make([]byte, 0x2000)
	lt.PutNote(buf, 0x100, "OSRELEASE=6.17.0\nKEY=\x01\n")
	lt.PutNote(buf, 0x1000, "OSRELEASE=6.17.0\n")
	rows, diags, err := run(buf, false)
	if err != nil || len(rows) != 1 || rows[0].Offset != 0x1000 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "0x100") {
		t.Errorf("diagnostics %q", diags)
	}
	_, _, err = run(buf, true)
	var damage *autoload.VMCoreInfoDamageError
	if !errors.As(err, &damage) || !strings.Contains(err.Error(), "0x100") {
		t.Errorf("strict: %v", err)
	}
}

func TestPhysicalMemoryIsRequired(t *testing.T) {
	if _, err := Run(tools.Context{}); !errors.Is(err, ErrNoPhysical) {
		t.Errorf("%v", err)
	}
}

func FuzzNotes(f *testing.F) {
	seed := make([]byte, 0x200)
	lt.PutNote(seed, 0x10, "OSRELEASE=6.17.0\nPAGESIZE=4096\n")
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		rows, _, err := run(data, false)
		if err != nil {
			return
		}
		at := map[uint64]int{}
		for _, r := range rows {
			if at[r.Offset] == 0 && r.Key != "OSRELEASE" {
				t.Fatalf("note at 0x%x opens with %q", r.Offset, r.Key)
			}
			at[r.Offset]++
			if r.Offset+24 > uint64(len(data)) {
				t.Fatalf("note at 0x%x outside the image", r.Offset)
			}
		}
	})
}
