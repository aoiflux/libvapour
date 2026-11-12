package poolscan

import (
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
)

const (
	nonPaged = 2
	paged    = 3
)

type fixture struct {
	img    *fxImage
	bodies map[string]uint64
}

// One allocation of every kind the tool scans, each in its own 0x200-byte
// slot of the pool pages, and some that a rule refuses.
func newFixture() fixture {
	img := newImage(4)
	f := fixture{img: img, bodies: map[string]uint64{}}
	slot := func(i int) uint64 { return fxPoolAt + uint64(i)*0x200 }

	p := img.object(fxObject{pool: slot(0), tag: "Proc", poolType: nonPaged, bodySize: fxProcessSize,
		dispatch: scan.ProcessObject})
	img.mem.u64(p+0x40, 0x1234)
	copy(img.mem.buf[p+0x80:], "lsass.exe")
	f.bodies["process"] = p

	bad := img.object(fxObject{pool: slot(1), tag: "Proc", poolType: nonPaged, bodySize: fxProcessSize,
		dispatch: scan.ProcessObject})
	img.mem.u64(bad+0x40, 0x1235)
	copy(img.mem.buf[bad+0x80:], "odd.exe")

	th := img.object(fxObject{pool: slot(2), tag: "Thre", poolType: nonPaged, bodySize: fxThreadSize,
		dispatch: scan.ThreadObject})
	img.mem.u64(th+0x48, 0x1234)
	img.mem.u64(th+0x50, 0x88)
	f.bodies["thread"] = th

	file := img.object(fxObject{pool: slot(3), tag: "File", poolType: nonPaged, bodySize: fxFileSize,
		dispatch: scan.IOTypeFile})
	img.ustr(file+0x20, `\Windows\System32\config\SAM`)
	f.bodies["file"] = file
	f.bodies["unnamed file"] = img.object(fxObject{pool: slot(4), tag: "File", poolType: nonPaged,
		bodySize: fxFileSize, dispatch: scan.IOTypeFile})
	img.object(fxObject{pool: slot(5), tag: "File", poolType: nonPaged, bodySize: fxFileSize, dispatch: 9})

	f.bodies["mutant"] = img.object(fxObject{pool: slot(6), tag: "Muta", poolType: nonPaged, bodySize: fxMutantSize,
		name: "SessionMutex", dispatch: scan.MutantObject})
	f.bodies["driver"] = img.object(fxObject{pool: slot(7), tag: "Driv", poolType: nonPaged, bodySize: fxDriverSize,
		name: "Tcpip", dispatch: scan.IOTypeDriver})
	f.bodies["link"] = img.object(fxObject{pool: slot(8), tag: "Symb", poolType: paged, bodySize: fxLinkSize,
		name: "C:"})
	img.object(fxObject{pool: slot(9), tag: "Symb", poolType: nonPaged, bodySize: fxLinkSize, name: "D:"})

	module := img.structure(slot(10), "MmLd", fxModuleSize)
	img.ustr(module+0x48, "ntoskrnl.exe")
	f.bodies["module"] = module
	f.bodies["atom"] = img.structure(slot(11), "AtmT", fxAtomSize)
	return f
}

func rowsByType(rows []Allocation) map[string][]Allocation {
	out := map[string][]Allocation{}
	for _, r := range rows {
		out[r.Type] = append(out[r.Type], r)
	}
	return out
}

func TestEveryKindIsReportedWithItsName(t *testing.T) {
	f := newFixture()
	ctx, diags := f.img.context(fxTable())
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := rowsByType(rows)
	for _, tc := range []struct {
		typ, tag, body string
		names          []string
	}{
		{"_EPROCESS", "Proc", "process", []string{"lsass.exe"}},
		{"_ETHREAD", "Thre", "thread", []string{""}},
		{"_FILE_OBJECT", "File", "file", []string{`\Windows\System32\config\SAM`, ""}},
		{"_KMUTANT", "Muta", "mutant", []string{"SessionMutex"}},
		{"_DRIVER_OBJECT", "Driv", "driver", []string{"Tcpip"}},
		{"_OBJECT_SYMBOLIC_LINK", "Symb", "link", []string{"C:"}},
		{"_KLDR_DATA_TABLE_ENTRY", "MmLd", "module", []string{"ntoskrnl.exe"}},
		{"_RTL_ATOM_TABLE", "AtmT", "atom", []string{""}},
	} {
		rs := got[tc.typ]
		if len(rs) != len(tc.names) {
			t.Errorf("%s: %d rows %+v, want %d", tc.typ, len(rs), rs, len(tc.names))
			continue
		}
		for i, r := range rs {
			if r.Tag != tc.tag || r.Name != tc.names[i] || r.Address != 0 || r.MappingsKnown || r.TypeIndexFailed {
				t.Errorf("%s row %d: %+v, want tag %q name %q and no kernel placement", tc.typ, i, r, tc.tag, tc.names[i])
			}
		}
	}
	if len(rows) != 9 {
		t.Errorf("%d rows, want 9: the odd PID, the wrong file Type and the nonpaged link are refused", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].Physical > rows[i].Physical {
			t.Fatalf("rows not in physical order without kernel addresses: %+v", rows)
		}
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "9 rows: 1 _DRIVER_OBJECT, 1 _EPROCESS") {
		t.Errorf("diagnostics %q do not count the rows by type", *diags)
	}
}

func TestPhysicalIsThePoolHeader(t *testing.T) {
	f := newFixture()
	ctx, _ := f.img.context(fxTable())
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rowsByType(rows)["_KMUTANT"] {
		if want := f.bodies["mutant"] - fxBodyAt - fxNameInfo - fxHeaderLen; r.Physical != want {
			t.Errorf("mutant Physical 0x%x, want its pool header 0x%x", r.Physical, want)
		}
	}
}

type withoutMember struct {
	symbols.SymbolTable
	typ, member string
}

func (w withoutMember) Field(typ, member string) (symbols.Field, error) {
	if typ == w.typ && member == w.member {
		return symbols.Field{}, symbols.UnknownTypeError{TypeName: typ + "." + member}
	}
	return w.SymbolTable.Field(typ, member)
}

func TestAKindWithoutItsCheckMembersIsSkipped(t *testing.T) {
	f := newFixture()
	for _, tc := range []struct{ typ, member, kind, diag string }{
		{"_EPROCESS", "ImageFileName", "_EPROCESS", "processes not scanned"},
		{"_ETHREAD", "Cid", "_ETHREAD", "threads not scanned"},
	} {
		ctx, diags := f.img.context(withoutMember{fxTable(), tc.typ, tc.member})
		rows, err := Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(rowsByType(rows)[tc.kind]); n != 0 {
			t.Errorf("without %s.%s: %d %s rows, want none", tc.typ, tc.member, n, tc.kind)
		}
		if !strings.Contains(strings.Join(*diags, "\n"), tc.diag) {
			t.Errorf("without %s.%s: diagnostics %q lack %q", tc.typ, tc.member, *diags, tc.diag)
		}
	}
}

func TestRunRefusesWhatItCannotScan(t *testing.T) {
	f := newFixture()
	ctx, _ := f.img.context(fxTable())
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Errorf("a Linux profile was scanned")
	}
	ctx, _ = f.img.context(fxTable())
	delete(ctx.Options, "physical_memory")
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "no physical memory") {
		t.Errorf("no physical layer: %v", err)
	}
}

func TestCountedStringReadsTheBufferFromKernelMemory(t *testing.T) {
	img := newImage(1)
	ctx, _ := img.context(fxTable())
	c := newCountedString(ctx, "_FILE_OBJECT", "FileName")
	body := uint64(fxPoolAt + 0x40)
	img.ustr(body+0x20, "a\x00b\x00")
	if got := c.read(img.mem, body); got != "a␀b" {
		t.Errorf("name %q, want the embedded NUL shown and the trailing one dropped", got)
	}
	img.mem.u64(body+0x28, 0)
	if got := c.read(img.mem, body); got != "" {
		t.Errorf("a null Buffer read as %q", got)
	}
	if got := newCountedString(ctx, "_FILE_OBJECT", "Missing").read(img.mem, body); got != "" {
		t.Errorf("an unresolved member read as %q", got)
	}
}
