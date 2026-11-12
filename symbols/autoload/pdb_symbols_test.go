package autoload

import (
	"strings"
	"testing"
)

func TestX86CNamesLoseOnlyTheirDocumentedDecoration(t *testing.T) {
	cases := map[string]string{
		"_KeServiceDescriptorTable":              "KeServiceDescriptorTable",
		"_NtCreateFile@44":                       "NtCreateFile",
		"@KfRaiseIrql@4":                         "KfRaiseIrql",
		"Vector@@16":                             "Vector",
		"_NoArguments@0":                         "NoArguments",
		"___RtlUserThreadStart@8":                "__RtlUserThreadStart",
		"?Method@Class@@QAEXXZ":                  "?Method@Class@@QAEXXZ",
		"__real@3fe0000000000000":                "__real@3fe0000000000000",
		"__xmm@00010001000100010001000100010001": "__xmm@00010001000100010001000100010001",
		"__xmm@80000000000000008000000000000000": "__xmm@80000000000000008000000000000000",
		"___@@_PchSym_@00@Kxu@tp":                "___@@_PchSym_@00@Kxu@tp",
		"ExecuteHandler@20":                      "ExecuteHandler@20",
		"_Name@x":                                "_Name@x",
		"_":                                      "",
		"plain":                                  "plain",
		"_@4":                                    "_@4",
	}
	for in, want := range cases {
		if got := undecorateC(in); got != want {
			t.Errorf("undecorateC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPublicsComeFirstAndTheFirstOfANameIsKept(t *testing.T) {
	f := newFixture()
	f.modules = [][]procedureSpec{{{name: "Shared", segment: 1, offset: 0x30}, {name: "StaticOnly", segment: 2, offset: 0x40}, {name: "StaticOnly", segment: 1, offset: 0x10}}}
	_, at := moduleStreamOf(f.modules[0]...)
	f.publics = []publicSpec{
		{kind: sLProcRef, name: "Shared", module: 1, offset: at[0]},
		{kind: sPub32, name: "Shared", segment: 1, offset: 0x20},
		{kind: sLProcRef, name: "StaticOnly", module: 1, offset: at[1]},
		{kind: sLProcRef, name: "StaticOnly", module: 1, offset: at[2]},
		{kind: sPub32, name: "Twice", segment: 1, offset: 0x50},
		{kind: sPub32, name: "Twice", segment: 2, offset: 0x60},
		{kind: sProcRef, name: "GlobalProc", module: 1, offset: at[0]},
		{kind: sGData32, name: "GlobalData", segment: 1, offset: 0x70},
		{kind: sLData32, name: "StaticData", segment: 2, offset: 0x80},
	}
	got := f.convert(t)
	want := map[string]uint64{"Shared": 0x1020, "StaticOnly": 0x5040, "Twice": 0x1050, "StaticData": 0x5080}
	for name, address := range want {
		if got[name] != address {
			t.Errorf("%s at %#x, want %#x", name, got[name], address)
		}
	}
	for _, name := range []string{"GlobalProc", "GlobalData"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s was placed; a global's place is its public", name)
		}
	}
}

func TestAProcedureReferenceMustLeadToAProcedureOfItsName(t *testing.T) {
	f := newFixture()
	f.modules = [][]procedureSpec{{{name: "Real", segment: 1, offset: 0x30}}}
	_, at := moduleStreamOf(f.modules[0]...)
	f.publics = []publicSpec{
		{kind: sPub32, name: "Anchor", segment: 1},
		{kind: sLProcRef, name: "Other", module: 1, offset: at[0]},
		{kind: sLProcRef, name: "Real", module: 2, offset: at[0]},
		{kind: sLProcRef, name: "Real", module: 1, offset: at[0] + 1},
		{kind: sLProcRef, name: "Real", module: 1, offset: 2},
		{kind: sLProcRef, name: "Real", module: 1, offset: 1 << 20},
	}
	got := f.convert(t)
	if _, ok := got["Other"]; ok {
		t.Error("a reference whose procedure has another name was placed")
	}
	if _, ok := got["Real"]; ok {
		t.Error("a reference to another module, a misaligned offset or the signature was placed")
	}
}

func TestOnlyASegmentNamingASectionPlacesASymbol(t *testing.T) {
	f := newFixture()
	f.publics = []publicSpec{
		{kind: sPub32, name: "First", segment: 1, offset: 4},
		{kind: sPub32, name: "Last", segment: 2, offset: 8},
		{kind: sPub32, name: "Absolute", segment: 0, offset: 8},
		{kind: sPub32, name: "Past", segment: 3, offset: 8},
		{kind: sPub32, name: "Wraps", segment: 2, offset: 0xffffffff},
	}
	got := f.convert(t)
	if got["First"] != 0x1004 || got["Last"] != 0x5008 {
		t.Errorf("First %#x Last %#x", got["First"], got["Last"])
	}
	for _, name := range []string{"Absolute", "Past", "Wraps"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s was placed", name)
		}
	}
}

func TestAnOMAPPDBPlacesSymbolsInTheFinalImage(t *testing.T) {
	f := newFixture()
	f.original = []uint32{0x1000, 0x0800}
	f.omap = [][2]uint32{{0x2000, 0}, {0x1000, 0x8000}, {0x1100, 0x9000}}
	f.publics = []publicSpec{
		{kind: sPub32, name: "Moved", segment: 1, offset: 0x10},
		{kind: sPub32, name: "SecondBlock", segment: 1, offset: 0x180},
		{kind: sPub32, name: "Removed", segment: 1, offset: 0x1004},
		{kind: sPub32, name: "BeforeTheMap", segment: 2, offset: 0},
	}
	got := f.convert(t)
	if got["Moved"] != 0x8010 || got["SecondBlock"] != 0x9080 {
		t.Errorf("Moved at %#x, SecondBlock at %#x; want 0x8010 and 0x9080", got["Moved"], got["SecondBlock"])
	}
	for _, name := range []string{"Removed", "BeforeTheMap"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s was placed", name)
		}
	}

	f.omap = nil
	if got := f.convert(t); got["Moved"] != 0x1010 {
		t.Errorf("without an OMAP stream the final section headers place Moved at %#x, want 0x1010", got["Moved"])
	}
}

func TestADebugInfoStreamOutsideItsBoundsIsRefused(t *testing.T) {
	f := newFixture()
	f.publics = []publicSpec{{kind: sPub32, name: "A", segment: 1}}
	streams := f.streams()
	dbi := streams[pdbDebugStream]
	c, err := readMSF(writeMSF(512, streams))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readDebugInfo(c, dbi[:debugHeaderSize-1]); err == nil {
		t.Error("a short header was read")
	}
	bad := append([]byte(nil), dbi...)
	copy(bad[debugSubstreamsAt:], leafWriter(nil).u32(uint32(len(dbi))))
	if _, err := readDebugInfo(c, bad); err == nil {
		t.Error("a module substream past the stream was read")
	}
	negative := append([]byte(nil), dbi...)
	copy(negative[debugOptionalSizeAt:], leafWriter(nil).u32(0xfffffff0))
	if _, err := readDebugInfo(c, negative); err == nil {
		t.Error("a negative substream size was read")
	}
	signature := append([]byte(nil), dbi...)
	copy(signature, leafWriter(nil).u32(930803))
	if _, err := readDebugInfo(c, signature); err == nil || !strings.Contains(err.Error(), "not -1") {
		t.Errorf("an old header signature: %v", err)
	}
}

func TestModuleEntriesStopAtOneThatDoesNotFit(t *testing.T) {
	entry := make(leafWriter, moduleEntryFixed)
	entry = entry.str("a.obj").str("a.obj")
	for len(entry)%4 != 0 {
		entry = append(entry, 0)
	}
	two := append(append(leafWriter(nil), entry...), entry...)
	if got := readModules(two); len(got) != 2 {
		t.Fatalf("read %d modules, want 2", len(got))
	}
	if got := readModules(append(append(leafWriter(nil), entry...), entry[:moduleEntryFixed+3]...)); len(got) != 1 {
		t.Fatalf("read %d modules from one and a cut one", len(got))
	}
}

func FuzzAddresses(f *testing.F) {
	fixture := newFixture()
	fixture.modules = [][]procedureSpec{{{name: "P", segment: 1, offset: 4}}}
	_, at := moduleStreamOf(fixture.modules[0]...)
	fixture.publics = []publicSpec{{kind: sPub32, name: "_A@4", segment: 1}, {kind: sLProcRef, name: "P", module: 1, offset: at[0]}}
	streams := fixture.streams()
	f.Add(streams[pdbDebugStream], symbolRecordsOf(fixture.publics...), true)
	f.Fuzz(func(t *testing.T, dbi, records []byte, decorated bool) {
		s := fixture.streams()
		s[pdbDebugStream] = dbi
		s = append(s, records)
		c, err := readMSF(writeMSF(512, s))
		if err != nil {
			return
		}
		info, err := readDebugInfo(c, dbi)
		if err != nil {
			return
		}
		info.symbolRecords = uint16(len(s) - 1)
		for name, address := range collectAddresses(c, info, decorated) {
			if name == "" || address > 0xffffffff {
				t.Fatalf("placed %q at %#x", name, address)
			}
		}
	})
}

func FuzzUndecorateC(f *testing.F) {
	for _, s := range []string{"_A@4", "@B@8", "C@@16", "?D@@YAXXZ", "__real@3fe0", "_", "@"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := undecorateC(name)
		if got != name && !strings.Contains(name, got) {
			t.Fatalf("undecorateC(%q) = %q is not part of the name", name, got)
		}
		if strings.HasPrefix(name, "?") && got != name {
			t.Fatalf("a C++ name %q changed to %q", name, got)
		}
		if len(got) > len(name) {
			t.Fatalf("undecorateC(%q) = %q grew", name, got)
		}
	})
}
