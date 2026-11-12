package memoryranges

import (
	"slices"
	"strings"
	"testing"
)

func TestProtectionNamesFollowTheDocumentedConstants(t *testing.T) {
	cases := map[uint32]string{
		0x01:       "PAGE_NOACCESS",
		0x02:       "PAGE_READONLY",
		0x10:       "PAGE_EXECUTE",
		0x80:       "PAGE_EXECUTE_WRITECOPY",
		0x204:      "PAGE_READWRITE|PAGE_NOCACHE",
		0x140:      "PAGE_EXECUTE_READWRITE|PAGE_GUARD",
		0x408:      "PAGE_WRITECOPY|PAGE_WRITECOMBINE",
		0x40000020: "PAGE_EXECUTE_READ|PAGE_TARGETS_INVALID",
		0x0:        "0x0",
		0x1002:     "PAGE_READONLY|0x1000",
	}
	for v, want := range cases {
		if got := ProtectionName(v); got != want {
			t.Errorf("ProtectionName(0x%x) = %q, want %q", v, got, want)
		}
		if back, ok := Win32Protection(want); !ok || back != v {
			t.Errorf("Win32Protection(%q) = 0x%x, %v; want 0x%x", want, back, ok, v)
		}
	}
	if v, ok := Win32Protection("PAGE_GUARD|READONLY"); !ok || v != 0x102 {
		t.Errorf("a later part without the prefix: 0x%x, %v", v, ok)
	}
	for _, bad := range []string{"", ProtectionUnknown, "PAGE_NOT_A_CONSTANT", "PAGE_READONLY|", "0x"} {
		if v, ok := Win32Protection(bad); ok {
			t.Errorf("Win32Protection(%q) = 0x%x, true; want unknown", bad, v)
		}
	}
}

func TestEachIndexOfTheMeasuredTableNamesItsProtection(t *testing.T) {
	table := measuredProtectTable()
	for index, want := range map[uint64]string{
		0: "PAGE_NOACCESS", 1: "PAGE_READONLY", 4: "PAGE_READWRITE", 7: "PAGE_EXECUTE_WRITECOPY",
		9: "PAGE_READONLY|PAGE_NOCACHE", 24: "PAGE_NOACCESS", 28: "PAGE_READWRITE|PAGE_WRITECOMBINE",
		31: "PAGE_EXECUTE_WRITECOPY|PAGE_WRITECOMBINE",
	} {
		if got := protectionOf(table, vadFlags{protection: index, protectionOK: true}); got != want {
			t.Errorf("index %d: %q, want %q", index, got, want)
		}
	}
	if got := protectionOf(table, vadFlags{protection: 32, protectionOK: true}); got != ProtectionUnknown {
		t.Errorf("index past the table: %q", got)
	}
	if got := protectionOf(nil, vadFlags{protection: 4, protectionOK: true}); got != ProtectionUnknown {
		t.Errorf("no table: %q", got)
	}
}

func fourKinds() *tImage {
	img := newImage([]tVAD{
		{start: 0x20000, end: 0x2ffff, private: true, protection: 4, commit: 3},
		{start: 0x10000, end: 0x10fff, private: true, protection: 1, kind: 4},
		{start: 0x7ff600000000, end: 0x7ff600003fff, kind: 2, protection: 7, file: `\Windows\System32\ntdll.dll`},
		{start: 0x40000, end: 0x4ffff, protection: 1, file: `\Windows\Fonts\a.ttf`},
	})
	img.root(0)
	img.left(0, 1)
	img.right(0, 3)
	img.right(3, 2)
	return img
}

func TestEveryRowCarriesItsProtectionKindAndFile(t *testing.T) {
	img := fourKinds()
	rows := mappings(t, img, nil)
	if got, want := starts(rows, func(m Mapping) uint64 { return m.Start }), []uint64{0x10000, 0x20000, 0x40000, 0x7ff600000000}; !slices.Equal(got, want) {
		t.Fatalf("starts %x, want %x", got, want)
	}
	want := []struct {
		protection, kind, path string
		private                bool
	}{
		{"PAGE_READONLY", KindPrivate, "", true},
		{"PAGE_READWRITE", KindPrivate, "", true},
		{"PAGE_READONLY", KindMapped, `\Windows\Fonts\a.ttf`, false},
		{"PAGE_EXECUTE_WRITECOPY", KindImage, `\Windows\System32\ntdll.dll`, false},
	}
	for i, w := range want {
		m := rows[i]
		if m.Protection != w.protection || m.Type != w.kind || m.Path != w.path || m.PathUnreadable || m.NoFile != (w.path == "") ||
			m.PrivateMemory != w.private || !m.PrivateMemoryKnown {
			t.Errorf("row %d: %+v, want %+v", i, m, w)
		}
		if m.PID != 404 || m.Process != "smss.exe" || m.DirectoryTableBase != 0x1aa000 || !m.CommitChargeKnown {
			t.Errorf("row %d identity: %+v", i, m)
		}
	}
	if rows[1].VadAddress != nodeAt(0) || rows[1].CommitCharge != 3 || rows[1].ParentUnreadable || rows[1].Parent != 0 {
		t.Errorf("root row %+v", rows[1])
	}
	if rows[3].Parent != nodeAt(3) || rows[3].Tag != "Vad " {
		t.Errorf("image row %+v", rows[3])
	}
	if len(img.diags) != 0 {
		t.Errorf("diagnostics %q", img.diags)
	}
}

func TestTheCommitChargeHighByteSitsAboveTheLowMember(t *testing.T) {
	img := newImage([]tVAD{{start: 0x10000, end: 0x2ffff, private: true, commit: 1<<35 - 2}})
	img.root(0)
	rows := mappings(t, img, nil)
	if rows[0].CommitCharge != 1<<35-2 || !rows[0].CommitChargeKnown {
		t.Errorf("commit 0x%x known %v", rows[0].CommitCharge, rows[0].CommitChargeKnown)
	}
}

func TestUnreadableFlagsLeaveProtectionAndKindUnknown(t *testing.T) {
	img := threeVADs()
	img.mem.drop(nodeAt(0)+tFlagsWord, 4)
	rows := mappings(t, img, nil)
	m := rows[1]
	if m.Protection != ProtectionUnknown || m.Type != KindUnknown || m.PrivateMemoryKnown || m.NoFile || !m.PathUnreadable {
		t.Errorf("row %+v", m)
	}
	if len(img.diags) != 1 || !strings.Contains(img.diags[0], "pid 404 VAD at 0xffff800000100100: flags not read") {
		t.Errorf("diagnostics %q", img.diags)
	}
	ctx := img.ctx(map[string]any{"strict": true})
	d, _ := NewDecoder(ctx)
	if _, err := d.Mappings(ctx, tProcess); err == nil {
		t.Error("strict: no error for unreadable flags")
	}
}

func TestAnUnreadableProtectionTableLeavesEveryProtectionUnknown(t *testing.T) {
	img := threeVADs()
	img.mem.drop(tProtectVA, 4)
	rows := mappings(t, img, nil)
	for _, m := range rows {
		if m.Protection != ProtectionUnknown || m.Type == KindUnknown {
			t.Errorf("row %+v", m)
		}
	}
	if len(img.diags) != 1 || !strings.Contains(img.diags[0], "MmProtectToValue: not read, VAD protections unknown") {
		t.Errorf("diagnostics %q", img.diags)
	}
}

func TestATableWithoutVadTypeCallsEverySectionViewMapped(t *testing.T) {
	img := fourKinds()
	img.t.AddStruct(symbolsWithout(img, "_MMVAD_FLAGS", "VadType"))
	rows := mappings(t, img, nil)
	if rows[3].Type != KindMapped {
		t.Errorf("image view without VadType: %q", rows[3].Type)
	}
}

func TestATagThatIsNotTextIsEmpty(t *testing.T) {
	img := newImage([]tVAD{{start: 0x10000, end: 0x10fff, private: true, tag: "Va\x00S"}})
	img.root(0)
	if rows := mappings(t, img, nil); rows[0].Tag != "" {
		t.Errorf("tag %q", rows[0].Tag)
	}
}
