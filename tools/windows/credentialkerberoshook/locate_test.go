package credentialkerberoshook

import (
	"encoding/hex"
	"strings"
	"testing"
)

// CDLocateCSystem as read on the captures (S23 M2), with the view start,
// the routine's RVA and the RVAs of cCSystems and CSystems.
var measuredLocate = []struct {
	capture            string
	view, rva          uint64
	countRVA, tableRVA uint64
	code               string
}{
	{"mem1", 0x7ffcae970000, 0x3150, 0xeb00, 0xf1e0,
		"8b 05 aa b9 00 00 4c 8d 15 83 c0 00 00 44 8b c9 44 8b c0 ff c8 45 85 c0 74 15 8b c8 48 c1 e1 07 49 03 ca 44 39 09 75 e8 48 89 0a 33 c0 c3"},
	{"mem2", 0x7ff9071f0000, 0x15d0, 0xfac0, 0x101a0,
		"44 8b 05 e9 e4 00 00 eb 19 41 ff c8 4c 8d 0d bd eb 00 00 41 8b c0 48 c1 e0 07 4c 03 c8 41 39 09 74 0c 45 85 c0 75 e2 b8 41 03 08 80 c3"},
	{"mem5", 0x7ff9ec900000, 0x2760, 0x10d7c, 0xf500,
		"8b 05 16 e6 00 00 85 c0 74 1a 4c 8d 0d 8f cd 00 00 ff c8 44 8b c0 49 c1 e0 07 43 39 0c 08 74 0a 85 c0 75 ed b8 41 03 08 80 c3"},
}

func codeBytes(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func TestMeasuredLocateRoutinesGiveTheirCountAndTable(t *testing.T) {
	for _, m := range measuredLocate {
		head, ok := headFromLocateCode(codeBytes(m.code), m.view+m.rva)
		if !ok {
			t.Errorf("%s: refused", m.capture)
			continue
		}
		if head.count != m.view+m.countRVA || head.array != m.view+m.tableRVA || head.source != SourceCode {
			t.Errorf("%s: count 0x%x table 0x%x source %s", m.capture, head.count, head.array, head.source)
		}
	}
}

func TestLocateCodeOfAnotherShapeIsRefused(t *testing.T) {
	mem1 := measuredLocate[0].code
	at := measuredLocate[0].view + measuredLocate[0].rva
	cases := map[string]string{
		"shift by 6":   strings.Replace(mem1, "48 c1 e1 07", "48 c1 e1 06", 1),
		"no lea":       strings.Replace(mem1, "4c 8d 15 83 c0 00 00", "4c 8b 15 83 c0 00 00", 1),
		"no dword mov": strings.Replace(mem1, "8b 05 aa b9 00 00", "8b c1 90 90 90 90", 1),
		"ret first":    "c3 " + mem1,
		"empty":        "",
		"undecodable":  "0f 0b 0f",
	}
	for name, code := range cases {
		if head, ok := headFromLocateCode(codeBytes(code), at); ok {
			t.Errorf("%s: accepted %+v", name, head)
		}
	}
}

func TestLocateStopsAtItsWindow(t *testing.T) {
	pad := strings.Repeat("90 ", locateWindow)
	if _, ok := headFromLocateCode(codeBytes(pad+measuredLocate[0].code), 0x10000); ok {
		t.Error("a routine past the window was decoded")
	}
}
