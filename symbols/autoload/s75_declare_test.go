package autoload

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
)

func TestADownloadIsBoundBeforeAndWhileItIsRead(t *testing.T) {
	if _, err := readPDBBody(strings.NewReader("12345"), 6, 5); !errors.Is(err, errBodyTooLarge) {
		t.Errorf("declared past the bound: %v", err)
	}
	if _, err := readPDBBody(strings.NewReader("123456"), -1, 5); !errors.Is(err, errBodyTooLarge) {
		t.Errorf("sent past the bound: %v", err)
	}
	if got, err := readPDBBody(strings.NewReader("12345"), -1, 5); err != nil || string(got) != "12345" {
		t.Errorf("exactly the bound: %q (%v)", got, err)
	}
}

func cacheFile(t *testing.T, d symbols.Declaration) string {
	t.Helper()
	var b bytes.Buffer
	if err := symbols.Encode(&b, d); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "table.vsym")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestACachedTableMustBeForTheBuildAndHoldSymbols(t *testing.T) {
	fp := &Fingerprint{PDBName: "ntkrnlmp.pdb", GUID: strings.Repeat("ab", 16), Age: 3}
	table := func(guid string, age uint32, addresses ...symbols.Address) symbols.Declaration {
		return symbols.Declaration{PointerWidth: 8, WindowsPDB: &symbols.PDBBuild{GUID: guid, Age: age}, Addresses: addresses}
	}
	one := symbols.Address{Name: "KiServiceTable", Address: 0x1000}
	if _, err := loadCached(cacheFile(t, table(strings.Repeat("AB", 16), 3, one)), fp, symbols.ReadOptions{}); err != nil {
		t.Errorf("the build's table in other letter case: %v", err)
	}
	for name, d := range map[string]symbols.Declaration{
		"another age":  table(strings.Repeat("AB", 16), 4, one),
		"another GUID": table(strings.Repeat("CD", 16), 3, one),
		"no symbols":   table(strings.Repeat("AB", 16), 3),
	} {
		if _, err := loadCached(cacheFile(t, d), fp, symbols.ReadOptions{}); !errors.Is(err, errCacheMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := loadCached(filepath.Join(t.TempDir(), "absent.vsym"), fp, symbols.ReadOptions{}); err == nil {
		t.Error("an absent file was loaded")
	}
}

func TestNamesBecomeUTF8AndTheLaterOfTwoThatMeetKeepsThePlace(t *testing.T) {
	if got := validText("a\xff\xfebé"); got != "a��bé" {
		t.Errorf("validText = %q", got)
	}
	d := declaration(strings.Repeat("AB", 16), 1, 8,
		map[string]pdbRecord{
			"_A\xff": {Size: 8, Fields: map[string]pdbMember{"X": {Offset: 0}}},
			"_A\xfe": {Size: 16, Fields: map[string]pdbMember{"Y": {Offset: 8}}},
			"_Empty": {Size: 4, Fields: map[string]pdbMember{}},
		}, nil,
		map[string]uint64{"b": 2, "a": 1})
	if len(d.Records) != 1 || d.Records[0].Name != "_A�" || d.Records[0].Width != 8 || d.Records[0].Members[0].Name != "X" {
		t.Errorf("records %+v, want one _A� of 8 bytes", d.Records)
	}
	if len(d.Addresses) != 2 || d.Addresses[0].Name != "a" || d.Addresses[1].Name != "b" {
		t.Errorf("addresses %+v, want name order", d.Addresses)
	}
	if d.PointerWidth != 8 || d.WindowsPDB.Age != 1 {
		t.Errorf("build %+v width %d", d.WindowsPDB, d.PointerWidth)
	}
	pointer := false
	for _, s := range d.Scalars {
		pointer = pointer || s.Name == "pointer" && s.Width == 8
	}
	if !pointer {
		t.Errorf("scalars %+v hold no 8-byte pointer", d.Scalars)
	}
}
