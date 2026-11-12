package pe

import (
	"errors"
	"testing"
)

const dbDir = uint32(0x1000)

var dbGUID = [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 1, 2, 3, 4, 5, 6, 7, 8}

func dbEntry(img []byte, i int, typ, size, rva uint32) {
	at := uint64(dbDir) + uint64(i)*debugDirectoryEntrySize
	put32(img, at+debugEntryTypeOffset, typ)
	put32(img, at+debugEntrySizeOffset, size)
	put32(img, at+debugEntryRVAOffset, rva)
}

func dbRecord(img []byte, at uint32, magic, path string, age uint32) uint32 {
	copy(img[at:], magic)
	copy(img[at+4:], dbGUID[:])
	put32(img, uint64(at)+20, age)
	copy(img[at+24:], path+"\x00")
	return uint32(24 + len(path) + 1)
}

func TestTheFirstRSDSRecordInDirectoryOrderIsRead(t *testing.T) {
	img := make([]byte, 0x3000)
	dbEntry(img, 0, 13, 0x20, 0x1800)
	size := dbRecord(img, 0x1200, "NB10", `c:\old.pdb`, 1)
	dbEntry(img, 1, DebugTypeCodeView, size, 0x1200)
	size = dbRecord(img, 0x1300, codeViewMagic, `D:\build\amd64\ntkrnlmp.pdb`, 3)
	dbEntry(img, 2, DebugTypeCodeView, size, 0x1300)
	dbEntry(img, 3, DebugTypeCodeView, dbRecord(img, 0x1400, codeViewMagic, "second.pdb", 9), 0x1400)
	cv, err := ReadCodeView(flat(img), DataDirectory{dbDir, 4 * debugDirectoryEntrySize})
	if err != nil {
		t.Fatal(err)
	}
	if cv.GUID != dbGUID || cv.Age != 3 || cv.PDBPath != `D:\build\amd64\ntkrnlmp.pdb` || cv.RVA != 0x1300 {
		t.Errorf("%+v", cv)
	}
	for path, want := range map[string]string{`a\b\c.pdb`: "c.pdb", "x/y.pdb": "y.pdb", "bare.pdb": "bare.pdb", `dir\`: ""} {
		if got := (CodeView{PDBPath: path}).PDBName(); got != want {
			t.Errorf("PDBName(%q) = %q", path, got)
		}
	}
}

func TestAnUnreadRecordIsReportedAsUnreadNotAbsent(t *testing.T) {
	img := make([]byte, 0x3000)
	dbEntry(img, 0, DebugTypeCodeView, dbRecord(img, 0x2100, codeViewMagic, "k.pdb", 1), 0x2100)
	dir := DataDirectory{dbDir, debugDirectoryEntrySize}
	if _, err := ReadCodeView(withHoles(img, 0x2000), dir); !errors.Is(err, ErrUnreadable) {
		t.Errorf("record page unread: %v", err)
	}
	if _, err := ReadCodeView(withHoles(img, 0x1000), dir); !errors.Is(err, ErrUnreadable) {
		t.Errorf("directory page unread: %v", err)
	}
	if cv, err := ReadCodeView(flat(img), dir); err != nil || cv.PDBPath != "k.pdb" {
		t.Errorf("all read: %+v %v", cv, err)
	}
}

func TestCodeViewFailures(t *testing.T) {
	entry := DataDirectory{dbDir, debugDirectoryEntrySize}
	for _, tc := range []struct {
		name string
		dir  DataDirectory
		edit func([]byte)
		want error
	}{
		{"no directory", DataDirectory{}, func([]byte) {}, ErrNoDebugDirectory},
		{"no whole entry", DataDirectory{dbDir, 27}, func([]byte) {}, ErrBadDebugDirectory},
		{"no CodeView entry", entry, func(b []byte) { dbEntry(b, 0, 16, 0x20, 0x1800) }, ErrNoCodeView},
		{"not mapped", entry, func(b []byte) { dbEntry(b, 0, DebugTypeCodeView, 0x30, 0) }, ErrNoCodeView},
		{"too short for a path", entry, func(b []byte) {
			dbRecord(b, 0x1800, codeViewMagic, "", 1)
			dbEntry(b, 0, DebugTypeCodeView, 24, 0x1800)
		}, ErrNoCodeView},
		{"empty path", entry, func(b []byte) {
			dbEntry(b, 0, DebugTypeCodeView, dbRecord(b, 0x1800, codeViewMagic, "", 1), 0x1800)
		}, ErrNoCodeView},
		{"no NUL inside SizeOfData", entry, func(b []byte) {
			dbEntry(b, 0, DebugTypeCodeView, dbRecord(b, 0x1800, codeViewMagic, "long.pdb", 1)-3, 0x1800)
		}, ErrUnterminatedString},
		{"other magic", entry, func(b []byte) {
			dbEntry(b, 0, DebugTypeCodeView, dbRecord(b, 0x1800, "NB10", "x.pdb", 1), 0x1800)
		}, ErrNoCodeView},
	} {
		img := make([]byte, 0x3000)
		tc.edit(img)
		if _, err := ReadCodeView(flat(img), tc.dir); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}
