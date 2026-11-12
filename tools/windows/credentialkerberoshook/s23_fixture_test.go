package credentialkerberoshook

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
)

const (
	fxLSASS      = uint64(916)
	fxBase       = uint64(0x7ff9_0710_0000)
	fxOther      = uint64(0x7ff9_0720_0000)
	fxPrivate    = uint64(0x0000_0250_0000)
	fxDebugRVA   = uint32(0x3000)
	fxRSDSRVA    = uint32(0x3100)
	fxNameRVA    = uint32(0x4000)
	fxCountRVA   = uint32(0x5000)
	fxTableRVA   = uint32(0x5100)
	fxPDBName    = "cryptdll.pdb"
	fxDirDebugAt = 160
)

var fxGUID = [16]byte{0x59, 0xda, 0xbc, 0x3e, 0x9e, 0x10, 0xef, 0xd8, 0xb1, 0xb1, 0x9a, 0x2d, 0xba, 0x73, 0x55, 0xbd}

// The mem1 CDLocateCSystem body (S23 M2) with its two displacements made to
// reach the fixture's count and table from the export's RVA.
func locateBody(rva, countRVA, tableRVA uint32) []byte {
	b := []byte{0x8b, 0x05, 0, 0, 0, 0, 0x4c, 0x8d, 0x15, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[2:], countRVA-(rva+6))
	binary.LittleEndian.PutUint32(b[9:], tableRVA-(rva+13))
	return append(b, 0x44, 0x8b, 0xc9, 0x44, 0x8b, 0xc0, 0xff, 0xc8, 0x45, 0x85, 0xc0, 0x74, 0x15, 0x8b, 0xc8,
		0x48, 0xc1, 0xe1, 0x07, 0x49, 0x03, 0xca, 0x44, 0x39, 0x09, 0x75, 0xe8, 0x48, 0x89, 0x0a, 0x33, 0xc0, 0xc3)
}

type fxEntry struct {
	etype    int32
	name     uint64
	routines map[int]uint64
}

func (e fxEntry) bytes() []byte {
	b := make([]byte, entrySize)
	binary.LittleEndian.PutUint32(b[entryTypeOffset:], uint32(e.etype))
	binary.LittleEndian.PutUint64(b[entryNameOffset:], e.name)
	for off, p := range e.routines {
		binary.LittleEndian.PutUint64(b[off:], p)
	}
	return b
}

func cleanEntry(etype int32) fxEntry {
	r := map[int]uint64{}
	for i, s := range slotOffsets {
		if s.slot == SlotAlternateEncrypt || s.slot == SlotAlternateDecrypt {
			continue
		}
		r[s.offset] = fxBase + 0x1100 + uint64(i)*0x10
	}
	return fxEntry{etype: etype, name: fxBase + uint64(fxNameRVA), routines: r}
}

func utf16z(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(units)+2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	return b
}

type fxImage struct {
	count   uint32
	entries []fxEntry
	noDebug bool
	export  bool
}

func (im fxImage) build() []byte {
	var exports []testsupport.FixtureExport
	if im.export {
		exports = append(exports, testsupport.FixtureExport{Name: locateRoutine,
			Body: locateBody(testsupport.ExportRVA(0), fxCountRVA, fxTableRVA)})
	} else {
		exports = append(exports, testsupport.FixtureExport{Name: "CDLocateCheckSum", Body: []byte{0xc3}})
	}
	img := testsupport.BuildExportingPE(fxBase, exports)
	opt := uint64(binary.LittleEndian.Uint32(img[0x3c:])) + 4 + 20
	if !im.noDebug {
		binary.LittleEndian.PutUint32(img[opt+fxDirDebugAt:], fxDebugRVA)
		binary.LittleEndian.PutUint32(img[opt+fxDirDebugAt+4:], 28)
		cv := append([]byte("RSDS"), fxGUID[:]...)
		cv = binary.LittleEndian.AppendUint32(cv, 1)
		cv = append(cv, []byte(`d:\build\`+fxPDBName+"\x00")...)
		copy(img[fxRSDSRVA:], cv)
		d := img[fxDebugRVA:]
		binary.LittleEndian.PutUint32(d[12:], 2)
		binary.LittleEndian.PutUint32(d[16:], uint32(len(cv)))
		binary.LittleEndian.PutUint32(d[20:], fxRSDSRVA)
	}
	copy(img[fxNameRVA:], utf16z("Kerberos AES256-CTS-HMAC-SHA1-96"))
	binary.LittleEndian.PutUint32(img[fxCountRVA:], im.count)
	for i, e := range im.entries {
		copy(img[fxTableRVA+uint32(i)*entrySize:], e.bytes())
	}
	return img
}

type fxCapture struct {
	image      fxImage
	process    string
	noCryptdll bool
	otherName  string
	symbols    bool
}

type fxRun struct {
	fixture *testsupport.ProcessFixture
	ctx     tools.Context
	diags   *[]string
}

func (c fxCapture) run() fxRun {
	name := c.process
	if name == "" {
		name = lsassImage
	}
	cryptdll := `\Windows\System32\cryptdll.dll`
	if c.noCryptdll {
		cryptdll = `\Windows\System32\bcrypt.dll`
	}
	f := testsupport.BuildProcessFixture([]testsupport.FixtureProcess{
		{PID: 4, Name: "System", NoPeb: true},
		{PID: fxLSASS, Name: name, NoPeb: true, VADs: []testsupport.FixtureVAD{
			{Start: fxPrivate, End: fxPrivate + 0xfff, Protection: testsupport.FixtureProtectionExecuteReadWrite},
			{Start: fxBase, End: fxBase + uint64(testsupport.ExportImageSize) - 1, Path: cryptdll,
				Protection: testsupport.FixtureProtectionExecuteWriteCopy},
			{Start: fxOther, End: fxOther + 0x1fff, Path: `\Windows\System32\extra.dll`,
				Protection: testsupport.FixtureProtectionExecuteWriteCopy},
		}},
	})
	space := f.Space(fxLSASS)
	space.MapImage(fxBase, c.image.build())
	other := make([]byte, 0x2000)
	if c.otherName != "" {
		copy(other, utf16z(c.otherName))
	}
	space.MapImage(fxOther, other)
	ctx := f.Context()
	diags := []string{}
	ctx.Options["diagnostics"] = &diags
	if c.symbols {
		ctx.LoadPDB = fxLoadPDB
	}
	return fxRun{fixture: f, ctx: ctx, diags: &diags}
}

func fxLoadPDB(fp autoload.Fingerprint) (symbols.SymbolTable, error) {
	want := autoload.Fingerprint{PDBName: fxPDBName, GUID: autoload.FormatGUID(fxGUID[:]), Age: 1}
	if fp != want {
		return nil, errors.New("fixture: unknown pdb " + fp.String())
	}
	t := symbols.NewTable("cryptdll-fixture", 8)
	t.AddSymbol(symbols.Symbol{Name: symbolTable, Address: uint64(fxTableRVA)})
	t.AddSymbol(symbols.Symbol{Name: symbolCount, Address: uint64(fxCountRVA)})
	return t, nil
}
