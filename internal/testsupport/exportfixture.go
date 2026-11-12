package testsupport

import (
	"encoding/binary"
	"sort"
)

const (
	ExportImageSize   = uint32(0x8000)
	ExportCodeRVA     = uint32(0x1000)
	ExportDirRVA      = uint32(0x2000)
	ExportOrdinalBase = uint32(1)

	exportDirectorySize = uint32(40)
	exportCodeStride    = uint32(16)
	exportRawPointer    = fixtureImageHeaderSize
)

type FixtureExport struct {
	Name      string
	Body      []byte
	Forwarder string
	RVA       uint32
}

func ExportRVA(i int) uint32 {
	return ExportCodeRVA + uint32(i)*exportCodeStride
}

type exportArea struct {
	img  []byte
	next uint32
}

func (a *exportArea) take(n uint32) uint32 {
	at := a.next
	a.next += n
	if a.next > ExportImageSize {
		panic("testsupport: export data does not fit the fixture image")
	}
	return at
}

func (a *exportArea) text(s string) uint32 {
	at := a.take(uint32(len(s)) + 1)
	copy(a.img[at:], s)
	return at
}

// Everything the directory points at lies inside the range the data
// directory gives, which is what makes a function RVA that points into it a
// forwarder (S79 D4).
func BuildExportingPE(imageBase uint64, exports []FixtureExport) []byte {
	code := peSection{name: ".text", rva: ExportCodeRVA, size: ExportImageSize - ExportCodeRVA,
		rawPointer: exportRawPointer, rawLen: ExportImageSize - ExportCodeRVA}
	p := newPEImage(ExportImageSize, imageBase, fileExecutableImage|fileDLL, []peSection{code})
	le := binary.LittleEndian

	var named []int
	for i, e := range exports {
		if e.Name != "" {
			named = append(named, i)
		}
	}
	sort.SliceStable(named, func(a, b int) bool { return exports[named[a]].Name < exports[named[b]].Name })

	area := &exportArea{img: p.img, next: ExportDirRVA}
	dir := area.take(exportDirectorySize)
	functions := area.take(4 * uint32(len(exports)))
	names := area.take(4 * uint32(len(named)))
	ordinals := area.take(2 * uint32(len(named)))

	for i, e := range exports {
		rva := ExportRVA(i)
		if e.RVA != 0 {
			rva = e.RVA
		}
		switch {
		case e.Forwarder != "":
			rva = area.text(e.Forwarder)
		case len(e.Body) > 0:
			copy(p.img[rva:], e.Body)
		}
		le.PutUint32(p.img[functions+4*uint32(i):], rva)
	}
	for slot, i := range named {
		le.PutUint32(p.img[names+4*uint32(slot):], area.text(exports[i].Name))
		le.PutUint16(p.img[ordinals+2*uint32(slot):], uint16(i))
	}

	d := p.img[dir:]
	le.PutUint32(d[16:], ExportOrdinalBase)
	le.PutUint32(d[20:], uint32(len(exports)))
	le.PutUint32(d[24:], uint32(len(named)))
	le.PutUint32(d[28:], functions)
	le.PutUint32(d[32:], names)
	le.PutUint32(d[36:], ordinals)
	p.setExportDirectory(ExportDirRVA, area.next-ExportDirRVA)
	return p.img
}
