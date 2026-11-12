package libvapour

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
)

// A synthetic x64 Windows capture. Paging follows S53 P1 and P2: 4-level,
// index bits 47:39, 38:30, 29:21, 20:12, 512 eight-byte entries a table, P
// bit 0, R/W bit 1, frame bits 51:12.
const (
	fxPage      = 0x1000
	fxPresentRW = 0x3
	fxFrameMask = 0x000ffffffffff000
	fxSize      = 4 << 20

	fxKernelBase = 0xfffff80000200000
	fxHeadRVA    = 0x3000
	fxBuildRVA   = 0x4000
	fxSystemVA   = 0xffffc00000100000

	// _EPROCESS and _KPROCESS members as the ntkrnlmp PDB of build 26100
	// places them (S53 W6); _LIST_ENTRY as S76 M5 measures it.
	fxPcb                = 0x0
	fxDirectoryTableBase = 0x28
	fxUniqueProcessID    = 0x1d0
	fxActiveLinks        = 0x1d8
	fxImageFileName      = 0x338
	fxEprocessSize       = fxImageFileName + 15
	fxFlink              = 0x0
	fxBlink              = 0x8

	// KUSER_SHARED_DATA members, S03 B4.
	fxSharedBuild = 0x260
	fxSharedMajor = 0x26c
	fxSharedMinor = 0x270

	// Build 26100 with the decoration nibble 0xF the captures carry (S03 O1).
	fxNtBuildNumber = 0xf00065f4
)

var fxGUID = [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 1, 2, 3, 4, 5, 6, 7, 8}

func fxBuild(guid [16]byte) symbols.PDBBuild {
	return symbols.PDBBuild{Database: "ntkrnlmp.pdb", GUID: autoload.FormatGUID(guid[:]), Age: 1}
}

func fxFingerprint(guid [16]byte) autoload.Fingerprint {
	b := fxBuild(guid)
	return autoload.Fingerprint{PDBName: b.Database, GUID: b.GUID, Age: b.Age}
}

type winCapture struct {
	buf  []byte
	next uint64
	root uint64
}

// Frame 0 is never handed out, so the capture starts with zeros and reads as
// a raw image.
func newWinCapture() *winCapture {
	c := &winCapture{buf: make([]byte, fxSize), next: fxPage}
	c.root = c.frame()
	return c
}

func (c *winCapture) frame() uint64 {
	f := c.next
	c.next += fxPage
	return f
}

func (c *winCapture) put64(pa, v uint64) { binary.LittleEndian.PutUint64(c.buf[pa:], v) }
func (c *winCapture) put32(pa uint64, v uint32) {
	binary.LittleEndian.PutUint32(c.buf[pa:], v)
}

func (c *winCapture) entryFor(va uint64) uint64 {
	table := c.root
	for shift := uint(39); shift > 12; shift -= 9 {
		at := table + (va>>shift&0x1ff)*8
		e := binary.LittleEndian.Uint64(c.buf[at:])
		if e&1 == 0 {
			e = c.frame() | fxPresentRW
			c.put64(at, e)
		}
		table = e & fxFrameMask
	}
	return table + (va>>12&0x1ff)*8
}

func (c *winCapture) mapPage(va uint64) uint64 {
	pa := c.frame()
	c.put64(c.entryFor(va), pa|fxPresentRW)
	return pa
}

func (c *winCapture) setEntry(va, entry uint64) { c.put64(c.entryFor(va), entry) }

// PE Format: MZ, e_lfanew at 0x3C, "PE\0\0", the 20-byte COFF header with
// SizeOfOptionalHeader at 16, the PE32+ optional header (magic 0x20B) with
// NumberOfRvaAndSizes 16 at 108 and the data directories from 112, Debug the
// seventh; a 28-byte debug directory entry, Type 2 at 12, SizeOfData 16,
// AddressOfRawData 20; and the RSDS record of S75 W3.
func peWithCodeView(pdbPath string, guid [16]byte, age uint32) []byte {
	page := make([]byte, fxPage)
	const lfanew, debugDir, record = 0x80, 0x200, 0x240
	copy(page, "MZ")
	binary.LittleEndian.PutUint32(page[0x3c:], lfanew)
	copy(page[lfanew:], "PE\x00\x00")
	coff := lfanew + 4
	binary.LittleEndian.PutUint16(page[coff:], 0x8664)
	binary.LittleEndian.PutUint16(page[coff+16:], 112+16*8)
	optional := coff + 20
	binary.LittleEndian.PutUint16(page[optional:], 0x20b)
	binary.LittleEndian.PutUint32(page[optional+108:], 16)
	binary.LittleEndian.PutUint32(page[optional+112+6*8:], debugDir)
	binary.LittleEndian.PutUint32(page[optional+112+6*8+4:], 28)
	rsds := append([]byte("RSDS"), guid[:]...)
	rsds = binary.LittleEndian.AppendUint32(rsds, age)
	rsds = append(append(rsds, pdbPath...), 0)
	binary.LittleEndian.PutUint32(page[debugDir+12:], 2)
	binary.LittleEndian.PutUint32(page[debugDir+16:], uint32(len(rsds)))
	binary.LittleEndian.PutUint32(page[debugDir+20:], record)
	binary.LittleEndian.PutUint32(page[debugDir+24:], record)
	copy(page[record:], rsds)
	return page
}

type winKernel struct {
	*winCapture
	headVA  uint64
	linksVA uint64
}

// A kernel image at fxKernelBase whose record names guid, its
// PsActiveProcessHead, and the System process alone on the list.
func newWinKernel(guid [16]byte) *winKernel {
	c := newWinCapture()
	k := &winKernel{winCapture: c, headVA: fxKernelBase + fxHeadRVA, linksVA: fxSystemVA + fxActiveLinks}
	copy(c.buf[c.mapPage(fxKernelBase):], peWithCodeView(`d:\build\ntkrnlmp.pdb`, guid, 1))
	c.mapPage(fxKernelBase + fxPage)
	head := c.mapPage(k.headVA)
	c.put64(head+fxFlink, k.linksVA)
	c.put64(head+fxBlink, k.linksVA)

	sys := c.mapPage(fxSystemVA)
	c.put64(sys+fxPcb+fxDirectoryTableBase, c.root)
	c.put64(sys+fxUniqueProcessID, 4)
	c.put64(sys+fxActiveLinks+fxFlink, k.headVA)
	c.put64(sys+fxActiveLinks+fxBlink, k.headVA)
	copy(c.buf[sys+fxImageFileName:], "System\x00")
	return k
}

// S32 4.7: a page below 1 MiB that starts E9 with a jump past 0xA8 inside
// the page, the long-mode target at 0x70 and CR3 at 0x90 + 0x10.
func (k *winKernel) addStartPage() {
	page := k.frame()
	copy(k.buf[page:], []byte{0xe9, 0x00, 0x01})
	k.put64(page+0x70, fxKernelBase+fxPage)
	k.put64(page+0xa0, k.root)
}

func (k *winKernel) addBuildNumber(value uint32) {
	k.put32(k.mapPage(fxKernelBase+fxBuildRVA), value)
}

func (k *winKernel) write(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "windows.raw")
	if err := os.WriteFile(path, k.buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func ptr(to string) symbols.TypeRef {
	return symbols.TypeRef{Name: to, IsPointer: true, Element: &symbols.TypeRef{Name: to}}
}

func bits(offset, length uint8) symbols.TypeRef {
	return symbols.TypeRef{Name: "unsigned long long", BitOffset: offset, BitLength: length}
}

type pteLayout int

const (
	noPTELayout pteLayout = iota
	pte14393
	pte19045
)

// _MMPTE_SOFTWARE as S53 W3 gives it for 14393 and for 19045.
func softwarePTE(l pteLayout) []symbols.Record {
	switch l {
	case pte14393:
		return []symbols.Record{{Name: "_MMPTE_SOFTWARE", Width: 8, Members: []symbols.Member{
			{Name: "PageFileLow", Type: bits(1, 4)}, {Name: "PageFileHigh", Type: bits(32, 32)}}}}
	case pte19045:
		return []symbols.Record{{Name: "_MMPTE_SOFTWARE", Width: 8, Members: []symbols.Member{
			{Name: "SwizzleBit", Type: bits(4, 1)}, {Name: "PageFileLow", Type: bits(12, 4)},
			{Name: "PageFileHigh", Type: bits(32, 32)}}}}
	}
	return nil
}

func winDeclaration(build *symbols.PDBBuild, pte pteLayout, withBuild bool) symbols.Declaration {
	u64 := symbols.TypeRef{Name: "unsigned long long"}
	u32 := symbols.TypeRef{Name: "unsigned long"}
	records := []symbols.Record{
		{Name: "_LIST_ENTRY", Width: 16, Members: []symbols.Member{
			{Name: "Flink", Offset: fxFlink, Type: ptr("_LIST_ENTRY")}, {Name: "Blink", Offset: fxBlink, Type: ptr("_LIST_ENTRY")}}},
		{Name: "_KPROCESS", Width: 0x30, Members: []symbols.Member{{Name: "DirectoryTableBase", Offset: fxDirectoryTableBase, Type: u64}}},
		{Name: "_EPROCESS", Width: fxEprocessSize, Members: []symbols.Member{
			{Name: "Pcb", Offset: fxPcb, Type: symbols.TypeRef{Name: "_KPROCESS"}},
			{Name: "UniqueProcessId", Offset: fxUniqueProcessID, Type: ptr("void")},
			{Name: "ActiveProcessLinks", Offset: fxActiveLinks, Type: symbols.TypeRef{Name: "_LIST_ENTRY"}},
			{Name: "ImageFileName", Offset: fxImageFileName, Type: symbols.TypeRef{Name: "unsigned char", IsArray: true,
				ArrayLength: 15, Element: &symbols.TypeRef{Name: "unsigned char"}}}}},
	}
	records = append(records, softwarePTE(pte)...)
	addresses := []symbols.Address{{Name: "PsActiveProcessHead", Address: fxHeadRVA}}
	if withBuild {
		records = append(records, symbols.Record{Name: "_KUSER_SHARED_DATA", Width: 0x274, Members: []symbols.Member{
			{Name: "NtBuildNumber", Offset: fxSharedBuild, Type: u32},
			{Name: "NtMajorVersion", Offset: fxSharedMajor, Type: u32},
			{Name: "NtMinorVersion", Offset: fxSharedMinor, Type: u32}}})
		addresses = append(addresses, symbols.Address{Name: "NtBuildNumber", Address: fxBuildRVA})
	}
	return symbols.Declaration{PointerWidth: 8, WindowsPDB: build, Records: records, Addresses: addresses}
}

func encodeTable(t *testing.T, d symbols.Declaration) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := symbols.Encode(&b, d); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func writeTable(t *testing.T, d symbols.Declaration) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kernel.vsym")
	if err := os.WriteFile(path, encodeTable(t, d), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func seedCache(t *testing.T, dir string, fp autoload.Fingerprint, d symbols.Declaration) {
	t.Helper()
	path, err := autoload.CachePath(dir, &fp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encodeTable(t, d), 0o600); err != nil {
		t.Fatal(err)
	}
}
