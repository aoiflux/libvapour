package ntfsrecord

import (
	"encoding/binary"
	"errors"
	"time"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// Layouts as Microsoft Learn's NTFS structure pages give them, with the
// update sequence array at 0x30 and the first attribute at 0x38 as every
// measured record has them (S42 D1-D6, M2, M4).
const (
	fixtureArray = 0x30
	fixtureFirst = 0x38
	fixtureUSN   = 0x0007
)

type fixtureAttr struct {
	code     uint32
	name     string
	value    []byte
	resident bool
	length   int
}

type fixtureRecord struct {
	sequence uint16
	links    uint16
	flags    uint16
	base     uint64
	segment  uint32
	attrs    []fixtureAttr
	size     int
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func pad8(n int) int { return (n + 7) &^ 7 }

func ticksOf(t time.Time) uint64 {
	return uint64(t.Unix()+filetimeUnixGap)*10_000_000 + uint64(t.Nanosecond()/100)
}

func timeBlock(ts [4]time.Time) []byte {
	b := make([]byte, 32)
	for i, t := range ts {
		if !t.IsZero() {
			binary.LittleEndian.PutUint64(b[8*i:], ticksOf(t))
		}
	}
	return b
}

func standardValue(ts [4]time.Time, attrs uint32, length int) []byte {
	v := make([]byte, length)
	copy(v, timeBlock(ts))
	if length >= 0x24 {
		binary.LittleEndian.PutUint32(v[0x20:], attrs)
	}
	return v
}

func nameValue(parent uint64, parentSeq uint16, ts [4]time.Time, flags uint8, name string) []byte {
	n := utf16le(name)
	v := make([]byte, fileNameNameOffset+len(n))
	binary.LittleEndian.PutUint64(v, parent|uint64(parentSeq)<<48)
	copy(v[8:], timeBlock(ts))
	v[0x40] = byte(len(n) / 2)
	v[0x41] = flags
	copy(v[fileNameNameOffset:], n)
	return v
}

func resident(code uint32, name string, value []byte) fixtureAttr {
	return fixtureAttr{code: code, name: name, value: value, resident: true}
}

func (a fixtureAttr) bytes() []byte {
	name := utf16le(a.name)
	if !a.resident {
		n := a.length
		if n == 0 {
			n = pad8(nonresidentSize + len(name) + 8)
		}
		b := make([]byte, max(n, nonresidentSize+len(name)))
		binary.LittleEndian.PutUint32(b, a.code)
		binary.LittleEndian.PutUint32(b[4:], uint32(n))
		b[8] = 1
		b[9] = byte(len(name) / 2)
		binary.LittleEndian.PutUint16(b[10:], nonresidentSize)
		copy(b[nonresidentSize:], name)
		return b[:n]
	}
	valueOffset := pad8(residentHeader + len(name))
	n := pad8(valueOffset + len(a.value))
	if a.length != 0 {
		n = a.length
	}
	b := make([]byte, max(n, valueOffset+len(a.value)))
	binary.LittleEndian.PutUint32(b, a.code)
	binary.LittleEndian.PutUint32(b[4:], uint32(n))
	b[9] = byte(len(name) / 2)
	binary.LittleEndian.PutUint16(b[10:], residentHeader)
	binary.LittleEndian.PutUint32(b[0x10:], uint32(len(a.value)))
	binary.LittleEndian.PutUint16(b[0x14:], uint16(valueOffset))
	copy(b[residentHeader:], name)
	copy(b[valueOffset:], a.value)
	return b[:n]
}

// restored builds the record as it sits in the cache after a read: every
// stride tail holds its own data and the array holds the words a protecting
// write would save.
func (f fixtureRecord) restored() []byte {
	size := f.size
	if size == 0 {
		size = 1024
	}
	b := make([]byte, size)
	copy(b, signature)
	words := size/sequenceStride + 1
	binary.LittleEndian.PutUint16(b[4:], fixtureArray)
	binary.LittleEndian.PutUint16(b[6:], uint16(words))
	binary.LittleEndian.PutUint16(b[0x10:], f.sequence)
	binary.LittleEndian.PutUint16(b[0x12:], f.links)
	binary.LittleEndian.PutUint16(b[0x14:], fixtureFirst)
	binary.LittleEndian.PutUint16(b[0x16:], f.flags)
	binary.LittleEndian.PutUint32(b[0x1c:], uint32(size))
	binary.LittleEndian.PutUint64(b[0x20:], f.base)
	binary.LittleEndian.PutUint32(b[0x2c:], f.segment)
	at := fixtureFirst
	for _, a := range f.attrs {
		at += copy(b[at:], a.bytes())
	}
	binary.LittleEndian.PutUint32(b[at:], endMarker)
	binary.LittleEndian.PutUint32(b[0x18:], uint32(at+8))
	binary.LittleEndian.PutUint16(b[fixtureArray:], fixtureUSN)
	for i := 1; i < words; i++ {
		copy(b[fixtureArray+2*i:], b[i*sequenceStride-2:i*sequenceStride])
	}
	return b
}

// protected builds the record as a write leaves it on disk: each stride tail
// holds the update sequence number.
func (f fixtureRecord) protected() []byte {
	b := f.restored()
	for i := 1; i <= len(b)/sequenceStride; i++ {
		binary.LittleEndian.PutUint16(b[i*sequenceStride-2:], fixtureUSN)
	}
	return b
}

var (
	fixtureT1 = time.Date(2026, 10, 29, 19, 9, 32, 400840400, time.UTC)
	fixtureT2 = time.Date(2025, 3, 1, 8, 0, 0, 0, time.UTC)
	fixtureT3 = time.Date(2026, 10, 30, 1, 2, 3, 100, time.UTC)
	fixtureT4 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
)

func sampleRecord() fixtureRecord {
	si := [4]time.Time{fixtureT1, fixtureT2, fixtureT3, fixtureT4}
	fn := [4]time.Time{fixtureT1, fixtureT1, fixtureT1, fixtureT1}
	return fixtureRecord{
		sequence: 3,
		links:    1,
		flags:    flagInUse,
		segment:  116130,
		attrs: []fixtureAttr{
			resident(codeStandardInformation, "", standardValue(si, 0x20, 0x48)),
			resident(codeFileName, "", nameValue(0x1234, 5, fn, fileNameDOS, "MEM7_S~1.MEM")),
			resident(codeFileName, "", nameValue(0x1234, 5, fn, fileNameNTFS, "mem7_server2025.mem")),
			resident(codeData, "", []byte("resident body")),
			resident(codeData, "Zone.Identifier", []byte("[ZoneTransfer]\r\nZoneId=3\r\n")),
			{code: codeData, name: "big", resident: false},
		},
	}
}

type flat []byte

func (f flat) ReadAt(off, n uint64) ([]byte, error) {
	if off > uint64(len(f)) || n > uint64(len(f))-off {
		return nil, memory.ErrOutOfBounds
	}
	return f[off : off+n], nil
}

func (f flat) Size() uint64 { return uint64(len(f)) }

var errHole = errors.New("fixture: hole")

type holed struct {
	flat
	from, to uint64
}

func (h holed) ReadAt(off, n uint64) ([]byte, error) {
	if off < h.to && off+n > h.from {
		return nil, errHole
	}
	return h.flat.ReadAt(off, n)
}

func fixtureContext(phys memory.MemoryReader, diags *[]string) tools.Context {
	options := map[string]any{"diagnostics": diags}
	if phys != nil {
		options[tools.OptionPhysicalMemory] = phys
	}
	return tools.Context{
		Memory:  flat(make([]byte, 16)),
		Symbols: symbols.NewTable("nt", 8),
		Profile: profiles.WindowsX64Profile{},
		Options: options,
	}
}
