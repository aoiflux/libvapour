package ntfsrecord

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/aoiflux/libvapour/util"
)

const (
	signature       = "FILE"
	sequenceStride  = 512
	maxRecordSize   = 4096
	headerSize      = 0x2a
	endMarker       = 0xffffffff
	residentHeader  = 0x18
	nonresidentSize = 0x48

	codeStandardInformation = 0x10
	codeFileName            = 0x30
	codeData                = 0x80

	flagInUse            = 0x0001
	flagNameIndexPresent = 0x0002

	standardInformationSize = 0x30
	fileNameNameOffset      = 0x42
	fileNameFlagsKnown      = fileNameNTFS | fileNameDOS
	fileNameNTFS            = 0x01
	fileNameDOS             = 0x02
)

var (
	errSignature      = errors.New("ntfsrecord: signature is not FILE")
	errArray          = errors.New("ntfsrecord: update sequence array does not end before the last word of the first sector")
	errSize           = errors.New("ntfsrecord: update sequence array gives a record outside 1024 to 4096 bytes")
	errTruncated      = errors.New("ntfsrecord: record runs past readable memory")
	errFirstAttribute = errors.New("ntfsrecord: first attribute offset is not a quadword inside the record after the update sequence array")
	errAttributeSize  = errors.New("ntfsrecord: attribute record length is not a quadword multiple that fits its form and the record")
	errForm           = errors.New("ntfsrecord: attribute form code is neither resident nor nonresident")
	errAttributeName  = errors.New("ntfsrecord: attribute name runs past its attribute record")
	errValue          = errors.New("ntfsrecord: resident value does not lie between the attribute header and the attribute record end")
	errTypeOrder      = errors.New("ntfsrecord: attribute type codes decrease")
	errNoEnd          = errors.New("ntfsrecord: no end marker inside the record")
	errTorn           = errors.New("ntfsrecord: a stride inside the used bytes holds the update sequence number and another does not")

	errStandardForm  = errors.New("ntfsrecord: $STANDARD_INFORMATION is not resident")
	errStandardShort = errors.New("ntfsrecord: $STANDARD_INFORMATION value is shorter than 0x30 bytes")
	errNameForm      = errors.New("ntfsrecord: $FILE_NAME is not resident")
	errNameShort     = errors.New("ntfsrecord: $FILE_NAME value is shorter than 0x42 bytes")
	errNameLength    = errors.New("ntfsrecord: $FILE_NAME name runs past its value")
	errNameFlags     = errors.New("ntfsrecord: $FILE_NAME flags hold bits other than FILE_NAME_NTFS and FILE_NAME_DOS")
)

type FixupForm string

const (
	FixupProtected FixupForm = "protected"
	FixupRestored  FixupForm = "restored"
	FixupTorn      FixupForm = "torn"
)

type Namespace string

const (
	NamespaceNeither    Namespace = "neither"
	NamespaceNTFS       Namespace = "FILE_NAME_NTFS"
	NamespaceDOS        Namespace = "FILE_NAME_DOS"
	NamespaceNTFSAndDOS Namespace = "FILE_NAME_NTFS|FILE_NAME_DOS"
)

func namespaceOf(flags uint8) Namespace {
	switch flags & fileNameFlagsKnown {
	case fileNameNTFS:
		return NamespaceNTFS
	case fileNameDOS:
		return NamespaceDOS
	case fileNameNTFS | fileNameDOS:
		return NamespaceNTFSAndDOS
	}
	return NamespaceNeither
}

type fileReference struct {
	segment  uint64
	sequence uint16
}

func readReference(b []byte) fileReference {
	low := uint64(binary.LittleEndian.Uint32(b))
	high := uint64(binary.LittleEndian.Uint16(b[4:]))
	return fileReference{segment: high<<32 | low, sequence: binary.LittleEndian.Uint16(b[6:])}
}

type attribute struct {
	offset   int
	typeCode uint32
	resident bool
	name     string
	value    []byte
}

type record struct {
	physical     uint64
	fixup        FixupForm
	sequence     uint16
	linkCount    uint16
	flags        uint16
	bytesInUse   uint32
	allocated    uint32
	base         fileReference
	segment      uint32
	segmentKnown bool
	attributes   []attribute
}

type times struct {
	creation, lastWrite, change, lastAccess time.Time
}

type standardInformation struct {
	times
	fileAttributes uint32
}

type fileName struct {
	times
	parent    fileReference
	namespace Namespace
	name      string
}

func le16(b []byte, at int) uint16 { return binary.LittleEndian.Uint16(b[at:]) }
func le32(b []byte, at int) uint32 { return binary.LittleEndian.Uint32(b[at:]) }

// The size field counts words (the sequence number and one saved word per
// stride), not bytes as the structure page says: every measured record holds
// 3 and is 1024 bytes long (S42 M2).
func recordSize(b []byte) (int, int, error) {
	if len(b) < headerSize || string(b[:4]) != signature {
		return 0, 0, errSignature
	}
	offset, words := int(le16(b, 4)), int(le16(b, 6))
	if offset < headerSize || offset%2 != 0 || offset+2*words > sequenceStride-2 {
		return 0, 0, errArray
	}
	size := (words - 1) * sequenceStride
	if size < 2*sequenceStride || size > maxRecordSize {
		return 0, 0, errSize
	}
	return size, offset, nil
}

func parseRecord(physical uint64, b []byte) (record, error) {
	size, arrayOffset, err := recordSize(b)
	if err != nil {
		return record{}, err
	}
	if len(b) < size {
		return record{}, errTruncated
	}
	buf := make([]byte, size)
	copy(buf, b)
	tails := applyFixup(buf, arrayOffset)
	// Learn leaves 0x12 and 0x18 to 0x1F reserved; the link count and the
	// bytes in use and allocated are their measured meanings (S42 M2, M4,
	// M13), reported as read.
	r := record{
		physical:   physical,
		sequence:   le16(buf, 0x10),
		linkCount:  le16(buf, 0x12),
		flags:      le16(buf, 0x16),
		bytesInUse: le32(buf, 0x18),
		allocated:  le32(buf, 0x1c),
		base:       readReference(buf[0x20:]),
	}
	if arrayOffset >= 0x30 {
		r.segment, r.segmentKnown = le32(buf, 0x2c), true
	}
	arrayEnd := arrayOffset + 2*(size/sequenceStride+1)
	end, err := walkAttributes(buf, arrayEnd, &r)
	if err != nil {
		return record{}, err
	}
	r.fixup = fixupForm(tails, end)
	return r, nil
}

type strideTail struct {
	offset int
	held   bool
}

// Learn's restore step, applied to every stride whose tail still holds the
// sequence number. A tail equal to both the number and its saved word says
// nothing and is left out.
func applyFixup(buf []byte, arrayOffset int) []strideTail {
	usn := le16(buf, arrayOffset)
	var tails []strideTail
	for i := 1; i <= len(buf)/sequenceStride; i++ {
		tail := i*sequenceStride - 2
		saved := le16(buf, arrayOffset+2*i)
		v := le16(buf, tail)
		if v == usn && v == saved {
			continue
		}
		if v == usn {
			binary.LittleEndian.PutUint16(buf[tail:], saved)
		}
		tails = append(tails, strideTail{offset: tail, held: v == usn})
	}
	return tails
}

// The end marker fills the quadword it starts, as attribute records are
// quadword aligned, and the used bytes end there (S42 M4). A stride whose tail
// lies past them holds no attribute bytes, and in nearly every torn-looking
// record measured that is the stride that differs (S42 M3), so only strides
// inside the used bytes decide the form.
func fixupForm(tails []strideTail, used int) FixupForm {
	held, lost := false, false
	for _, t := range tails {
		if t.offset >= used {
			continue
		}
		if t.held {
			held = true
		} else {
			lost = true
		}
	}
	switch {
	case !held:
		return FixupRestored
	case lost:
		return FixupTorn
	}
	return FixupProtected
}

func walkAttributes(buf []byte, arrayEnd int, r *record) (int, error) {
	at := int(le16(buf, 0x14))
	if at%8 != 0 || at < arrayEnd || at >= len(buf) {
		return 0, errFirstAttribute
	}
	previous := uint32(0)
	for {
		if at+4 > len(buf) {
			return 0, errNoEnd
		}
		code := le32(buf, at)
		if code == endMarker {
			return min(at+8, len(buf)), nil
		}
		if at+residentHeader > len(buf) {
			return 0, errNoEnd
		}
		if code < previous {
			return 0, errTypeOrder
		}
		previous = code
		a, length, err := readAttribute(buf[at:], code)
		if err != nil {
			return 0, err
		}
		a.offset = at
		r.attributes = append(r.attributes, a)
		at += length
	}
}

func readAttribute(b []byte, code uint32) (attribute, int, error) {
	length := int(le32(b, 4))
	form := b[8]
	if form > 1 {
		return attribute{}, 0, errForm
	}
	least := residentHeader
	if form == 1 {
		least = nonresidentSize
	}
	if length%8 != 0 || length < least || length > len(b) {
		return attribute{}, 0, errAttributeSize
	}
	a := attribute{typeCode: code, resident: form == 0}
	if n := int(b[9]); n > 0 {
		offset := int(le16(b, 10))
		if offset+2*n > length {
			return attribute{}, 0, errAttributeName
		}
		a.name = util.DecodeCountedUTF16LE(b[offset : offset+2*n])
	}
	if a.resident {
		valueLength, valueOffset := int(le32(b, 0x10)), int(le16(b, 0x14))
		if valueOffset < residentHeader || valueOffset+valueLength > length {
			return attribute{}, 0, errValue
		}
		a.value = b[valueOffset : valueOffset+valueLength]
	}
	return a, length, nil
}

const filetimeUnixGap = 11644473600

func filetime(b []byte) time.Time {
	v := binary.LittleEndian.Uint64(b)
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(int64(v/10_000_000)-filetimeUnixGap, int64(v%10_000_000)*100).UTC()
}

// The structure pages leave these bytes reserved; the four FILETIME slots and
// their order are measured (S42 M8, M9).
func readTimes(b []byte) times {
	return times{creation: filetime(b), lastWrite: filetime(b[8:]), change: filetime(b[16:]), lastAccess: filetime(b[24:])}
}

func (a attribute) standardInformation() (standardInformation, error) {
	if !a.resident {
		return standardInformation{}, errStandardForm
	}
	if len(a.value) < standardInformationSize {
		return standardInformation{}, errStandardShort
	}
	return standardInformation{times: readTimes(a.value), fileAttributes: le32(a.value, 0x20)}, nil
}

func (a attribute) fileName() (fileName, error) {
	if !a.resident {
		return fileName{}, errNameForm
	}
	v := a.value
	if len(v) < fileNameNameOffset {
		return fileName{}, errNameShort
	}
	n, flags := int(v[0x40]), v[0x41]
	if fileNameNameOffset+2*n > len(v) {
		return fileName{}, errNameLength
	}
	if flags&^fileNameFlagsKnown != 0 {
		return fileName{}, errNameFlags
	}
	return fileName{
		times:     readTimes(v[8:]),
		parent:    readReference(v),
		namespace: namespaceOf(flags),
		name:      util.DecodeCountedUTF16LE(v[fileNameNameOffset : fileNameNameOffset+2*n]),
	}, nil
}

// A long name (FILE_NAME_NTFS) is preferred, then a name in neither
// namespace, then a short name; the first of a kind in record order wins.
func preferredName(names []fileName) (string, bool) {
	rank := func(ns Namespace) int {
		switch ns {
		case NamespaceNTFS, NamespaceNTFSAndDOS:
			return 0
		case NamespaceNeither:
			return 1
		}
		return 2
	}
	best := -1
	for i, n := range names {
		if best < 0 || rank(n.namespace) < rank(names[best].namespace) {
			best = i
		}
	}
	if best < 0 {
		return "", false
	}
	return names[best].name, true
}
