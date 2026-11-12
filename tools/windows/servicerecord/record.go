package servicerecord

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
)

type addressRange struct{ start, end uint64 }

func (r addressRange) holds(v uint64) bool { return v >= r.start && v < r.end }

type serviceStatus struct {
	serviceType, currentState, controlsAccepted uint32
	win32ExitCode, serviceSpecificExitCode      uint32
}

type record struct {
	address           uint64
	previous, next    uint64
	sequence          uint32
	name, display     string
	displayUnreadable bool
	status            serviceStatus
	startType         uint32
	errorControl      uint32
	processOrDriver   uint64
}

type rejection string

const (
	rejectUnread       rejection = "unread"
	rejectTag          rejection = "tag"
	rejectImagePointer rejection = "image pointer"
	rejectName         rejection = "name"
	rejectState        rejection = "state"
	rejectType         rejection = "type"
	rejectStartType    rejection = "start type"
	rejectErrorControl rejection = "error control"
	rejectSequence     rejection = "sequence"
)

// S34 D3.
const maxNameUnits = 256

const statusSize = 7 * 4

func (l layout) span() uint64 {
	end := uint64(0)
	for _, o := range []uint64{l.tagAt + 4, l.previous + pointerSize, l.next + pointerSize, l.serviceName + pointerSize,
		l.displayName + pointerSize, l.sequence + 4, l.status + statusSize, l.startType + 4, l.errorControl + 4,
		l.processOrDriver + pointerSize} {
		end = max(end, o)
	}
	return end
}

// The rules are S34 5.1, checked in its order so that a rejection names the
// first rule that failed.
func decode(r memory.MemoryReader, l layout, at uint64, image addressRange) (record, rejection) {
	b, err := r.ReadAt(at, l.span())
	if err != nil || uint64(len(b)) < l.span() {
		return record{}, rejectUnread
	}
	d := func(o uint64) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
	q := func(o uint64) uint64 { return binary.LittleEndian.Uint64(b[o:]) }
	if at%recordAlignment != 0 || d(l.tagAt) != l.tag {
		return record{}, rejectTag
	}
	if l.imagePointer && !image.holds(q(0)) {
		return record{}, rejectImagePointer
	}
	rec := record{
		address: at, previous: q(l.previous), next: q(l.next), sequence: d(l.sequence),
		status: serviceStatus{
			serviceType: d(l.status), currentState: d(l.status + 4), controlsAccepted: d(l.status + 8),
			win32ExitCode: d(l.status + 12), serviceSpecificExitCode: d(l.status + 16),
		},
		startType: d(l.startType), errorControl: d(l.errorControl), processOrDriver: q(l.processOrDriver),
	}
	name, ok := readUTF16(r, q(l.serviceName), maxNameUnits)
	if !ok || name == "" || strings.ContainsAny(name, `/\`) {
		return record{}, rejectName
	}
	rec.name = name
	switch s := rec.status; {
	case s.currentState < stateStopped || s.currentState > stateLast:
		return record{}, rejectState
	case s.serviceType&typeKind == 0 || s.serviceType&^typeKnownBits != 0:
		return record{}, rejectType
	case rec.startType >= uint32(len(startNames)):
		return record{}, rejectStartType
	case rec.errorControl >= uint32(len(errorControlNames)):
		return record{}, rejectErrorControl
	case rec.sequence == 0:
		return record{}, rejectSequence
	}
	if p := q(l.displayName); p != 0 {
		rec.display, ok = readUTF16(r, p, maxNameUnits)
		rec.displayUnreadable = !ok
	}
	return rec, ""
}

// Reads a page at a time so that a string ending before an unreadable page
// still reads.
func readUTF16(r memory.MemoryReader, at uint64, maxUnits int) (string, bool) {
	if at == 0 || at%2 != 0 {
		return "", false
	}
	units := make([]uint16, 0, 32)
	for len(units) <= maxUnits {
		n := pageSize - at%pageSize
		if left := uint64(maxUnits+1-len(units)) * 2; n > left {
			n = left
		}
		b, err := r.ReadAt(at, n)
		if err != nil || uint64(len(b)) < n {
			return "", false
		}
		for i := 0; i+1 < len(b); i += 2 {
			u := binary.LittleEndian.Uint16(b[i:])
			if u == 0 {
				return string(utf16.Decode(units)), true
			}
			units = append(units, u)
		}
		if at+n < at {
			return "", false
		}
		at += n
	}
	return "", false
}

func readUint32(r memory.MemoryReader, at uint64) (uint32, bool) {
	b, err := r.ReadAt(at, 4)
	if err != nil || len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

func readPointer(r memory.MemoryReader, at uint64) (uint64, bool) {
	b, err := r.ReadAt(at, pointerSize)
	if err != nil || len(b) < pointerSize {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

const pageSize = 0x1000
