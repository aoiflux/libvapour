package diskbootrecords

import (
	"encoding/binary"
	"fmt"
)

const (
	recordSize      = 512
	bootCodeSize    = 0x1B8
	signatureOffset = 0x1B8
	tableOffset     = 0x1BE
	entrySize       = 16
	entryCount      = 4
	markerOffset    = 0x1FE

	indicatorInactive = 0x00
	indicatorActive   = 0x80

	typeUnused = 0x00

	chsSectorBits = 0x3F
	lbaRange      = uint64(1) << 32
)

var marker = [2]byte{0x55, 0xAA}

type entry struct {
	indicator     uint8
	startHead     uint8
	startSector   uint8
	startCylinder uint16
	systemID      uint8
	endHead       uint8
	endSector     uint8
	endCylinder   uint16
	relative      uint32
	total         uint32
	raw           [entrySize]byte
	index         int
}

// The cylinder's top two bits sit in bits 6-7 of the sector byte.
func cylinderSector(sectorByte, cylinderByte uint8) (uint8, uint16) {
	return sectorByte & chsSectorBits, uint16(sectorByte&^chsSectorBits)<<2 | uint16(cylinderByte)
}

func parseEntry(b []byte, index int) entry {
	e := entry{indicator: b[0], startHead: b[1], systemID: b[4], endHead: b[5], index: index,
		relative: binary.LittleEndian.Uint32(b[8:]), total: binary.LittleEndian.Uint32(b[12:])}
	e.startSector, e.startCylinder = cylinderSector(b[2], b[3])
	e.endSector, e.endCylinder = cylinderSector(b[6], b[7])
	copy(e.raw[:], b)
	return e
}

func (e entry) inUse() bool { return e.systemID != typeUnused }

func (e entry) start() uint64 { return uint64(e.relative) }

func (e entry) end() uint64 { return uint64(e.relative) + uint64(e.total) }

type record struct {
	bytes   [recordSize]byte
	entries [entryCount]entry
}

func parseRecord(b []byte) (record, bool) {
	var r record
	if len(b) < recordSize || b[markerOffset] != marker[0] || b[markerOffset+1] != marker[1] {
		return r, false
	}
	copy(r.bytes[:], b)
	for i := range entryCount {
		at := tableOffset + i*entrySize
		r.entries[i] = parseEntry(b[at:at+entrySize], i+1)
	}
	return r, true
}

func (r record) diskSignature() uint32 { return binary.LittleEndian.Uint32(r.bytes[signatureOffset:]) }

func (r record) bootCode() []byte { return r.bytes[:bootCodeSize] }

// tableProblem returns "" for a partition table every rule of S66 B4 accepts,
// otherwise the first rule it breaks.
func (r record) tableProblem() string {
	active, used := 0, 0
	for i, e := range r.entries {
		if e.indicator != indicatorInactive && e.indicator != indicatorActive {
			return fmt.Sprintf("entry %d: boot indicator %#x", i+1, e.indicator)
		}
		if !e.inUse() {
			if e.raw != ([entrySize]byte{}) {
				return fmt.Sprintf("entry %d: unused but not zero", i+1)
			}
			continue
		}
		used++
		if e.indicator == indicatorActive {
			active++
		}
		switch {
		case e.total == 0:
			return fmt.Sprintf("entry %d: no sectors", i+1)
		case e.relative == 0:
			return fmt.Sprintf("entry %d: starts at the boot record", i+1)
		case e.end() > lbaRange:
			return fmt.Sprintf("entry %d: runs past 2^32 sectors", i+1)
		case e.startSector == 0 || e.endSector == 0:
			return fmt.Sprintf("entry %d: CHS sector 0", i+1)
		}
		for _, o := range r.entries[:i] {
			if o.inUse() && e.start() < o.end() && o.start() < e.end() {
				return fmt.Sprintf("entries %d and %d overlap", o.index, i+1)
			}
		}
	}
	switch {
	case used == 0:
		return "no entry in use"
	case active > 1:
		return fmt.Sprintf("%d active entries", active)
	}
	return ""
}
