package autoload

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	pdbInfoStream  = 1
	pdbTypeStream  = 2
	pdbDebugStream = 3

	infoHeaderSize = 28
	infoGUIDAt     = 12

	debugHeaderSize      = 64
	debugAgeAt           = 8
	debugSymbolRecordsAt = 20
	debugSubstreamsAt    = 24
	debugOptionalSizeAt  = 48
	debugECSizeAt        = 52
	debugMachineAt       = 58

	moduleEntryFixed   = 64
	moduleSymStreamAt  = 34
	moduleSymBytesAt   = 36
	sectionHeaderBytes = 40
	sectionVAAt        = 12

	slotOMAPFromSource    = 4
	slotSectionHeaders    = 5
	slotOriginalSections  = 10
	noStreamIndex         = 0xffff
	machineI386           = 0x014c
	machineAMD64          = 0x8664
	machineARM64          = 0xaa64
	debugVersionSignature = 0xffffffff
)

func pdbGUID(info []byte) (string, error) {
	if len(info) < infoHeaderSize {
		return "", fmt.Errorf("autoload: pdb information stream is %d bytes, shorter than its %d-byte header", len(info), infoHeaderSize)
	}
	return formatGUID(info[infoGUIDAt : infoGUIDAt+16]), nil
}

func machinePointer(machine uint16) (arch string, pointerSize int, ok bool) {
	switch machine {
	case machineI386:
		return "x86", 4, true
	case machineAMD64:
		return "x64", 8, true
	case machineARM64:
		return "arm64", 8, true
	}
	return "", 0, false
}

type pdbModule struct {
	symbolStream uint16
	symbolBytes  uint32
}

type omapEntry struct{ from, to uint32 }

type debugInfo struct {
	symbolRecords uint16
	modules       []pdbModule
	sections      []uint32
	omap          []omapEntry
}

// The header names seven substream sizes; the substreams follow it in the
// order module info, section contributions, section map, file info, type
// server map, EC, optional debug header, and must lie within the stream.
func readDebugInfo(c *msfContainer, s []byte) (debugInfo, error) {
	if len(s) < debugHeaderSize {
		return debugInfo{}, fmt.Errorf("autoload: pdb debug information stream is %d bytes, shorter than its %d-byte header", len(s), debugHeaderSize)
	}
	if binary.LittleEndian.Uint32(s) != debugVersionSignature {
		return debugInfo{}, fmt.Errorf("autoload: pdb debug information header signature is %#x, not -1", binary.LittleEndian.Uint32(s))
	}
	var sizes [7]uint64
	for i := range 5 {
		sizes[i] = uint64(int64(int32(binary.LittleEndian.Uint32(s[debugSubstreamsAt+4*i:]))))
	}
	sizes[5] = uint64(int64(int32(binary.LittleEndian.Uint32(s[debugECSizeAt:]))))
	sizes[6] = uint64(int64(int32(binary.LittleEndian.Uint32(s[debugOptionalSizeAt:]))))
	var starts [7]uint64
	end := uint64(debugHeaderSize)
	for i, n := range sizes {
		if n > uint64(len(s)) || end+n > uint64(len(s)) {
			return debugInfo{}, fmt.Errorf("autoload: pdb debug information substream %d of %d bytes runs past the stream's %d bytes", i, int64(n), len(s))
		}
		starts[i] = end
		end += n
	}
	info := debugInfo{
		symbolRecords: binary.LittleEndian.Uint16(s[debugSymbolRecordsAt:]),
		modules:       readModules(s[starts[0] : starts[0]+sizes[0]]),
	}
	optional := s[starts[6] : starts[6]+sizes[6]]
	slot := func(i int) uint16 {
		if (i+1)*2 > len(optional) {
			return noStreamIndex
		}
		return binary.LittleEndian.Uint16(optional[i*2:])
	}
	headers := slot(slotSectionHeaders)
	if original, omap := slot(slotOriginalSections), slot(slotOMAPFromSource); original != noStreamIndex && omap != noStreamIndex {
		headers = original
		info.omap = readOMAP(c.stream(int(omap)))
	}
	if headers != noStreamIndex {
		info.sections = sectionAddresses(c.stream(int(headers)))
	}
	return info, nil
}

func readModules(sub []byte) []pdbModule {
	var out []pdbModule
	for at := 0; at+moduleEntryFixed <= len(sub); {
		names := sub[at+moduleEntryFixed:]
		module := bytes.IndexByte(names, 0)
		if module < 0 {
			break
		}
		object := bytes.IndexByte(names[module+1:], 0)
		if object < 0 {
			break
		}
		out = append(out, pdbModule{
			symbolStream: binary.LittleEndian.Uint16(sub[at+moduleSymStreamAt:]),
			symbolBytes:  binary.LittleEndian.Uint32(sub[at+moduleSymBytesAt:]),
		})
		at = (at + moduleEntryFixed + module + 1 + object + 1 + 3) &^ 3
	}
	return out
}

func sectionAddresses(headers []byte) []uint32 {
	out := make([]uint32, 0, len(headers)/sectionHeaderBytes)
	for at := 0; at+sectionHeaderBytes <= len(headers); at += sectionHeaderBytes {
		out = append(out, binary.LittleEndian.Uint32(headers[at+sectionVAAt:]))
	}
	return out
}

func readOMAP(s []byte) []omapEntry {
	out := make([]omapEntry, 0, len(s)/8)
	for at := 0; at+8 <= len(s); at += 8 {
		out = append(out, omapEntry{binary.LittleEndian.Uint32(s[at:]), binary.LittleEndian.Uint32(s[at+4:])})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].from < out[j].from })
	return out
}

// The entry with the largest source address not above rva maps it. An entry
// mapped to zero marks code the rewrite removed, and nothing before the first
// entry has a place in the final image.
func (d debugInfo) finalAddress(rva uint32) (uint32, bool) {
	if d.omap == nil {
		return rva, true
	}
	i := sort.Search(len(d.omap), func(i int) bool { return d.omap[i].from > rva }) - 1
	if i < 0 || d.omap[i].to == 0 {
		return 0, false
	}
	return d.omap[i].to + (rva - d.omap[i].from), true
}

func (d debugInfo) address(segment uint16, offset uint32) (uint64, bool) {
	if segment == 0 || int(segment) > len(d.sections) {
		return 0, false
	}
	rva := uint64(d.sections[segment-1]) + uint64(offset)
	if rva > 0xffffffff {
		return 0, false
	}
	final, ok := d.finalAddress(uint32(rva))
	return uint64(final), ok
}
