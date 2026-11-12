package testsupport

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

// _KUSER_SHARED_DATA and _DBGKD_GET_VERSION64 members (S79 T10) and the
// kernel's own view of the shared page (M2).
const (
	KUserSharedData      = uint64(0xFFFFF78000000000)
	NtBuildNumberOffset  = 0x260
	NtMajorVersionOffset = 0x26c
	NtMinorVersionOffset = 0x270
	KdMinorVersionOffset = 0x02
	// Every capture's NtBuildNumber carries 0xF in its top four bits (M3).
	FreeBuildDecoration = uint32(0xF) << 28

	NtBuildNumberGlobal = uint64(0xFFFFF80000004000)
	// Clear of the process fixture's MmProtectToValue page.
	KdVersionBlock = uint64(0xFFFFF80000005000)

	versionBlockSize  = 0x28
	buildNumberSize   = 4
	sharedDataMapSize = pageSize
)

type versionRegion struct {
	base uint64
	data []byte
}

// WithWindowsVersion puts one build in all three places a tool may read it
// from, so whichever it reads, it sees the same kernel. On 19045 the version
// block carries the base build instead (M4); tests do not need that split.
func WithWindowsVersion(table symbols.SymbolTable, mem memory.MemoryReader, major, minor uint32,
	build uint16) (symbols.SymbolTable, memory.MemoryReader) {
	le := binary.LittleEndian
	shared := make([]byte, sharedDataMapSize)
	le.PutUint32(shared[NtBuildNumberOffset:], uint32(build))
	le.PutUint32(shared[NtMajorVersionOffset:], major)
	le.PutUint32(shared[NtMinorVersionOffset:], minor)
	global := make([]byte, buildNumberSize)
	le.PutUint32(global, FreeBuildDecoration|uint32(build))
	block := make([]byte, versionBlockSize)
	le.PutUint16(block[KdMinorVersionOffset:], build)
	regions := []versionRegion{{KUserSharedData, shared}, {NtBuildNumberGlobal, global}, {KdVersionBlock, block}}
	return versionSymbols{table}, versionReader{MemoryReader: mem, regions: regions}
}

type versionSymbols struct{ symbols.SymbolTable }

var versionMembers = map[[2]string]uint64{
	{"_KUSER_SHARED_DATA", "NtBuildNumber"}:  NtBuildNumberOffset,
	{"_KUSER_SHARED_DATA", "NtMajorVersion"}: NtMajorVersionOffset,
	{"_KUSER_SHARED_DATA", "NtMinorVersion"}: NtMinorVersionOffset,
	{"_DBGKD_GET_VERSION64", "MinorVersion"}: KdMinorVersionOffset,
}

var versionGlobals = map[string]uint64{"NtBuildNumber": NtBuildNumberGlobal, "KdVersionBlock": KdVersionBlock}

func (t versionSymbols) Field(typeName, fieldName string) (symbols.Field, error) {
	if at, ok := versionMembers[[2]string{typeName, fieldName}]; ok {
		return symbols.Field{Name: fieldName, Offset: at}, nil
	}
	return t.SymbolTable.Field(typeName, fieldName)
}

func (t versionSymbols) LookupSymbol(name string) (symbols.Symbol, error) {
	if at, ok := versionGlobals[name]; ok {
		return symbols.Symbol{Name: name, Address: at}, nil
	}
	return t.SymbolTable.LookupSymbol(name)
}

type versionReader struct {
	memory.MemoryReader
	regions []versionRegion
}

func (m versionReader) ReadAt(offset, size uint64) ([]byte, error) {
	for _, r := range m.regions {
		if offset >= r.base && size <= uint64(len(r.data)) && offset-r.base <= uint64(len(r.data))-size {
			at := offset - r.base
			return append([]byte(nil), r.data[at:at+size]...), nil
		}
	}
	return m.MemoryReader.ReadAt(offset, size)
}
