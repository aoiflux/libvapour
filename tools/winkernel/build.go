package winkernel

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

var ErrBuildUnread = errors.New("winkernel: windows build not readable")

const (
	// KI_USER_SHARED_DATA in WDK wdm.h: the AMD64 and ARM64 value, and the x86 kernel-mode value.
	sharedData64 = uint64(0xFFFFF78000000000)
	sharedData32 = uint64(0xFFDF0000)

	sharedDataType = "_KUSER_SHARED_DATA"
	buildSymbol    = "NtBuildNumber"
	ulongBytes     = 4

	// Learn calls the KUSER_SHARED_DATA copy "undecorated with C or F", so
	// the kernel's own variable carries that letter; S03 open point O1.
	decorationShift = 28
	buildMask       = 1<<decorationShift - 1
)

// Learn's release table gives 2004 to 22H2 the builds 19041 to 19045, and
// KB5015684 says those versions share an identical set of system files, so
// one measured layout serves the whole range (S03 4.9).
const (
	fileSetFirst = 19041
	fileSetLast  = 19045
)

func FileSetBuild(kernel uint32) uint32 {
	if kernel >= fileSetFirst && kernel <= fileSetLast {
		return fileSetFirst
	}
	return kernel
}

type Build struct {
	Major, Minor uint32
	VersionErr   error

	Kernel     uint32
	Decoration uint32
	KernelErr  error

	Shared    uint32
	SharedErr error
}

func (b Build) Missing() error {
	if b.VersionErr != nil {
		return b.VersionErr
	}
	return b.KernelErr
}

func SharedDataAddress(table symbols.SymbolTable) uint64 {
	if table.PointerSize() == 4 {
		return sharedData32
	}
	return sharedData64
}

func ReadBuild(tool string, mem memory.MemoryReader, table symbols.SymbolTable) Build {
	var b Build
	if mem == nil || table == nil {
		err := fmt.Errorf("%s: %w: no memory reader or symbol table", tool, ErrBuildUnread)
		return Build{VersionErr: err, KernelErr: err, SharedErr: err}
	}
	base := SharedDataAddress(table)
	var majorErr, minorErr error
	b.Major, majorErr = readShared(tool, mem, table, base, "NtMajorVersion")
	b.Minor, minorErr = readShared(tool, mem, table, base, "NtMinorVersion")
	if b.VersionErr = majorErr; b.VersionErr == nil {
		b.VersionErr = minorErr
	}
	if b.VersionErr != nil {
		b.Major, b.Minor = 0, 0
	}
	b.Shared, b.SharedErr = readShared(tool, mem, table, base, buildSymbol)

	raw, err := readKernelBuild(tool, mem, table)
	if err != nil {
		b.KernelErr = err
		return b
	}
	b.Kernel, b.Decoration = raw&buildMask, raw>>decorationShift
	return b
}

func readShared(tool string, mem memory.MemoryReader, table symbols.SymbolTable, base uint64, member string) (uint32, error) {
	f, err := table.Field(sharedDataType, member)
	if err != nil {
		return 0, fmt.Errorf("%s: %s.%s: %w: %w", tool, sharedDataType, member, ErrBuildUnread, err)
	}
	v, err := readULong(mem, base+f.Offset)
	if err != nil {
		return 0, fmt.Errorf("%s: %s.%s at 0x%x: %w: %w", tool, sharedDataType, member, base+f.Offset, ErrBuildUnread, err)
	}
	return v, nil
}

func readKernelBuild(tool string, mem memory.MemoryReader, table symbols.SymbolTable) (uint32, error) {
	sym, err := table.LookupSymbol(buildSymbol)
	if err != nil {
		return 0, fmt.Errorf("%s: %s: %w: %w", tool, buildSymbol, ErrBuildUnread, err)
	}
	v, err := readULong(mem, sym.Address)
	if err != nil {
		return 0, fmt.Errorf("%s: %s at 0x%x: %w: %w", tool, buildSymbol, sym.Address, ErrBuildUnread, err)
	}
	return v, nil
}

func readULong(mem memory.MemoryReader, at uint64) (uint32, error) {
	raw, err := mem.ReadAt(at, ulongBytes)
	if err != nil {
		return 0, err
	}
	if len(raw) < ulongBytes {
		return 0, fmt.Errorf("read %d bytes, got %d", ulongBytes, len(raw))
	}
	return binary.LittleEndian.Uint32(raw), nil
}
