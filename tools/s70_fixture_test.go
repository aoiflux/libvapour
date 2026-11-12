package tools

import (
	"encoding/binary"
	"errors"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
)

var errUnmapped = errors.New("unmapped")

// Pages keyed by their base; any read outside them fails.
type pages map[uint64][]byte

func (m pages) ReadAt(at, size uint64) ([]byte, error) {
	page, ok := m[at&^(PageSize-1)]
	off := at & (PageSize - 1)
	if !ok || off+size > uint64(len(page)) {
		return nil, errUnmapped
	}
	return append([]byte(nil), page[off:off+size]...), nil
}

func (m pages) Size() uint64 { return 0 }

const (
	sharedDataBase = uint64(0xFFFFF78000000000)
	buildGlobal    = uint64(0xFFFFF80000200010)
)

// A kernel whose shared data page and NtBuildNumber hold the given values;
// a zero version or build leaves that value out of the image.
type kernel struct {
	major, minor uint32
	build        uint32
	zeroShared   bool
	poolHeader   bool
	bodies       []string
}

func (k kernel) open() (*symbols.Table, pages) {
	table := symbols.NewTable("nt", 8)
	table.AddStruct(symbols.StructType{Name: "_KUSER_SHARED_DATA", Size: 0x720, Fields: []symbols.Field{
		{Name: "NtBuildNumber", Offset: 0x260}, {Name: "NtMajorVersion", Offset: 0x26c}, {Name: "NtMinorVersion", Offset: 0x270},
	}})
	table.AddSymbol(symbols.Symbol{Name: "NtBuildNumber", Address: buildGlobal})
	if k.poolHeader {
		table.AddStruct(symbols.StructType{Name: "_POOL_HEADER", Size: 0x10, Fields: []symbols.Field{
			{Name: "PoolType", Offset: 2}, {Name: "BlockSize", Offset: 2}, {Name: "PoolTag", Offset: 4},
		}})
	}
	for _, body := range k.bodies {
		table.AddStruct(symbols.StructType{Name: body, Size: 0x100})
	}
	mem := pages{}
	if k.major != 0 || k.zeroShared {
		page := make([]byte, PageSize)
		binary.LittleEndian.PutUint32(page[0x26c:], k.major)
		binary.LittleEndian.PutUint32(page[0x270:], k.minor)
		mem[sharedDataBase] = page
	}
	if k.build != 0 {
		page := make([]byte, PageSize)
		binary.LittleEndian.PutUint32(page[buildGlobal&(PageSize-1):], 0xF0000000|k.build)
		mem[buildGlobal&^(PageSize-1)] = page
	}
	return table, mem
}

func (k kernel) context(options map[string]any) (Context, *[]string) {
	table, mem := k.open()
	var diags []string
	if options == nil {
		options = map[string]any{}
	}
	options[optionDiagnostics] = &diags
	return Context{Memory: mem, Symbols: table, Profile: profiles.WindowsX64Profile{}, Options: options}, &diags
}
