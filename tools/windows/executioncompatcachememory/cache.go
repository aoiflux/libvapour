package executioncompatcachememory

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const Name = "windows.execution.list_compat_cache"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the application compatibility cache held by ahcache.sys in kernel memory, most recently used first",
		},
		RunAny,
	)
}

var (
	ErrNot64Bit     = errors.New("executioncompatcachememory: kernel is not 64-bit")
	ErrNoDriver     = errors.New("executioncompatcachememory: ahcache.sys is not loaded")
	ErrNoSymbols    = errors.New("executioncompatcachememory: ahcache.sys symbols not loaded")
	ErrCacheUnread  = errors.New("executioncompatcachememory: cache does not read")
	ErrTypeMissing  = errors.New("executioncompatcachememory: kernel type member missing")
	ErrLimit        = errors.New("executioncompatcachememory: cache is larger than the limits")
	ErrShort        = errors.New("executioncompatcachememory: structure does not read in full")
	ErrKeyLayout    = errors.New("executioncompatcachememory: key string is not well formed")
	ErrKeyTooLong   = errors.New("executioncompatcachememory: key is longer than MaxNameBytes")
	ErrDataTooLarge = errors.New("executioncompatcachememory: data is larger than MaxBufferBytes")
)

type CacheEntry struct {
	Position         int
	PositionFromTail int
	InList           bool
	InTable          bool
	Key              string
	KeyUnreadable    bool
	FileLastWrite    time.Time
	DataSize         uint32
	Data             []byte
	DataUnreadable   bool
	Address          uint64
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]CacheEntry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	if ctx.Symbols.PointerSize() != 8 {
		return nil, fmt.Errorf("%s: %w", Name, ErrNot64Bit)
	}
	mods, err := modulelist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		return nil, fmt.Errorf("%s: loaded modules: %w", Name, err)
	}
	handle, err := locateHandle(ctx, mods)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return collect(ctx, handle)
}

func locateHandle(ctx tools.Context, mods []modulelist.Module) (uint64, error) {
	var drv *modulelist.Module
	for i := range mods {
		if !mods[i].NameUnreadable && strings.EqualFold(mods[i].Name, driverName) {
			drv = &mods[i]
			break
		}
	}
	if drv == nil {
		return 0, ErrNoDriver
	}
	if ctx.LoadPDB == nil {
		return 0, fmt.Errorf("%w: no symbol loader", ErrNoSymbols)
	}
	h, err := extract.ReadHeaders(ctx.Memory, drv.Base)
	if err != nil {
		return 0, fmt.Errorf("%w: %s at 0x%x: %w", ErrNoSymbols, driverName, drv.Base, err)
	}
	read := pe.MappedReader(ctx.Memory, drv.Base, h.Optional.SizeOfImage)
	dir, err := h.ReadDataDirectory(read, pe.DirectoryEntryDebug)
	if err != nil {
		return 0, fmt.Errorf("%w: %s at 0x%x: %w", ErrNoSymbols, driverName, drv.Base, err)
	}
	cv, err := pe.ReadCodeView(read, dir)
	if err != nil {
		return 0, fmt.Errorf("%w: %s at 0x%x: %w", ErrNoSymbols, driverName, drv.Base, err)
	}
	fp := autoload.Fingerprint{PDBName: cv.PDBName(), GUID: autoload.FormatGUID(cv.GUID[:]), Age: cv.Age}
	table, err := ctx.LoadPDB(fp)
	if err != nil || table == nil {
		return 0, fmt.Errorf("%w: %s: %v", ErrNoSymbols, fp, err)
	}
	sym, err := table.LookupSymbol(handleSymbol)
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %w", ErrNoSymbols, fp, err)
	}
	if sym.Address >= uint64(h.Optional.SizeOfImage) {
		return 0, fmt.Errorf("%w: %s at rva 0x%x is outside the image", ErrNoSymbols, handleSymbol, sym.Address)
	}
	return drv.Base + sym.Address, nil
}
