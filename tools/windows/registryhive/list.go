package registryhive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.registry.list_hives"

const optionNameFilter = "windows.registry.list_hives.name"

var ErrNoHiveList = errors.New("registryhive: CmpHiveListHead not in the symbol table")

type Hive struct {
	Name         string
	Address      uint64
	FileFullPath string
	RegistryPath string
	RootCell     uint32
	// A non-zero VolatileSize marks keys that exist only in memory.
	StableSize   uint64
	VolatileSize uint64
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the loaded registry hives on CmpHiveListHead with their file and registry paths and storage sizes",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]Hive, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	filter, err := ctx.StringOption(optionNameFilter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	hives, err := listHives(ctx)
	if err != nil {
		return nil, err
	}
	return SelectHives(hives, filter), nil
}

func listHives(ctx tools.Context) ([]Hive, error) {
	l, err := loadLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !l.hasHiveList {
		return nil, fmt.Errorf("%s: %w: _CMHIVE.HiveList", Name, ErrLayout)
	}
	head, err := ctx.Symbols.LookupSymbol("CmpHiveListHead")
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", Name, ErrNoHiveList, err)
	}
	listLayout, err := winkernel.NativeListLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk, err := winkernel.ListWalker{
		Tool: Name, Memory: ctx.Memory, Layout: listLayout,
		Limit: ctx.Bounds().MaxListEntries, Strict: ctx.StrictMode(), Report: ctx.AddDiagnostic,
	}.WalkRecovering(head.Address, "CmpHiveListHead")
	if err != nil {
		return nil, err
	}
	strs := util.ResolveUnicodeStringLayout(ctx.Symbols)
	nameBytes := uint64(ctx.Bounds().MaxNameBytes)
	var out []Hive
	for _, entry := range walk.Entries {
		cmhive, ok := winkernel.Container(entry, l.hiveList)
		if !ok {
			continue
		}
		layer, err := NewHiveLayer(ctx, cmhive)
		if err != nil {
			ctx.AddDiagnostic("%s: hive at 0x%x: not opened: %v", Name, cmhive, err)
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: hive at 0x%x: %w", Name, cmhive, err)
			}
			continue
		}
		path := func(at uint64, present bool) string {
			if !present {
				return ""
			}
			s, err := util.ReadUnicodeString(ctx.Memory, cmhive+at, strs, nameBytes)
			if err != nil {
				return ""
			}
			return strings.TrimRight(s.Value, "\x00")
		}
		hv := Hive{Address: cmhive, RegistryPath: path(l.rootPath, l.hasRootPath),
			StableSize: layer.length[0], VolatileSize: layer.length[1]}
		hv.FileFullPath = firstNonEmpty(path(l.fullPath, l.hasFullPath), path(l.userName, l.hasUserName), hv.RegistryPath)
		hv.Name = LastPathComponent(hv.FileFullPath)
		if root, err := layer.rootCell(false); err == nil {
			hv.RootCell = root
		}
		out = append(out, hv)
	}
	return out, nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func (h *HiveLayer) BaseBlock() ([]byte, error) {
	at, err := h.pointer(h.ctx.Memory, h.hhive+h.l.baseBlock)
	if err != nil {
		return nil, fmt.Errorf("hive at 0x%x: base block pointer: %w", h.cmhive, err)
	}
	if at == 0 {
		return nil, fmt.Errorf("hive at 0x%x: base block pointer is null", h.cmhive)
	}
	b, err := h.ctx.Memory.ReadAt(at, h.l.shape.blockSize)
	if err != nil || uint64(len(b)) < h.l.shape.blockSize {
		return nil, fmt.Errorf("hive at 0x%x: base block at 0x%x does not read: %v", h.cmhive, at, err)
	}
	if v := binary.LittleEndian.Uint32(b[h.l.baseSig:]); v != baseSignature {
		return nil, fmt.Errorf("hive at 0x%x: base block at 0x%x: signature 0x%x is not regf", h.cmhive, at, v)
	}
	return b, nil
}
