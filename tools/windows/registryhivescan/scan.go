package registryhivescan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/poolbig"
	"github.com/aoiflux/libvapour/tools/winkernel"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.registry.scan_hives"

const (
	hiveTag       = "CM10"
	hiveSignature = 0xbee0bee0
)

var ErrLayout = errors.New("registryhivescan: _CMHIVE or _HHIVE members missing from the symbol table")

type ListState string

const (
	Listed      ListState = "listed"
	NotListed   ListState = "not_listed"
	ListUnknown ListState = "unknown"
)

type Hive struct {
	Address      uint64
	PoolSize     uint64
	Verified     bool
	FilePath     string
	RegistryPath string
	OnHiveList   ListState
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find registry hive objects (_CMHIVE) in CM10 big-pool allocations, with their file and registry paths and whether the kernel's hive list still links them",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Hive, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	l, err := loadLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	pools, err := poolbig.ReadTable(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return scan(ctx, l, pools, hiveList(ctx, l)), nil
}

type layout struct {
	hive, signature, size uint64
	paths                 []uint64
	list                  uint64
	listKnown             bool
	strings               util.UnicodeStringLayout
}

func loadLayout(table symbols.SymbolTable) (layout, error) {
	hive, err := table.Field("_CMHIVE", "Hive")
	if err != nil {
		return layout{}, fmt.Errorf("%w: %w", ErrLayout, err)
	}
	sig, err := table.Field("_HHIVE", "Signature")
	if err != nil {
		return layout{}, fmt.Errorf("%w: %w", ErrLayout, err)
	}
	st, err := table.Struct("_CMHIVE")
	if err != nil {
		return layout{}, fmt.Errorf("%w: %w", ErrLayout, err)
	}
	l := layout{hive: hive.Offset, signature: sig.Offset, size: st.Size, strings: util.ResolveUnicodeStringLayout(table)}
	for _, m := range []string{"FileFullPath", "FileUserName", "HiveRootPath"} {
		f, err := table.Field("_CMHIVE", m)
		if err != nil {
			l.paths = append(l.paths, noMember)
			continue
		}
		l.paths = append(l.paths, f.Offset)
	}
	if f, err := table.Field("_CMHIVE", "HiveList"); err == nil {
		l.list, l.listKnown = f.Offset, true
	}
	return l, nil
}

const noMember = ^uint64(0)

// A nil set means the list could not be walked, which is not the same as a
// hive missing from it.
func hiveList(ctx tools.Context, l layout) map[uint64]bool {
	if !l.listKnown {
		return nil
	}
	head, err := ctx.Symbols.LookupSymbol("CmpHiveListHead")
	if err != nil {
		return nil
	}
	links, err := winkernel.NativeListLayout(ctx.Symbols)
	if err != nil {
		return nil
	}
	walk, err := winkernel.ListWalker{
		Tool: Name, Memory: ctx.Memory, Layout: links,
		Limit: ctx.Bounds().MaxListEntries, Report: ctx.AddDiagnostic,
	}.WalkRecovering(head.Address, "CmpHiveListHead")
	if err != nil {
		ctx.AddDiagnostic("%s: CmpHiveListHead at 0x%x: hive list not walked: %v", Name, head.Address, err)
		return nil
	}
	set := map[uint64]bool{}
	for _, e := range walk.Entries {
		if at, ok := winkernel.Container(e, l.list); ok {
			set[at] = true
		}
	}
	return set
}

type tally struct{ inUse, freed, small, unsigned, unverified int }

func scan(ctx tools.Context, l layout, pools []poolbig.Allocation, listed map[uint64]bool) []Hive {
	var out []Hive
	var n tally
	nameBytes := uint64(max(ctx.Bounds().MaxNameBytes, 0))
	for _, p := range pools {
		if p.Tag != hiveTag {
			continue
		}
		if p.Freed {
			n.freed++
			continue
		}
		n.inUse++
		if p.Size < l.size {
			n.small++
			continue
		}
		h := Hive{Address: p.Address, PoolSize: p.Size, OnHiveList: ListUnknown}
		switch sig, err := readU32(ctx.Memory, p.Address+l.hive+l.signature); {
		case err != nil:
			n.unverified++
		case sig != hiveSignature:
			n.unsigned++
			continue
		default:
			h.Verified = true
		}
		h.FilePath, h.RegistryPath = paths(ctx.Memory, l, p.Address, nameBytes)
		if listed != nil {
			h.OnHiveList = NotListed
			if listed[p.Address] {
				h.OnHiveList = Listed
			}
		}
		out = append(out, h)
	}
	ctx.AddDiagnostic("%s: %d CM10 allocations in use, %d freed, %d smaller than _CMHIVE, %d without the hive signature, %d unverified",
		Name, n.inUse, n.freed, n.small, n.unsigned, n.unverified)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

func readU32(mem memory.MemoryReader, at uint64) (uint32, error) {
	raw, err := mem.ReadAt(at, 4)
	if err != nil {
		return 0, err
	}
	if len(raw) < 4 {
		return 0, memory.ErrOutOfBounds
	}
	return binary.LittleEndian.Uint32(raw), nil
}

func paths(mem memory.MemoryReader, l layout, cmhive, maxBytes uint64) (file, registry string) {
	texts := make([]string, len(l.paths))
	for i, off := range l.paths {
		if off == noMember {
			continue
		}
		if s, err := util.ReadUnicodeString(mem, cmhive+off, l.strings, maxBytes); err == nil && s.Buffer != 0 {
			texts[i] = s.Value
		}
	}
	for _, t := range texts {
		if t != "" {
			file = t
			break
		}
	}
	return file, texts[len(texts)-1]
}
