package registrykey

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.registry.read_key"

const (
	OptionHive         = "windows.registry.read_key.hive"
	OptionPath         = "windows.registry.read_key.path"
	OptionRecurse      = "windows.registry.read_key.recurse"
	OptionValidateBins = "windows.registry.read_key.validate_bins"
)

// Learn: "A registry tree can be 512 levels deep."
const maxLevels = 512

var (
	ErrIncomplete = errors.New("registrykey: key not read in full")
	ErrNoHive     = errors.New("registrykey: no hive found")
	ErrNoMatch    = errors.New("registrykey: no hive matches the hive option")
)

type Kind string

const (
	KindKey   Kind = "key"
	KindValue Kind = "value"
)

type Item struct {
	HivePath    string
	HiveAddress uint64
	Path        string
	Depth       int
	Kind        Kind

	Name           string
	NameUnreadable bool

	Type           string
	TypeCode       uint32
	TypeUnreadable bool
	Data           string
	Raw            []byte
	Length         uint32
	DataUnreadable bool

	LastWrite           time.Time
	LastWriteUnreadable bool
	Volatile            bool

	KeyNotRead bool
	Reason     string
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the subkeys and values of a key path in the registry hives in memory, optionally recursively",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type options struct {
	hive, path            string
	recurse, validateBins bool
}

func readOptions(ctx tools.Context) (options, error) {
	var o options
	var err error
	if o.hive, err = ctx.StringOption(OptionHive); err != nil {
		return o, err
	}
	if o.path, err = ctx.StringOption(OptionPath); err != nil {
		return o, err
	}
	if o.recurse, err = ctx.BoolOption(OptionRecurse); err != nil {
		return o, err
	}
	if o.validateBins, err = ctx.BoolOption(OptionValidateBins); err != nil {
		return o, err
	}
	o.hive, o.path = strings.TrimSpace(o.hive), strings.TrimSpace(o.path)
	return o, nil
}

func Run(ctx tools.Context) ([]Item, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	o, err := readOptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	hives := registryhive.GatherHives(ctx)
	if len(hives) == 0 {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoHive)
	}
	picked := registryhive.SelectHives(hives, o.hive)
	if len(picked) == 0 {
		return nil, fmt.Errorf("%s: %q: %w", Name, o.hive, ErrNoMatch)
	}
	cells := registryhive.CellReader(ctx)
	l := lister{ctx: ctx, path: o.path, recurse: o.recurse}
	for _, hv := range picked {
		layer, err := registryhive.NewHiveLayer(ctx, hv.Address)
		if err != nil {
			ctx.AddDiagnostic("%s: hive at 0x%x: not opened: %v", Name, hv.Address, err)
			continue
		}
		layer.SetCellReader(cells)
		layer.SetBinValidation(o.validateBins)
		l.listHive(layer, hiveID{path: hivePath(hv), address: hv.Address})
	}
	if l.firstErr != nil && ctx.StrictMode() {
		return l.out, l.firstErr
	}
	return l.out, nil
}

func hivePath(h registryhive.Hive) string {
	if h.FileFullPath != "" {
		return h.FileFullPath
	}
	return h.Name
}

type keyReader interface {
	OpenKey(path string) (*registryhive.KeyNode, error)
	SubkeysChecked(node *registryhive.KeyNode) ([]*registryhive.KeyNode, bool)
	ValuesChecked(node *registryhive.KeyNode) ([]registryhive.Value, bool)
}

type hiveID struct {
	path    string
	address uint64
}

type lister struct {
	ctx      tools.Context
	path     string
	recurse  bool
	out      []Item
	firstErr error
}

func (l *lister) fail(err error) {
	if l.firstErr == nil {
		l.firstErr = err
	}
}

func (l *lister) listHive(h keyReader, id hiveID) {
	chain, err := resolve(h, l.path)
	if err != nil {
		l.ctx.AddDiagnostic("%s: hive at 0x%x: key %q not read: %v", Name, id.address, l.path, err)
		if !errors.Is(err, registryhive.ErrKeyNotFound) {
			l.fail(fmt.Errorf("%s: hive at 0x%x: key %q: %w", Name, id.address, l.path, ErrIncomplete))
		}
		l.out = append(l.out, Item{HivePath: id.path, HiveAddress: id.address, Path: l.path, Kind: KindKey,
			NameUnreadable: true, LastWriteUnreadable: true, KeyNotRead: true, Reason: err.Error()})
		return
	}
	w := walk{l: l, h: h, id: id, open: map[uint32]bool{}, seen: map[uint32]bool{}}
	for _, k := range chain {
		w.open[k.CellIndex] = true
	}
	key := chain[len(chain)-1]
	w.list(key, joinNames(chain[1:]), 0, len(chain)-1)
}

// The root is resolved first so that an unreadable root is told apart from a
// missing key; the stored names, not the requested ones, make the path.
func resolve(h keyReader, path string) ([]*registryhive.KeyNode, error) {
	root, err := h.OpenKey("")
	if err != nil {
		return nil, err
	}
	chain := []*registryhive.KeyNode{root}
	sub := ""
	for _, part := range strings.Split(path, `\`) {
		if part == "" {
			continue
		}
		sub += `\` + part
		k, err := h.OpenKey(sub)
		if err != nil {
			return nil, err
		}
		chain = append(chain, k)
	}
	return chain, nil
}

func joinNames(keys []*registryhive.KeyNode) string {
	names := make([]string, len(keys))
	for i, k := range keys {
		names[i] = k.Name
	}
	return strings.Join(names, `\`)
}

type walk struct {
	l    *lister
	h    keyReader
	id   hiveID
	open map[uint32]bool
	seen map[uint32]bool
}

func (w *walk) incomplete(k *registryhive.KeyNode, what string) {
	w.l.ctx.AddDiagnostic("%s: key at 0x%x: %s: %v", Name, k.Address, what, ErrIncomplete)
	w.l.fail(fmt.Errorf("%s: key at 0x%x: %s: %w", Name, k.Address, what, ErrIncomplete))
}

func (w *walk) list(k *registryhive.KeyNode, path string, depth, level int) {
	w.seen[k.CellIndex] = true
	subs, complete := w.h.SubkeysChecked(k)
	for _, sk := range subs {
		w.l.out = append(w.l.out, w.keyItem(path, depth, sk))
		if w.l.recurse && w.enters(sk, level+1) {
			w.open[sk.CellIndex] = true
			w.list(sk, childPath(path, sk.Name), depth+1, level+1)
			delete(w.open, sk.CellIndex)
		}
	}
	if !complete {
		w.incomplete(k, "subkey list not read in full")
	}
	values, complete := w.h.ValuesChecked(k)
	for _, v := range values {
		w.l.out = append(w.l.out, w.valueItem(path, depth, k, v))
	}
	if !complete {
		w.incomplete(k, "value list not read in full")
	}
}

func childPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + `\` + name
}

func (w *walk) enters(sk *registryhive.KeyNode, level int) bool {
	switch {
	case sk.NameUnreadable:
		w.incomplete(sk, "name not read, subtree not listed")
	case w.open[sk.CellIndex]:
		w.l.ctx.AddDiagnostic("%s: key at 0x%x: subkey %q is its own ancestor: subtree not listed", Name, sk.Address, sk.Name)
	case w.seen[sk.CellIndex]:
		w.l.ctx.AddDiagnostic("%s: key at 0x%x: subkey %q listed under a second parent: subtree not listed again", Name, sk.Address, sk.Name)
	case level >= maxLevels:
		w.incomplete(sk, fmt.Sprintf("subkey %q at %d levels below the root: subtree not listed", sk.Name, level))
	default:
		return true
	}
	return false
}

func lastWrite(k *registryhive.KeyNode) (time.Time, bool) {
	if k.LastWriteUnreadable {
		return time.Time{}, false
	}
	t, _ := util.FiletimeToTime(k.LastWrite)
	return t, true
}

func volatile(k *registryhive.KeyNode) bool { return k.CellIndex&0x80000000 != 0 }

func (w *walk) keyItem(path string, depth int, k *registryhive.KeyNode) Item {
	t, read := lastWrite(k)
	return Item{HivePath: w.id.path, HiveAddress: w.id.address, Path: path, Depth: depth, Kind: KindKey,
		Name: k.Name, NameUnreadable: k.NameUnreadable, LastWrite: t, LastWriteUnreadable: !read, Volatile: volatile(k)}
}

func (w *walk) valueItem(path string, depth int, k *registryhive.KeyNode, v registryhive.Value) Item {
	t, read := lastWrite(k)
	it := Item{HivePath: w.id.path, HiveAddress: w.id.address, Path: path, Depth: depth, Kind: KindValue,
		Name: v.Name, NameUnreadable: v.NameUnreadable, TypeCode: v.Type, TypeUnreadable: v.TypeUnreadable,
		Data: v.Data, Raw: v.Raw, Length: v.Length, DataUnreadable: v.Unreadable(),
		LastWrite: t, LastWriteUnreadable: !read, Volatile: volatile(k)}
	if !v.TypeUnreadable {
		it.Type = TypeName(v.Type)
	}
	return it
}

var typeNames = map[uint32]string{
	0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
	6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 11: "REG_QWORD",
}

// Only the numbers Microsoft documents get a name.
func TypeName(code uint32) string {
	if n, ok := typeNames[code]; ok {
		return n
	}
	return fmt.Sprintf("type 0x%x", code)
}
