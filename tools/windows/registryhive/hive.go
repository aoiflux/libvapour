package registryhive

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

var (
	ErrNotHive    = errors.New("registryhive: hive signature is not 0xbee0bee0")
	ErrNoRootCell = errors.New("registryhive: root cell not readable from the base block or the root key control block")
)

type HiveLayer struct {
	ctx    tools.Context
	bounds limits.Limits
	l      *layout
	cmhive uint64
	hhive  uint64

	length       [2]uint64
	mapAt        [2]uint64
	lengthKnown  [2]bool
	cells        memory.MemoryReader
	tables       map[uint64]uint64
	entries      map[uint64]mapEntry
	checkBins    bool
	bins         map[uint64]error
	root         uint32
	rootErr      error
	rootResolved bool
}

type KeyNode struct {
	CellIndex           uint32
	Address             uint64
	Name                string
	LastWrite           uint64
	LastWriteUnreadable bool
	NameUnreadable      bool
	SubkeysUnreadable   bool
	ValuesUnreadable    bool

	parent      uint32
	parentRead  bool
	counts      [2]uint32
	countRead   [2]bool
	lists       [2]uint32
	listRead    [2]bool
	valueCount  uint32
	valueList   uint32
	class       uint32
	classLength uint16
	flags       uint16
}

type Value struct {
	Name             string
	Type             uint32
	Data             string
	Raw              []byte
	Length           uint32
	TypeUnreadable   bool
	LengthUnreadable bool
	NameUnreadable   bool
}

func (v Value) Unreadable() bool { return v.LengthUnreadable || uint64(len(v.Raw)) < uint64(v.Length) }

func NewHiveLayer(ctx tools.Context, cmhiveAddr uint64) (*HiveLayer, error) {
	l, err := loadLayout(ctx.Symbols)
	if err != nil {
		return nil, err
	}
	if ctx.Memory == nil {
		return nil, tools.ErrMissingMemoryReader
	}
	h := &HiveLayer{
		ctx: ctx, bounds: ctx.Bounds(), l: l, cmhive: cmhiveAddr, hhive: cmhiveAddr + l.hive,
		tables: map[uint64]uint64{}, entries: map[uint64]mapEntry{}, bins: map[uint64]error{},
	}
	h.cells = defaultCells(ctx)
	sig, err := ctx.Memory.ReadAt(h.hhive+l.signature, 4)
	if err != nil || len(sig) < 4 {
		return nil, fmt.Errorf("hive at 0x%x: signature does not read: %w: %v", cmhiveAddr, ErrNotHive, err)
	}
	if v := binary.LittleEndian.Uint32(sig); v != hiveSignature {
		return nil, fmt.Errorf("hive at 0x%x: signature 0x%x: %w", cmhiveAddr, v, ErrNotHive)
	}
	for s := uint64(0); s < 2; s++ {
		dual := h.hhive + l.storage + s*l.dualSize
		raw, err := ctx.Memory.ReadAt(dual+l.dualLength, 4)
		if err != nil || len(raw) < 4 {
			continue
		}
		m, err := h.pointer(ctx.Memory, dual+l.dualMap)
		if err != nil {
			continue
		}
		h.length[s], h.mapAt[s], h.lengthKnown[s] = uint64(binary.LittleEndian.Uint32(raw)), m, true
	}
	if !h.lengthKnown[0] {
		return nil, fmt.Errorf("hive at 0x%x: stable storage length and map do not read: %w", cmhiveAddr, ErrCellUnreadable)
	}
	return h, nil
}

// A nil reader keeps the kernel half only on builds with a Registry
// process: user addresses read through the kernel layer would come from
// whichever process it was built on.
func (h *HiveLayer) SetCellReader(r memory.MemoryReader) {
	if r == nil {
		h.cells = defaultCells(h.ctx)
	} else {
		h.cells = r
	}
	h.bins = map[uint64]error{}
}

func (h *HiveLayer) SetBinValidation(on bool) {
	h.checkBins = on
	h.bins = map[uint64]error{}
}

// The base block names the root cell; when it is out of memory the root key
// control block does. Failing both, the first cell after the first bin
// header is taken if it is a key node marked as a hive root.
func (h *HiveLayer) RootCell() (uint32, error) { return h.rootCell(true) }

func (h *HiveLayer) rootCell(report bool) (uint32, error) {
	if h.rootResolved {
		return h.root, h.rootErr
	}
	h.rootResolved = true
	base, baseErr := h.BaseBlock()
	if baseErr == nil {
		h.root = binary.LittleEndian.Uint32(base[h.l.baseRoot:])
		return h.root, nil
	}
	kcbErr := errors.New("no RootKcb member")
	if h.l.hasRootKcb {
		if root, err := h.rootFromKcb(); err == nil {
			h.root = root
			return root, nil
		} else {
			kcbErr = err
		}
	}
	first := uint32(h.l.bin.headerSize)
	if k, err := h.KeyNode(first); err == nil && k.flags&keyHiveRoot != 0 {
		if report {
			h.ctx.AddDiagnostic("registryhive: hive at 0x%x: base block and root key control block not readable: "+
				"root taken as cell 0x%x, the first after the bin header", h.cmhive, first)
		}
		h.root = first
		return first, nil
	}
	h.rootErr = fmt.Errorf("hive at 0x%x: %w: %v; %v", h.cmhive, ErrNoRootCell, baseErr, kcbErr)
	return 0, h.rootErr
}

func (h *HiveLayer) rootFromKcb() (uint32, error) {
	kcb, err := h.pointer(h.ctx.Memory, h.cmhive+h.l.rootKcb)
	if err != nil {
		return 0, fmt.Errorf("root key control block pointer: %w", err)
	}
	if kcb == 0 {
		return 0, errors.New("root key control block pointer is null")
	}
	raw, err := h.ctx.Memory.ReadAt(kcb+h.l.kcbKeyCell, 4)
	if err != nil || len(raw) < 4 {
		return 0, fmt.Errorf("root key control block at 0x%x: KeyCell does not read: %v", kcb, err)
	}
	return binary.LittleEndian.Uint32(raw), nil
}

func (h *HiveLayer) KeyNode(cellIndex uint32) (*KeyNode, error) {
	c, err := h.readCellSplit(cellIndex, h.l.key.name, h.l.key.name+2*maxKeyNameChars)
	if err != nil {
		return nil, err
	}
	k, err := decodeKey(c, h.l.key)
	if err != nil {
		return nil, fmt.Errorf("cell 0x%x at 0x%x: %w", cellIndex, c.addr, err)
	}
	return k, nil
}

func (h *HiveLayer) Subkeys(node *KeyNode) []*KeyNode {
	keys, _ := h.SubkeysChecked(node)
	return keys
}

// Keys come in list order, which the hive keeps sorted by name.
func (h *HiveLayer) SubkeysChecked(node *KeyNode) ([]*KeyNode, bool) {
	if node == nil {
		return nil, false
	}
	complete := !node.SubkeysUnreadable
	w := &leafWalk{h: h, parent: node.CellIndex, seen: map[uint32]bool{}, limit: listLimit(h.bounds)}
	for s := 0; s < 2; s++ {
		if node.countRead[s] && node.counts[s] == 0 {
			continue
		}
		if !node.listRead[s] {
			complete = false
			continue
		}
		before := len(w.keys)
		if !w.list(node.lists[s], true) {
			complete = false
		}
		if node.countRead[s] && uint64(len(w.keys)-before) < uint64(node.counts[s]) {
			complete = false
		}
	}
	return w.keys, complete && !w.cut
}

type leafWalk struct {
	h      *HiveLayer
	parent uint32
	seen   map[uint32]bool
	keys   []*KeyNode
	limit  int
	cut    bool
}

func (w *leafWalk) list(index uint32, allowRoot bool) bool {
	kind, cells, ok := w.h.readIndex(index)
	if kind == indexRoot {
		if !allowRoot {
			return false
		}
		for _, sub := range cells {
			if !w.list(sub, false) {
				ok = false
			}
		}
		return ok
	}
	for _, c := range cells {
		if w.seen[c] {
			ok = false
			continue
		}
		w.seen[c] = true
		if len(w.keys) >= w.limit {
			w.cut = true
			return false
		}
		k, err := w.h.KeyNode(c)
		if err != nil || (k.parentRead && k.parent != w.parent) {
			ok = false
			continue
		}
		w.keys = append(w.keys, k)
	}
	return ok
}

func listLimit(b limits.Limits) int {
	if b.MaxListEntries > 0 {
		return b.MaxListEntries
	}
	return limits.DefaultMaxListEntries
}

func (h *HiveLayer) readIndex(index uint32) (indexKind, []uint32, bool) {
	il := h.l.index
	head, _, err := h.readCell(index, il.list)
	if err != nil {
		return indexNone, nil, false
	}
	kind, count, err := decodeIndexHead(head, il)
	if err != nil {
		return indexNone, nil, false
	}
	stride := uint64(4)
	if kind == indexFastLeaf || kind == indexHashLeaf {
		stride = il.leafStride
	}
	body, _, err := h.readCell(index, il.list+uint64(count)*stride)
	if err != nil {
		return kind, nil, false
	}
	cells, ok := decodeIndexEntries(body, il, kind, count)
	return kind, cells, ok
}

func (h *HiveLayer) Values(node *KeyNode) []Value {
	values, _ := h.ValuesChecked(node)
	return values
}

func (h *HiveLayer) ValuesChecked(node *KeyNode) ([]Value, bool) {
	if node == nil {
		return nil, false
	}
	if node.ValuesUnreadable {
		return nil, false
	}
	if node.valueCount == 0 {
		return nil, true
	}
	count, complete := uint64(node.valueCount), true
	if limit := uint64(listLimit(h.bounds)); count > limit {
		count, complete = limit, false
	}
	list, _, err := h.readCell(node.valueList, 4*count)
	if err != nil {
		return nil, false
	}
	var out []Value
	for i := uint64(0); i < count; i++ {
		idx, ok := list.u32(4 * i)
		if !ok {
			complete = false
			continue
		}
		v, err := h.value(idx)
		if err != nil {
			complete = false
			continue
		}
		out = append(out, v)
	}
	return out, complete
}

func (h *HiveLayer) value(index uint32) (Value, error) {
	c, err := h.readCellSplit(index, h.l.value.name, h.l.value.name+2*maxValueNameChars)
	if err != nil {
		return Value{}, err
	}
	v, ref, err := decodeValue(c, h.l.value)
	if err != nil {
		return Value{}, fmt.Errorf("cell 0x%x at 0x%x: %w", index, c.addr, err)
	}
	if !v.LengthUnreadable {
		v.Raw = h.valueData(ref, v.Length)
	}
	v.Data = renderData(v.Type, v.Raw)
	return v, nil
}

func (h *HiveLayer) ClassData(node *KeyNode) []byte {
	if node == nil || node.classLength == 0 {
		return nil
	}
	c, _, err := h.readCell(node.class, uint64(node.classLength))
	if err != nil || !c.has(0, uint64(node.classLength)) {
		return nil
	}
	return c.b[:node.classLength]
}
