package memoryranges

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
)

var ErrVADLayout = errors.New("memoryranges: symbol table lacks a member the vad walk needs")

// Widths the four measured kernel tables give, for tables that name a member
// without its type (S24 T3, T5).
const (
	ulongWidth = 4
	ucharWidth = 1
)

type vadLayout struct {
	rootAt      uint64
	vadNode     uint64
	left, right uint64

	startLow, endLow   symbols.IntField
	startHigh, endHigh symbols.IntField
	haveHigh           bool

	protection, private, kind symbols.IntField
	haveProtection            bool
	havePrivate, haveKind     bool

	commit, commitHigh       symbols.IntField
	haveCommit, haveHighPart bool

	parent     uint64
	parentMask uint64
	haveParent bool

	tagDelta uint64
	haveTag  bool

	pointerSize uint64
}

func memberField(t symbols.SymbolTable, typ, name string, fallback uint64) (symbols.IntField, bool) {
	f, err := t.Field(typ, name)
	if err != nil {
		return symbols.IntField{}, false
	}
	if r, err := symbols.ResolveIntField(t, typ, name); err == nil {
		return r, true
	}
	if fallback == 0 || fallback > 8 {
		return symbols.IntField{}, false
	}
	return symbols.IntField{Offset: f.Offset, Width: fallback, BitOffset: f.Type.BitOffset, BitLength: f.Type.BitLength}, true
}

func offsetOf(t symbols.SymbolTable, typ, name string) (uint64, bool) {
	f, err := t.Field(typ, name)
	if err != nil {
		return 0, false
	}
	return f.Offset, true
}

func required(t symbols.SymbolTable, typ, name string) (uint64, error) {
	off, ok := offsetOf(t, typ, name)
	if !ok {
		return 0, fmt.Errorf("%w: %s.%s", ErrVADLayout, typ, name)
	}
	return off, nil
}

func resolveLayout(t symbols.SymbolTable) (vadLayout, error) {
	l := vadLayout{pointerSize: uint64(t.PointerSize())}
	vadRoot, err := required(t, "_EPROCESS", "VadRoot")
	if err != nil {
		return l, err
	}
	root, err := required(t, "_RTL_AVL_TREE", "Root")
	if err != nil {
		return l, err
	}
	l.rootAt = vadRoot + root
	if l.left, err = required(t, "_RTL_BALANCED_NODE", "Left"); err != nil {
		return l, err
	}
	if l.right, err = required(t, "_RTL_BALANCED_NODE", "Right"); err != nil {
		return l, err
	}
	l.vadNode, _ = offsetOf(t, "_MMVAD_SHORT", "VadNode")

	var ok bool
	if l.startLow, ok = memberField(t, "_MMVAD_SHORT", "StartingVpn", ulongWidth); !ok {
		return l, fmt.Errorf("%w: _MMVAD_SHORT.StartingVpn", ErrVADLayout)
	}
	if l.endLow, ok = memberField(t, "_MMVAD_SHORT", "EndingVpn", ulongWidth); !ok {
		return l, fmt.Errorf("%w: _MMVAD_SHORT.EndingVpn", ErrVADLayout)
	}
	sh, okS := memberField(t, "_MMVAD_SHORT", "StartingVpnHigh", ucharWidth)
	eh, okE := memberField(t, "_MMVAD_SHORT", "EndingVpnHigh", ucharWidth)
	if okS && okE {
		l.startHigh, l.endHigh, l.haveHigh = sh, eh, true
	}

	l.protection, l.haveProtection = flagMember(t, "Protection")
	l.private, l.havePrivate = flagMember(t, "PrivateMemory")
	l.kind, l.haveKind = flagMember(t, "VadType")

	if l.commit, l.haveCommit = memberField(t, "_MMVAD_SHORT", "CommitCharge", ulongWidth); !l.haveCommit {
		l.commit, l.haveCommit = wordMember(t, "u1", "_MMVAD_FLAGS1", "CommitCharge")
	}
	l.commitHigh, l.haveHighPart = memberField(t, "_MMVAD_SHORT", "CommitChargeHigh", ucharWidth)

	if l.parent, l.haveParent = offsetOf(t, "_RTL_BALANCED_NODE", "ParentValue"); l.haveParent {
		l.parentMask = overlaidBits(t)
	}
	l.tagDelta, l.haveTag = poolTagDelta(t)
	return l, nil
}

func flagMember(t symbols.SymbolTable, name string) (symbols.IntField, bool) {
	if f, ok := memberField(t, "_MMVAD_SHORT", name, ulongWidth); ok {
		return f, true
	}
	return wordMember(t, "u", "_MMVAD_FLAGS", name)
}

// The tables do not expand the unions u and u1, so a bit field's offset in its
// flags type is added to the union's offset (S24 O1).
func wordMember(t symbols.SymbolTable, union, flagsType, name string) (symbols.IntField, bool) {
	at, ok := offsetOf(t, "_MMVAD_SHORT", union)
	if !ok {
		return symbols.IntField{}, false
	}
	width := uint64(ulongWidth)
	if st, err := t.Struct(flagsType); err == nil && st.Size > 0 && st.Size <= 8 {
		width = st.Size
	}
	f, ok := memberField(t, flagsType, name, width)
	if !ok {
		return symbols.IntField{}, false
	}
	f.Offset += at
	return f, true
}

func overlaidBits(t symbols.SymbolTable) uint64 {
	end := uint64(0)
	for _, name := range []string{"Balance", "Red"} {
		if f, err := t.Field("_RTL_BALANCED_NODE", name); err == nil && f.Type.BitLength > 0 {
			end = max(end, uint64(f.Type.BitOffset)+uint64(f.Type.BitLength))
		}
	}
	return 1<<end - 1
}

// The value all four measured tables give, for a 64-bit table without
// _POOL_HEADER (S24 4.1 step 7, O5).
const measuredTagDelta64 = 12

func poolTagDelta(t symbols.SymbolTable) (uint64, bool) {
	st, err := t.Struct("_POOL_HEADER")
	tag, ok := offsetOf(t, "_POOL_HEADER", "PoolTag")
	if err == nil && ok && st.Size >= tag+4 {
		return st.Size - tag, true
	}
	if t.PointerSize() == 8 {
		return measuredTagDelta64, true
	}
	return 0, false
}
