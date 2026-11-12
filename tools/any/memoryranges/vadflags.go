package memoryranges

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

var ErrVADFlagsUnread = errors.New("memoryranges: vad flags do not read")

// VadType 2 is the only value whose meaning is measured: its control area
// always has Image set (S24 M11, O2).
const vadTypeImage = 2

type vadFlags struct {
	protection   uint64
	protectionOK bool
	private      bool
	privateOK    bool
	kind         uint64
	kindOK       bool
}

func (l vadLayout) flags(ctx tools.Context, base uint64) (vadFlags, error) {
	var f vadFlags
	read := func(field symbols.IntField, have bool, name string) (uint64, bool, error) {
		if !have {
			return 0, false, nil
		}
		v, err := field.Read(ctx.Memory, base)
		if err != nil {
			return 0, false, fmt.Errorf("%w: %s: %w", ErrVADFlagsUnread, name, err)
		}
		return v, true, nil
	}
	var err error
	if f.protection, f.protectionOK, err = read(l.protection, l.haveProtection, "Protection"); err != nil {
		return vadFlags{}, err
	}
	var private uint64
	if private, f.privateOK, err = read(l.private, l.havePrivate, "PrivateMemory"); err != nil {
		return vadFlags{}, err
	}
	f.private = private != 0
	if f.kind, f.kindOK, err = read(l.kind, l.haveKind, "VadType"); err != nil {
		return vadFlags{}, err
	}
	return f, nil
}

func (f vadFlags) kindName() string {
	switch {
	case !f.privateOK:
		return KindUnknown
	case f.private:
		return KindPrivate
	case f.kindOK && f.kind == vadTypeImage:
		return KindImage
	}
	return KindMapped
}

// The high byte sits above every bit of the low member (S24 4.7).
func (l vadLayout) commitCharge(ctx tools.Context, base uint64) (uint64, bool) {
	if !l.haveCommit {
		return 0, false
	}
	low, err := l.commit.Read(ctx.Memory, base)
	if err != nil {
		return 0, false
	}
	if !l.haveHighPart {
		return low, true
	}
	high, err := l.commitHigh.Read(ctx.Memory, base)
	if err != nil {
		return 0, false
	}
	width := uint64(l.commit.BitLength)
	if width == 0 {
		width = 8 * l.commit.Width
	}
	return low | high<<width, true
}

func (l vadLayout) parentOf(ctx tools.Context, node uint64) (uint64, bool) {
	if !l.haveParent {
		return 0, false
	}
	v, err := ctx.Symbols.ReadPointer(ctx.Memory, node+l.parent)
	if err != nil {
		return 0, false
	}
	return v &^ l.parentMask, true
}

// Callers compare tags exactly, so bytes that are not printable ASCII give no
// tag rather than a different one.
func (l vadLayout) tag(ctx tools.Context, base uint64) string {
	if !l.haveTag || base < l.tagDelta {
		return ""
	}
	raw, err := ctx.Memory.ReadAt(base-l.tagDelta, 4)
	if err != nil || len(raw) < 4 {
		return ""
	}
	for _, c := range raw[:4] {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(raw[:4])
}

// The tags measured on section views, for a VAD whose PrivateMemory is not
// known (S24 4.6 step 1, O3).
func sectionTag(tag string) bool { return tag == "Vad " || tag == "VadI" }

func isSectionView(privateKnown, private bool, tag string) bool {
	if privateKnown {
		return !private
	}
	return sectionTag(tag)
}
