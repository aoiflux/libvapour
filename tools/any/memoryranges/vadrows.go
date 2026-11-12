package memoryranges

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

type VAD struct {
	Base               uint64
	Start              uint64
	End                uint64
	PrivateMemory      bool
	PrivateMemoryKnown bool
	Tag                string
}

// Only a section view is an _MMVAD with a Subsection (S24 4.6).
func (v VAD) IsMMVAD() bool { return isSectionView(v.PrivateMemoryKnown, v.PrivateMemory, v.Tag) }

func ProcessVADs(ctx tools.Context, proc processlist.Process) ([]VAD, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	l, err := resolveLayout(ctx.Symbols)
	if err != nil {
		return nil, err
	}
	nodes, err := l.tree(ctx, proc, userLimit(ctx))
	if err != nil {
		return nil, err
	}
	out := make([]VAD, 0, len(nodes))
	for _, n := range nodes {
		v := VAD{Base: n.base, Start: n.start(), End: n.end(), Tag: l.tag(ctx, n.base)}
		if f, err := l.flags(ctx, n.base); err == nil {
			v.PrivateMemory, v.PrivateMemoryKnown = f.private, f.privateOK
		}
		out = append(out, v)
	}
	return out, nil
}

type Decoder struct {
	layout     vadLayout
	protect    []uint32
	userLimit  uint64
	files      FileNames
	filesKnown bool
}

func NewDecoder(ctx tools.Context) (Decoder, error) {
	l, err := resolveLayout(ctx.Symbols)
	if err != nil {
		return Decoder{}, err
	}
	d := Decoder{layout: l, userLimit: userLimit(ctx)}
	if d.protect, err = readProtectTable(ctx, l); err != nil {
		ctx.AddDiagnostic("%s: MmProtectToValue: not read, VAD protections unknown: %v", walkLabel(ctx), err)
	}
	d.files, d.filesKnown = fileNamesFor(ctx)
	return d, nil
}

func (d Decoder) Mappings(ctx tools.Context, proc processlist.Process) ([]Mapping, error) {
	l := d.layout
	nodes, err := l.tree(ctx, proc, d.userLimit)
	if err != nil {
		return nil, err
	}
	out := make([]Mapping, 0, len(nodes))
	for _, n := range nodes {
		m := Mapping{
			PID:                proc.PID,
			Process:            processName(proc),
			DirectoryTableBase: proc.DirectoryTableBase,
			VadAddress:         n.base,
			Start:              n.start(),
			End:                n.end(),
			Protection:         ProtectionUnknown,
			Type:               KindUnknown,
			Tag:                l.tag(ctx, n.base),
			PathUnreadable:     true,
			ParentUnreadable:   true,
		}
		f, err := l.flags(ctx, n.base)
		if err != nil {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("vad at 0x%x: %w", n.base, err)
			}
			ctx.AddDiagnostic("%s: pid %d VAD at 0x%x: flags not read: %v", walkLabel(ctx), proc.PID, n.base, err)
		} else {
			m.Protection = protectionOf(d.protect, f)
			m.Type = f.kindName()
			m.PrivateMemory, m.PrivateMemoryKnown = f.private, f.privateOK
		}
		if p, ok := l.parentOf(ctx, n.node); ok {
			m.Parent, m.ParentUnreadable = p, false
		}
		m.CommitCharge, m.CommitChargeKnown = l.commitCharge(ctx, n.base)
		named := false
		switch {
		case m.PrivateMemoryKnown && m.PrivateMemory:
			m.NoFile = true
		case d.filesKnown:
			mf, ok := d.files.Resolve(ctx, n.base)
			m.NoFile = mf.NoFile
			if ok && !mf.NameUnreadable {
				m.Path, named = mf.Path, true
			}
		}
		m.PathUnreadable = !named && !m.NoFile
		out = append(out, m)
	}
	return out, nil
}

type TreeNode struct {
	Base   uint64
	Parent uint64
	Left   uint64
	Right  uint64
	Start  uint64
	End    uint64
	Tag    string
}

type TreeWalker struct {
	layout vadLayout
}

var errNoParentLink = errors.New("memoryranges: no _RTL_BALANCED_NODE.ParentValue in symbols")

func NewTreeWalker(table symbols.SymbolTable) (TreeWalker, error) {
	l, err := resolveLayout(table)
	if err != nil {
		return TreeWalker{}, err
	}
	if !l.haveParent {
		return TreeWalker{}, fmt.Errorf("%w: %w", ErrVADLayout, errNoParentLink)
	}
	return TreeWalker{layout: l}, nil
}

func (w TreeWalker) Walk(ctx tools.Context, proc processlist.Process) ([]TreeNode, error) {
	l := w.layout
	nodes, err := l.tree(ctx, proc, userLimit(ctx))
	if err != nil {
		return nil, err
	}
	out := make([]TreeNode, 0, len(nodes))
	unread := 0
	for _, n := range nodes {
		p, ok := l.parentOf(ctx, n.node)
		if !ok {
			unread++
		}
		out = append(out, TreeNode{Base: n.base, Parent: p, Left: n.left, Right: n.right,
			Start: n.start(), End: n.end(), Tag: l.tag(ctx, n.base)})
	}
	if unread > 0 {
		ctx.AddDiagnostic("%s: pid %d _EPROCESS at 0x%x: %d VAD parent links not read, shown as 0",
			walkLabel(ctx), proc.PID, proc.EPROCESS, unread)
	}
	return out, nil
}
