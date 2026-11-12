package memoryranges

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

var ErrLinuxShape = errors.New("memoryranges: linux memory-area layout not recognised")

const (
	areaAlign           = 4096
	areaPageShift       = 12
	mapleNodeAlign      = 256
	mapleTypeShift      = 3
	mapleTypeMask       = 0x0f
	mapleRootFlag       = 0x02
	mapleChildMark      = 0x04
	mapleParentSlotMask = 0xf8
	mapleHeightMax      = 31
	internalTag         = 2
	internalMask        = 3
	internalBelow       = 4096
)

type mapleKind struct {
	pivots, pivotCount uint64
	slots, slotCount   uint64
	meta               uint64
}

type areaShape struct {
	tree     bool
	mmTree   uint64
	treeRoot uint64
	mmList   uint64
	next     uint64
	nodeSize uint64
	metaEnd  uint64
	kinds    [4]mapleKind
	backLink bool
	vmaSize  uint64
	mmSize   uint64
}

func shapeMember(k *linuxobj.Kernel, typ, member string) (uint64, error) {
	f, err := k.Member(typ, member)
	if err != nil {
		return 0, fmt.Errorf("%w: %s.%s: %w", ErrLinuxShape, typ, member, err)
	}
	return f.Offset, nil
}

func resolveAreaShape(k *linuxobj.Kernel) (areaShape, error) {
	var s areaShape
	for _, m := range []string{"vm_start", "vm_end", "vm_flags", "vm_pgoff", "vm_file"} {
		if _, err := shapeMember(k, "vm_area_struct", m); err != nil {
			return s, err
		}
	}
	if _, err := shapeMember(k, "task_struct", "mm"); err != nil {
		return s, err
	}
	var err error
	if s.vmaSize, err = k.SizeOf("vm_area_struct"); err != nil {
		return s, fmt.Errorf("%w: %w", ErrLinuxShape, err)
	}
	if s.mmSize, err = k.SizeOf("mm_struct"); err != nil {
		return s, fmt.Errorf("%w: %w", ErrLinuxShape, err)
	}
	s.backLink = k.Has("vm_area_struct", "vm_mm")
	if k.Has("mm_struct", "mm_mt") {
		s.tree = true
		return s, resolveMaple(k, &s)
	}
	if s.mmList, err = shapeMember(k, "mm_struct", "mmap"); err != nil {
		return s, err
	}
	s.next, err = shapeMember(k, "vm_area_struct", "vm_next")
	return s, err
}

func resolveMaple(k *linuxobj.Kernel, s *areaShape) error {
	var err error
	if s.mmTree, err = shapeMember(k, "mm_struct", "mm_mt"); err != nil {
		return err
	}
	if s.treeRoot, err = shapeMember(k, "maple_tree", "ma_root"); err != nil {
		return err
	}
	if s.nodeSize, err = k.SizeOf("maple_node"); err != nil {
		return fmt.Errorf("%w: %w", ErrLinuxShape, err)
	}
	if s.metaEnd, err = shapeMember(k, "maple_metadata", "end"); err != nil {
		return err
	}
	array := func(typ, member string) (uint64, uint64, error) {
		f, err := k.Member(typ, member)
		if err != nil || f.Type.ArrayLength == 0 {
			return 0, 0, fmt.Errorf("%w: %s.%s is not an array of known length", ErrLinuxShape, typ, member)
		}
		return f.Offset, f.Type.ArrayLength, nil
	}
	dense := &s.kinds[0]
	if dense.slots, dense.slotCount, err = array("maple_node", "slot"); err != nil {
		return err
	}
	for kind, typ := range map[int]string{1: "maple_range_64", 2: "maple_range_64", 3: "maple_arange_64"} {
		kd := &s.kinds[kind]
		if kd.pivots, kd.pivotCount, err = array(typ, "pivot"); err != nil {
			return err
		}
		if kd.slots, kd.slotCount, err = array(typ, "slot"); err != nil {
			return err
		}
		if kd.meta, err = shapeMember(k, typ, "meta"); err != nil {
			return err
		}
		if kd.pivotCount >= kd.slotCount || kd.slots+kd.slotCount*k.PointerSize() > s.nodeSize {
			return fmt.Errorf("%w: %s does not fit maple_node", ErrLinuxShape, typ)
		}
	}
	return nil
}

type AreaLosses struct {
	Counts     map[string]int
	First      string
	MapCount   int64
	MapKnown   bool
	Kept       int
	TreeNodes  int
	TreeHeight int
	FlagHeight int
}

func (l *AreaLosses) lose(rule, first string) {
	if l.Counts == nil {
		l.Counts = map[string]int{}
	}
	if l.Counts[rule] == 0 && l.First == "" {
		l.First = first
	}
	l.Counts[rule]++
}

func (l AreaLosses) Total() int {
	n := 0
	for _, c := range l.Counts {
		n += c
	}
	return n
}

func (l AreaLosses) Mismatch() bool { return l.MapKnown && int64(l.Kept) != l.MapCount }

func (l AreaLosses) Error() string {
	var parts []string
	for _, rule := range lossRules {
		if n := l.Counts[rule]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, rule))
		}
	}
	if l.Mismatch() {
		parts = append(parts, fmt.Sprintf("%d areas kept against map_count %d", l.Kept, l.MapCount))
	}
	msg := "memoryranges: memory areas: " + strings.Join(parts, ", ")
	if l.First != "" {
		msg += "; first: " + l.First
	}
	return msg
}

const (
	lossNode       = "tree nodes that do not read or have a bad type"
	lossRange      = "tree slots outside their node's range"
	lossChild      = "inner tree slots that are not nodes"
	lossInternal   = "leaf slots holding internal entries"
	lossRevisit    = "tree nodes or list areas reached twice"
	lossDead       = "dead tree nodes"
	lossParent     = "tree nodes that do not name their parent"
	lossDepth      = "tree branches deeper than MAPLE_HEIGHT_MAX"
	lossCap        = "walks that reached Limits.MaxListEntries"
	lossUnread     = "areas that do not read"
	lossBounds     = "areas with bad bounds"
	lossOwner      = "areas whose vm_mm is not the mm walked"
	lossStored     = "areas stored over a range not their own"
	lossOrder      = "list areas below the previous area's end"
	lossListUnread = "list links that do not read"
)

var lossRules = []string{lossNode, lossDead, lossParent, lossRange, lossChild, lossInternal, lossRevisit, lossDepth, lossCap,
	lossListUnread, lossUnread, lossBounds, lossOwner, lossStored, lossOrder}

type candidate struct {
	vma, first, last uint64
	ranged           bool
}

type areaWalk struct {
	lw     *LinuxWalker
	mm     uint64
	losses AreaLosses
	cands  []candidate
	seen   map[uint64]bool
}

func (lw *LinuxWalker) walkAreas(mm uint64) ([]LinuxVMA, AreaLosses) {
	w := &areaWalk{lw: lw, mm: mm, seen: map[uint64]bool{}}
	if lw.shape.tree {
		w.tree()
	} else {
		w.list()
	}
	areas := w.check()
	w.losses.Kept = len(areas)
	if lw.k.Has("mm_struct", "map_count") {
		if n, err := lw.k.Int(lw.k.Memory(), mm, "mm_struct", "map_count"); err == nil {
			w.losses.MapCount, w.losses.MapKnown = n, true
		}
	}
	return areas, w.losses
}

func (w *areaWalk) word(b []byte, at uint64) uint64 {
	if w.lw.k.PointerSize() == 4 {
		return uint64(binary.LittleEndian.Uint32(b[at:]))
	}
	return binary.LittleEndian.Uint64(b[at:])
}

func (w *areaWalk) tree() {
	k, s := w.lw.k, w.lw.shape
	at := w.mm + s.mmTree
	root, err := k.PointerAt(k.Memory(), at+s.treeRoot)
	if err != nil {
		w.losses.lose(lossNode, fmt.Sprintf("mm_mt at %#x: %v", k.Masked(at), err))
		return
	}
	if flags, err := k.Uint(k.Memory(), at, "maple_tree", "ma_flags"); err == nil {
		w.losses.FlagHeight = int(flags&0x7c) >> 2
	}
	switch {
	case root == 0:
	case isNode(root):
		w.node(root&^mapleRootFlag, 0, ^uint64(0)>>(64-8*k.PointerSize()), 1, 0, 0)
	case root&internalMask == internalTag:
		w.losses.lose(lossInternal, fmt.Sprintf("mm_mt root %#x", root))
	default:
		w.cands = append(w.cands, candidate{vma: root})
	}
}

func isNode(entry uint64) bool { return entry&internalMask == internalTag && entry > internalBelow }

// A child is encoded by mt_mk_node: the node, its type, and MAPLE_ENODE_NULL
// so that it is never zero (S39 T2).
func isChild(entry uint64) bool {
	return entry&mapleChildMark != 0 && entry&^(mapleNodeAlign-1) != 0 && (entry>>mapleTypeShift)&mapleTypeMask <= 3
}

func (w *areaWalk) node(enode, lo, hi uint64, depth int, parent, slot uint64) {
	k, s := w.lw.k, w.lw.shape
	addr := k.Canonical(enode &^ (mapleNodeAlign - 1))
	kind := (enode >> mapleTypeShift) & mapleTypeMask
	where := fmt.Sprintf("maple node at %#x", k.Masked(addr))
	if depth > mapleHeightMax {
		w.losses.lose(lossDepth, where)
		return
	}
	if w.seen[addr] {
		w.losses.lose(lossRevisit, where)
		return
	}
	if len(w.seen) >= w.lw.k.Context().Bounds().MaxListEntries {
		w.losses.lose(lossCap, where)
		return
	}
	w.seen[addr] = true
	if kind > 3 {
		w.losses.lose(lossNode, fmt.Sprintf("%s: type %d", where, kind))
		return
	}
	b, err := k.Memory().ReadAt(addr, s.nodeSize)
	if err != nil || uint64(len(b)) < s.nodeSize {
		w.losses.lose(lossNode, fmt.Sprintf("%s: %v", where, err))
		return
	}
	up := k.Canonical(w.word(b, 0) &^ (mapleNodeAlign - 1))
	if up == addr {
		w.losses.lose(lossDead, where)
		return
	}
	if parent != 0 && (up != parent || (w.word(b, 0)&mapleParentSlotMask)>>mapleTypeShift != slot) {
		w.losses.lose(lossParent, fmt.Sprintf("%s: parent %#x, want %#x slot %d", where, w.word(b, 0), parent, slot))
		return
	}
	w.losses.TreeNodes++
	w.losses.TreeHeight = max(w.losses.TreeHeight, depth)
	kd := s.kinds[kind]
	width := k.PointerSize()
	pivot := func(i uint64) uint64 { return w.word(b, kd.pivots+i*width) }
	end := w.dataEnd(kind, kd, b, pivot, lo, hi)
	first := lo
	for i := uint64(0); i <= end; i++ {
		last := hi
		if kind == 0 {
			last = lo + i
		} else if i < kd.pivotCount {
			if p := pivot(i); p != 0 || i == 0 {
				last = p
			}
		}
		if last < first || last > hi {
			w.losses.lose(lossRange, fmt.Sprintf("%s: slot %d over %#x-%#x in %#x-%#x", where, i, first, last, lo, hi))
			return
		}
		entry := w.word(b, kd.slots+i*width)
		switch {
		case kind < 2 && entry == 0:
		case kind < 2 && entry&internalMask == internalTag:
			w.losses.lose(lossInternal, fmt.Sprintf("%s: slot %d", where, i))
		case kind < 2:
			w.cands = append(w.cands, candidate{vma: k.Canonical(entry), first: first, last: last, ranged: true})
		case !isChild(entry):
			w.losses.lose(lossChild, fmt.Sprintf("%s: slot %d holds %#x", where, i, entry))
		default:
			w.node(entry, first, last, depth+1, addr, i)
		}
		if last == hi {
			break
		}
		first = last + 1
	}
}

// The data end follows ma_data_end (S39 T5).
func (w *areaWalk) dataEnd(kind uint64, kd mapleKind, b []byte, pivot func(uint64) uint64, lo, hi uint64) uint64 {
	if kind == 0 {
		return min(kd.slotCount-1, hi-lo)
	}
	meta := uint64(b[kd.meta+w.lw.shape.metaEnd])
	if kind == 3 {
		return min(meta, kd.slotCount-1)
	}
	last := kd.pivotCount - 1
	switch pivot(last) {
	case 0:
		return min(meta, kd.slotCount-1)
	case hi:
		return last
	}
	return kd.pivotCount
}

func (w *areaWalk) list() {
	k, s := w.lw.k, w.lw.shape
	vma, err := k.PointerAt(k.Memory(), w.mm+s.mmList)
	if err != nil {
		w.losses.lose(lossListUnread, fmt.Sprintf("mm_struct at %#x: mmap: %v", k.Masked(w.mm), err))
		return
	}
	limit := k.Context().Bounds().MaxListEntries
	for vma != 0 {
		if w.seen[vma] {
			w.losses.lose(lossRevisit, fmt.Sprintf("vm_area_struct at %#x", k.Masked(vma)))
			return
		}
		if len(w.seen) >= limit {
			w.losses.lose(lossCap, fmt.Sprintf("vm_area_struct at %#x", k.Masked(vma)))
			return
		}
		w.seen[vma] = true
		w.cands = append(w.cands, candidate{vma: vma})
		if vma, err = k.PointerAt(k.Memory(), vma+s.next); err != nil {
			w.losses.lose(lossListUnread, fmt.Sprintf("vm_area_struct at %#x: vm_next: %v", k.Masked(vma), err))
			return
		}
	}
}

func (w *areaWalk) check() []LinuxVMA {
	k := w.lw.k
	mem := k.Memory()
	var out []LinuxVMA
	var prevEnd uint64
	for _, c := range w.cands {
		where := fmt.Sprintf("vm_area_struct at %#x", k.Masked(c.vma))
		if !k.Readable(c.vma, w.lw.shape.vmaSize) {
			w.losses.lose(lossUnread, where)
			continue
		}
		start, err1 := k.Uint(mem, c.vma, "vm_area_struct", "vm_start")
		end, err2 := k.Uint(mem, c.vma, "vm_area_struct", "vm_end")
		file, err3 := k.Pointer(mem, c.vma, "vm_area_struct", "vm_file")
		if err := errors.Join(err1, err2, err3); err != nil {
			w.losses.lose(lossUnread, where)
			continue
		}
		if start >= end || start%areaAlign != 0 || end%areaAlign != 0 {
			w.losses.lose(lossBounds, fmt.Sprintf("%s: %#x-%#x", where, start, end))
			continue
		}
		if w.lw.shape.backLink {
			owner, err := k.Pointer(mem, c.vma, "vm_area_struct", "vm_mm")
			if err != nil || owner != w.mm {
				w.losses.lose(lossOwner, fmt.Sprintf("%s: vm_mm %#x", where, k.Masked(owner)))
				continue
			}
		}
		if c.ranged && (c.first != start || c.last != end-1) {
			w.losses.lose(lossStored, fmt.Sprintf("%s: %#x-%#x stored over %#x-%#x", where, start, end, c.first, c.last))
			continue
		}
		if !w.lw.shape.tree && start < prevEnd {
			w.losses.lose(lossOrder, fmt.Sprintf("%s: starts at %#x below %#x", where, start, prevEnd))
			continue
		}
		prevEnd = end
		out = append(out, LinuxVMA{Addr: c.vma, Start: start, End: end, File: file})
	}
	return out
}

func linuxProtection(flags uint64) string {
	perm := []byte("---")
	for i, c := range "rwx" {
		if flags&(1<<i) != 0 {
			perm[i] = byte(c)
		}
	}
	return string(perm)
}

func runLinux(ctx tools.Context) ([]Mapping, error) {
	lw, err := NewLinuxWalker(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", walkLabel(ctx), err)
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	out := make([]Mapping, 0, 256)
	unnamed, firstUnnamed := 0, ""
	for _, proc := range procs {
		rows, missed, err := lw.mappings(proc)
		out = append(out, rows...)
		if missed > 0 && firstUnnamed == "" {
			firstUnnamed = fmt.Sprintf("pid %d (%s)", proc.PID, proc.Name)
		}
		unnamed += missed
		if err == nil {
			continue
		}
		var losses AreaLosses
		if errors.As(err, &losses) && !ctx.StrictMode() {
			ctx.AddDiagnostic("%s: pid %d (%s): %v", walkLabel(ctx), proc.PID, proc.Name, err)
			continue
		}
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: pid %d (%s): %w", walkLabel(ctx), proc.PID, proc.Name, err)
		}
		ctx.AddDiagnostic("%s: pid %d (%s): memory areas not listed: %v", walkLabel(ctx), proc.PID, proc.Name, err)
	}
	if unnamed > 0 {
		ctx.AddDiagnostic("%s: %d memory areas whose name was not built, Path left empty; first in %s",
			walkLabel(ctx), unnamed, firstUnnamed)
	}
	return out, nil
}

func (lw *LinuxWalker) mappings(proc processlist.Process) ([]Mapping, int, error) {
	k := lw.k
	mm, err := k.Pointer(k.Memory(), proc.EPROCESS, "task_struct", "mm")
	if err != nil {
		return nil, 0, fmt.Errorf("task_struct at %#x: mm: %w", k.Masked(proc.EPROCESS), err)
	}
	if mm == 0 {
		return nil, 0, nil
	}
	if !k.Readable(mm, lw.shape.mmSize) {
		return nil, 0, fmt.Errorf("mm_struct at %#x: does not read", k.Masked(mm))
	}
	areas, losses := lw.walkAreas(mm)
	out := make([]Mapping, 0, len(areas))
	missed := 0
	for _, a := range areas {
		m, err := lw.mapping(proc, mm, a)
		if err != nil {
			return out, missed, err
		}
		if m.PathUnreadable {
			missed++
		}
		out = append(out, m)
	}
	if losses.Total() > 0 || losses.Mismatch() {
		return out, missed, losses
	}
	return out, missed, nil
}

func (lw *LinuxWalker) mapping(proc processlist.Process, mm uint64, a LinuxVMA) (Mapping, error) {
	k := lw.k
	mem := k.Memory()
	flags, err := k.Uint(mem, a.Addr, "vm_area_struct", "vm_flags")
	if err != nil {
		return Mapping{}, fmt.Errorf("vm_area_struct at %#x: %w", k.Masked(a.Addr), err)
	}
	m := Mapping{
		PID:        proc.PID,
		Process:    proc.Name,
		Start:      a.Start,
		End:        a.End - 1,
		Protection: linuxProtection(flags),
		Type:       "anonymous",
		VadAddress: a.Addr,
	}
	if a.File != 0 {
		m.Type = "file"
		pgoff, err := k.Uint(mem, a.Addr, "vm_area_struct", "vm_pgoff")
		if err != nil {
			return Mapping{}, fmt.Errorf("vm_area_struct at %#x: %w", k.Masked(a.Addr), err)
		}
		m.PageOffset = pgoff << areaPageShift
		m.Inode, m.Major, m.Minor = lw.fileIdentity(a.File)
	}
	name, named, err := lw.AreaName(proc.EPROCESS, mm, a)
	switch {
	case IsPathUnresolved(err):
		m.PathUnreadable = true
	case err != nil:
		return Mapping{}, fmt.Errorf("vm_area_struct at %#x: name: %w", k.Masked(a.Addr), err)
	case !named:
		m.PathUnreadable = true
	default:
		m.Path = name
	}
	return m, nil
}

// The device and inode are those the maps file prints (S39 F5).
func (lw *LinuxWalker) fileIdentity(file uint64) (ino uint64, major, minor uint32) {
	k := lw.k
	inode, ok, err := k.MappedFileInode(file)
	if err != nil || !ok {
		return 0, 0, 0
	}
	ino, err = k.Uint(k.Memory(), inode, "inode", "i_ino")
	if err != nil {
		return 0, 0, 0
	}
	sb, err := k.Pointer(k.Memory(), inode, "inode", "i_sb")
	if err != nil || sb == 0 {
		return ino, 0, 0
	}
	dev, err := k.Uint(k.Memory(), sb, "super_block", "s_dev")
	if err != nil {
		return ino, 0, 0
	}
	return ino, uint32(dev >> 20), uint32(dev & (1<<20 - 1))
}
