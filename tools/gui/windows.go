package gui

import (
	"errors"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/util"
)

var (
	ErrNotSelf       = errors.New("gui: window does not name itself")
	ErrOtherParent   = errors.New("gui: window names another parent")
	ErrOutsideHeap   = errors.New("gui: pointer is outside the desktop heap")
	ErrTextShape     = errors.New("gui: window text descriptor is not a valid counted string")
	ErrTreeDepth     = errors.New("gui: window tree is deeper than MaxRecursionDepth")
	ErrTooManyWindow = errors.New("gui: desktop holds more windows than MaxListEntries")
)

type Window struct {
	Address uint64
	Parent  uint64
	Depth   int
	Thread  Thread

	Text         string
	TextReadable bool

	Procedure         uint64
	ProcedureReadable bool
}

type WindowWalk struct {
	Windows  []Window
	Rejected map[string]int
}

func (w *WindowWalk) reject(err error) {
	if w.Rejected == nil {
		w.Rejected = map[string]int{}
	}
	w.Rejected[err.Error()]++
}

// Depth first from the desktop window: each window's first child, then that
// child's siblings in order (S57 4.7).
func (e *Env) Windows(d Desktop) (WindowWalk, error) {
	var walk WindowWalk
	if d.Address == 0 || d.Info == 0 {
		return walk, nil
	}
	r := e.space(d.SessionID)
	root, err := readU64(r, d.Info+e.Layout.DesktopInfoWindow)
	if err != nil {
		return walk, e.walkFailure("desktop", d.Address, err)
	}
	if root == 0 {
		return walk, nil
	}
	seen := map[uint64]bool{}
	_, err = e.visit(r, d, root, 0, 0, seen, &walk)
	return walk, err
}

func (e *Env) visit(r memory.MemoryReader, d Desktop, at, parent uint64, depth int, seen map[uint64]bool,
	walk *WindowWalk) (bool, error) {
	b := e.ctx.Bounds()
	if depth > b.MaxRecursionDepth {
		return false, e.walkFailure("window", at, ErrTreeDepth)
	}
	if seen[at] {
		return false, e.walkFailure("window", at, ErrListRepeats)
	}
	if len(walk.Windows) >= b.MaxListEntries {
		return false, e.walkFailure("window", at, ErrTooManyWindow)
	}
	seen[at] = true
	w, child, err := e.windowAt(r, d, at, parent)
	if err != nil {
		walk.reject(err)
		return false, nil
	}
	w.Depth = depth
	walk.Windows = append(walk.Windows, w)
	for c := child; c != 0; {
		accepted, err := e.visit(r, d, c, at, depth+1, seen, walk)
		if err != nil || !accepted {
			return true, err
		}
		next, err := readU64(r, c+e.Layout.Window.Next)
		if err != nil {
			walk.reject(err)
			return true, nil
		}
		if !e.objectPointer(next) {
			walk.reject(ErrNotSystemSpace)
			return true, nil
		}
		c = next
	}
	return true, nil
}

func (e *Env) windowAt(r memory.MemoryReader, d Desktop, at, parent uint64) (Window, uint64, error) {
	l := e.Layout.Window
	self, err := readU64(r, at+l.Self)
	if err != nil {
		return Window{}, 0, err
	}
	if self != at {
		return Window{}, 0, ErrNotSelf
	}
	desk, err := readU64(r, at+l.Desktop)
	if err != nil {
		return Window{}, 0, err
	}
	if desk != d.Address {
		return Window{}, 0, ErrOtherDesktop
	}
	if parent != 0 {
		if p, err := readU64(r, at+l.Parent); err != nil || p != parent {
			return Window{}, 0, ErrOtherParent
		}
	}
	child, err := readU64(r, at+l.Child)
	if err != nil {
		return Window{}, 0, err
	}
	if !e.objectPointer(child) {
		return Window{}, 0, ErrNotSystemSpace
	}
	w := Window{Address: at, Parent: parent}
	if info, err := readU64(r, at+l.Thread); err == nil && info != 0 {
		if t, err := e.threadAt(r, d.SessionID, info); err == nil {
			w.Thread = t
		} else {
			w.Thread = Thread{Address: info}
		}
	}
	shadow, shadowErr := e.shadowOf(r, d, at)
	w.Text, w.TextReadable = e.windowText(r, d, at, shadow, shadowErr)
	w.Procedure, w.ProcedureReadable = e.member(r, at, shadow, shadowErr, l.ProcedureIn, l.Procedure)
	return w, child, nil
}

// The shadow is the window's second copy inside the desktop heap; the
// window also keeps its offset from the heap's base (S57 M7).
func (e *Env) shadowOf(r memory.MemoryReader, d Desktop, at uint64) (uint64, error) {
	l := e.Layout.Window
	if !l.HasShadow {
		return 0, nil
	}
	shadow, err := readU64(r, at+l.Shadow)
	if err != nil {
		return 0, err
	}
	offset, err := readU64(r, at+l.ShadowOffset)
	if err != nil {
		return 0, err
	}
	if !inHeap(d, shadow, 1) || shadow-d.HeapBase != offset {
		return 0, ErrOutsideHeap
	}
	return shadow, nil
}

func inHeap(d Desktop, at, n uint64) bool {
	end := d.HeapBase + uint64(d.HeapSize)
	return at >= d.HeapBase && n <= uint64(d.HeapSize) && at <= end-n
}

func (e *Env) member(r memory.MemoryReader, at, shadow uint64, shadowErr error, in Place, off uint64) (uint64, bool) {
	base := at
	if in == InShadow {
		if shadowErr != nil {
			return 0, false
		}
		base = shadow
	}
	v, err := readU64(r, base+off)
	return v, err == nil
}

func (e *Env) member32(r memory.MemoryReader, at, shadow uint64, shadowErr error, in Place, off uint64) (uint32, bool) {
	base := at
	if in == InShadow {
		if shadowErr != nil {
			return 0, false
		}
		base = shadow
	}
	v, err := readU32(r, base+off)
	return v, err == nil
}

// The text descriptor is a counted UTF-16 string. win32kfull accepts one only
// with even sizes, a length below the maximum, and the whole maximum inside
// the desktop heap (S57 D4).
func (e *Env) windowText(r memory.MemoryReader, d Desktop, at, shadow uint64, shadowErr error) (string, bool) {
	l := e.Layout.Window
	length, ok1 := e.member32(r, at, shadow, shadowErr, l.TextLength, l.TextLengthAt)
	maximum, ok2 := e.member32(r, at, shadow, shadowErr, l.TextMaximum, l.TextMaximumAt)
	buffer, err := readU64(r, at+l.TextBuffer)
	if !ok1 || !ok2 || err != nil {
		return "", false
	}
	text, err := e.readText(r, d, length, maximum&textMaximumMask, buffer)
	return text, err == nil
}

const textMaximumMask = 0x7fffffff

func (e *Env) readText(r memory.MemoryReader, d Desktop, length, maximum uint32, buffer uint64) (string, error) {
	if buffer == 0 || length == 0 {
		return "", nil
	}
	if length%2 != 0 || maximum%2 != 0 || length >= maximum {
		return "", ErrTextShape
	}
	if !inHeap(d, buffer, uint64(maximum)) {
		return "", ErrOutsideHeap
	}
	if int64(length) > e.ctx.Bounds().MaxTextBytes {
		return "", ErrTextShape
	}
	b, err := r.ReadAt(buffer, uint64(length))
	if err != nil || len(b) != int(length) {
		return "", ErrUnreadable
	}
	return util.DecodeUTF16LE(b), nil
}
