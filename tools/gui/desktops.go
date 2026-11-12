package gui

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

var (
	ErrOtherStation = errors.New("gui: desktop names another window station")
	ErrListRepeats  = errors.New("gui: list returns to an object already walked")
	ErrListLimit    = errors.New("gui: list is longer than MaxListEntries")
	ErrOtherDesktop = errors.New("gui: object names another desktop")
)

type Desktop struct {
	Address   uint64
	Physical  uint64
	OtherCopy uint64
	SessionID uint32

	Station             uint64
	StationName         string
	StationNameReadable bool

	Name         string
	NameReadable bool

	Info     uint64
	Next     uint64
	HeapBase uint64
	HeapSize uint32
}

type Thread struct {
	Address uint64
	EThread uint64
	TID     uint64
	Owner   Owner
}

type Owner struct {
	EPROCESS        uint64
	PID             uint64
	Process         string
	ProcessReadable bool
}

func (e *Env) desktopAt(r memory.MemoryReader, at uint64) (Desktop, error) {
	l := e.Layout.Desktop
	n := e.Layout.desktopExtent()
	b, err := r.ReadAt(at, n)
	if err != nil || uint64(len(b)) != n {
		return Desktop{}, fmt.Errorf("%w: desktop at 0x%x", ErrUnreadable, at)
	}
	d := Desktop{
		Address:  at,
		Info:     binary.LittleEndian.Uint64(b[l.Info:]),
		Next:     binary.LittleEndian.Uint64(b[l.Next:]),
		Station:  binary.LittleEndian.Uint64(b[l.Station:]),
		HeapBase: binary.LittleEndian.Uint64(b[l.HeapBase:]),
		HeapSize: binary.LittleEndian.Uint32(b[l.HeapSize:]),
	}
	if !e.objectPointer(d.Info) || !e.objectPointer(d.Next) || !e.objectPointer(d.Station) {
		return Desktop{}, fmt.Errorf("%w: desktop at 0x%x", ErrNotSystemSpace, at)
	}
	return d, nil
}

// The station's own address comes from its placement, or else from the
// first desktop whose station member leads to the same members as the
// scanned allocation (S57 4.4 step 2).
func (e *Env) Desktops(st *Station) ([]Desktop, error) {
	r := e.space(st.SessionID)
	var out []Desktop
	seen := map[uint64]bool{}
	limit := e.ctx.Bounds().MaxListEntries
	for at := st.Desktops; at != 0; {
		if seen[at] {
			return out, e.walkFailure("window station", st.Physical, ErrListRepeats)
		}
		if len(out) >= limit {
			return out, e.walkFailure("window station", st.Physical, ErrListLimit)
		}
		seen[at] = true
		if !e.k.isObject(r, at, typeDesktop) {
			return out, e.walkFailure("desktop", at, ErrWrongType)
		}
		d, err := e.desktopAt(r, at)
		if err != nil {
			return out, e.walkFailure("desktop", at, err)
		}
		if st.Address == 0 && e.sameStation(r, d.Station, *st) {
			st.Address = d.Station
		}
		if d.Station != st.Address {
			return out, e.walkFailure("desktop", at, ErrOtherStation)
		}
		d.SessionID = st.SessionID
		d.StationName, d.StationNameReadable = st.Name, st.NameReadable
		d.Name, d.NameReadable = e.k.objectName(r, r, at)
		out = append(out, d)
		at = d.Next
	}
	return out, nil
}

func (e *Env) sameStation(r memory.MemoryReader, at uint64, st Station) bool {
	if at == 0 || !e.k.isObject(r, at, typeWindowStation) {
		return false
	}
	got, err := e.stationAt(r, at)
	return err == nil && got.SessionID == st.SessionID && got.Next == st.Next && got.Desktops == st.Desktops
}

func (e *Env) walkFailure(object string, at uint64, err error) error {
	e.ctx.AddDiagnostic("%s: %s at 0x%x: list walk stopped: %v", e.tool, object, at, err)
	if e.ctx.StrictMode() {
		return fmt.Errorf("%s: %s at 0x%x: list walk stopped: %w", e.tool, object, at, err)
	}
	return nil
}

func (e *Env) ScanDesktops() ([]Desktop, error) {
	return scanObjects(e, DesktopFilter, e.Layout.desktopExtent(), e.decodeDesktop,
		func(d *Desktop, p scan.Placed[Desktop]) {
			d.Address = p.Place.BodyAddress()
			d.OtherCopy = p.OtherMappedBody()
		})
}

// A scanned desktop is kept only when its station member leads to a window
// station: the station gives the session whose space holds the rest.
func (e *Env) decodeDesktop(physical memory.MemoryReader, body uint64) (Desktop, bool) {
	d, err := e.desktopAt(physical, body)
	if err != nil || d.Station == 0 {
		return Desktop{}, false
	}
	name, ok := e.k.objectName(physical, e.ctx.Memory, body)
	if !ok || !ValidObjectName(name) {
		return Desktop{}, false
	}
	if !e.k.isObject(e.ctx.Memory, d.Station, typeWindowStation) {
		return Desktop{}, false
	}
	st, err := e.stationAt(e.ctx.Memory, d.Station)
	if err != nil {
		return Desktop{}, false
	}
	d.Physical, d.Name, d.NameReadable, d.SessionID = body, name, true, st.SessionID
	d.StationName, d.StationNameReadable = e.k.objectName(e.ctx.Memory, e.ctx.Memory, d.Station)
	return d, true
}

func (e *Env) Threads(d Desktop) ([]Thread, error) {
	if d.Address == 0 {
		return nil, nil
	}
	r := e.space(d.SessionID)
	entries, err := e.threadEntries(r, d)
	if err != nil {
		return nil, err
	}
	l := e.Layout.Thread
	var out []Thread
	others := 0
	for _, entry := range entries {
		info, ok := winkernel.Container(entry, l.Link)
		if !ok {
			continue
		}
		t, err := e.threadAt(r, d.SessionID, info)
		if err != nil {
			e.ctx.AddDiagnostic("%s: thread info at 0x%x: %v", e.tool, info, err)
			continue
		}
		if desk, err := readU64(r, info+l.Desktop); err != nil || desk != d.Address {
			others++
			continue
		}
		out = append(out, t)
	}
	if others > 0 {
		e.ctx.AddDiagnostic("%s: desktop at 0x%x: %d threads on its list are left out: %v", e.tool, d.Address,
			others, ErrOtherDesktop)
	}
	return out, nil
}

// Each entry is judged by what it holds (its desktop member and its thread
// object), so the walk does not stop at a back link that the capture's smear
// broke (S57 M5). A forward walk that breaks is completed from the head's
// back link.
func (e *Env) threadEntries(r memory.MemoryReader, d Desktop) ([]uint64, error) {
	native, err := winkernel.NativeListLayout(e.ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", e.tool, err)
	}
	head := d.Address + e.Layout.Desktop.Threads
	walk := func(link uint64, label string) (winkernel.ListWalk, error) {
		w := winkernel.ListWalker{Tool: e.tool, Memory: r, Limit: e.ctx.Bounds().MaxListEntries,
			Layout: winkernel.ListLayout{Width: native.Width, Flink: link},
			Strict: e.ctx.StrictMode(), Report: e.ctx.AddDiagnostic}
		return w.Walk(head, fmt.Sprintf("desktop at 0x%x: thread list %s", d.Address, label))
	}
	forward, err := walk(native.Flink, "forward")
	if err != nil || forward.Forward == nil || !native.HasBlink {
		return forward.Entries, err
	}
	back, err := walk(native.Blink, "backward")
	if err != nil {
		return nil, err
	}
	met := make(map[uint64]bool, len(forward.Entries))
	for _, entry := range forward.Entries {
		met[entry] = true
	}
	entries := forward.Entries
	for _, entry := range back.Entries {
		if !met[entry] {
			met[entry] = true
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func (e *Env) threadAt(r memory.MemoryReader, session uint32, info uint64) (Thread, error) {
	l := e.Layout.Thread
	ethread, err := readU64(r, info+l.EThread)
	if err != nil {
		return Thread{}, err
	}
	if !e.k.isObject(r, ethread, typeThread) {
		return Thread{}, fmt.Errorf("thread at 0x%x: %w", ethread, ErrWrongType)
	}
	tid, err := readU64(r, ethread+e.k.cid+e.k.uniqueThread)
	if err != nil {
		return Thread{}, err
	}
	t := Thread{Address: info, EThread: ethread, TID: tid}
	t.Owner = e.ownerOf(r, session, info)
	return t, nil
}

func (e *Env) ownerOf(r memory.MemoryReader, session uint32, info uint64) Owner {
	key := processKey{session, info}
	if o, ok := e.procs[key]; ok {
		return o
	}
	var o Owner
	if pinfo, err := readU64(r, info+e.Layout.Thread.ProcessInfo); err == nil {
		if ep, err := readU64(r, pinfo+e.Layout.ProcessInfoProcess); err == nil && e.k.isObject(r, ep, typeProcess) {
			o.EPROCESS = ep
			pid, perr := readU64(r, ep+e.k.pid)
			name, nerr := r.ReadAt(ep+e.k.imageName, e.k.imageNameSize)
			if perr == nil && nerr == nil {
				o.PID, o.Process, o.ProcessReadable = pid, imageName(name), true
			}
		}
	}
	e.procs[key] = o
	return o
}

func imageName(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
