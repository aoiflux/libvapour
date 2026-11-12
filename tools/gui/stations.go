package gui

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
)

var ErrNoPhysicalMemory = errors.New("gui: no physical memory to scan")

// Each tag is the Key of its _OBJECT_TYPE (S31 M1). Freed allocations stay
// in: the scan exists to find what the lists no longer hold.
var (
	StationFilter = scan.PoolFilter{Tag: "Wind", PageType: scan.PagedPool | scan.NonPagedPool | scan.FreePool,
		ObjectType: typeWindowStation}
	DesktopFilter = scan.PoolFilter{Tag: "Desk", PageType: scan.PagedPool | scan.NonPagedPool | scan.FreePool,
		ObjectType: typeDesktop}
)

type Station struct {
	Physical  uint64
	Address   uint64
	OtherCopy uint64

	Name         string
	NameReadable bool
	SessionID    uint32
	Next         uint64
	Desktops     uint64
}

func (e *Env) ScanStations() ([]Station, error) {
	return scanObjects(e, StationFilter, e.Layout.stationExtent(), e.decodeStation,
		func(s *Station, p scan.Placed[Station]) {
			s.Address = p.Place.BodyAddress()
			s.OtherCopy = p.OtherMappedBody()
		})
}

func scanObjects[T any](e *Env, filter scan.PoolFilter, extent uint64,
	decode func(physical memory.MemoryReader, body uint64) (T, bool), place func(*T, scan.Placed[T])) ([]T, error) {
	physical := e.ctx.PhysicalMemory()
	if physical == nil {
		return nil, fmt.Errorf("%s: %w", e.tool, ErrNoPhysicalMemory)
	}
	objects, err := scan.ResolveObjectLayout(e.ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", e.tool, err)
	}
	filter.MinSize = objects.PoolHeaderSize + objects.BodyOffset + extent
	layout, identity, err := e.ctx.ExecutiveScan(e.tool, filter, scan.TypeTag{})
	if err != nil {
		return nil, err
	}
	placed, stats, err := scan.FindExecutiveObjectsPlaced(physical, filter, layout, identity,
		func(body uint64) (T, bool) { return decode(physical, body) }, e.ctx.Bounds().Workers)
	if err != nil {
		return nil, fmt.Errorf("%s: pool tag %q scan: %w", e.tool, filter.Tag, err)
	}
	out := make([]T, len(placed))
	for i, p := range placed {
		out[i] = p.Row
		place(&out[i], p)
	}
	e.ctx.AddDiagnostic("%s: pool tag %q: %d objects from %d tag hits (%s)", e.tool, filter.Tag, len(out),
		stats.TagHits, stats.Describe())
	return out, nil
}

func (e *Env) decodeStation(physical memory.MemoryReader, body uint64) (Station, bool) {
	s, err := e.stationAt(physical, body)
	if err != nil {
		return Station{}, false
	}
	name, ok := e.k.objectName(physical, e.ctx.Memory, body)
	if !ok || !ValidObjectName(name) {
		return Station{}, false
	}
	s.Physical, s.Name, s.NameReadable = body, name, true
	return s, true
}

func (e *Env) stationAt(r memory.MemoryReader, at uint64) (Station, error) {
	l := e.Layout.Station
	b, err := r.ReadAt(at, e.Layout.stationExtent())
	if err != nil || uint64(len(b)) != e.Layout.stationExtent() {
		return Station{}, fmt.Errorf("%w: window station at 0x%x", ErrUnreadable, at)
	}
	s := Station{
		SessionID: binary.LittleEndian.Uint32(b[l.SessionID:]),
		Next:      binary.LittleEndian.Uint64(b[l.Next:]),
		Desktops:  binary.LittleEndian.Uint64(b[l.Desktops:]),
	}
	if !e.objectPointer(s.Next) || !e.objectPointer(s.Desktops) {
		return Station{}, fmt.Errorf("%w: window station at 0x%x", ErrNotSystemSpace, at)
	}
	return s, nil
}

var ErrNotSystemSpace = errors.New("gui: pointer is neither null nor in system space")

// Window stations, desktops, thread and window objects all live in system
// space (S57 F7, M4).
func (e *Env) objectPointer(p uint64) bool {
	return p == 0 || p >= e.system && p != ^uint64(0)
}

// Station and desktop names may not contain a backslash (S57 F3, F4); a
// control character never comes from a name the API accepted.
func ValidObjectName(name string) bool {
	if name == "" || strings.ContainsRune(name, '\\') {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}
