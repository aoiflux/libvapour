package gui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/symbols/autoload"
)

var ErrUnsupportedVersion = errors.New("gui: no measured layout for this win32kbase.sys")

type StationMembers struct {
	SessionID, Next, Desktops uint64
}

type DesktopMembers struct {
	Info, Next, Station, Threads uint64
	HeapBase, HeapSize           uint64
}

type ThreadMembers struct {
	EThread, ProcessInfo, Desktop, Link uint64
}

// Where a member lives: in the kernel's window object, or in the copy of it
// that the window object points to inside the desktop heap.
type Place int

const (
	InWindow Place = iota
	InShadow
)

type WindowMembers struct {
	Thread, Desktop, Self uint64
	Next, Parent, Child   uint64

	HasShadow    bool
	Shadow       uint64
	ShadowOffset uint64

	TextLength, TextMaximum Place
	TextLengthAt            uint64
	TextMaximumAt           uint64
	TextBuffer              uint64

	ProcedureIn Place
	Procedure   uint64
}

type Layout struct {
	Name  string
	Build uint32
	// The win32kbase.pdb record of the capture the layout was measured on.
	GUID string
	Age  uint32

	Station            StationMembers
	Desktop            DesktopMembers
	DesktopInfoWindow  uint64
	Thread             ThreadMembers
	ProcessInfoProcess uint64
	Window             WindowMembers
}

func Layouts() []Layout { return append([]Layout(nil), measured...) }

func LayoutFor(fp autoload.Fingerprint) (Layout, error) {
	for _, l := range measured {
		if strings.EqualFold(l.GUID, fp.GUID) && l.Age == fp.Age {
			return l, nil
		}
	}
	return Layout{}, fmt.Errorf("%w: %s %s-%d", ErrUnsupportedVersion, fp.PDBName, fp.GUID, fp.Age)
}

const (
	pointerSize   = 8
	listEntrySize = 16
	ulongSize     = 4
)

func (l Layout) stationExtent() uint64 {
	s := l.Station
	return max(s.SessionID+ulongSize, s.Next+pointerSize, s.Desktops+pointerSize)
}

func (l Layout) desktopExtent() uint64 {
	d := l.Desktop
	return max(d.Info+pointerSize, d.Next+pointerSize, d.Station+pointerSize, d.Threads+listEntrySize,
		d.HeapBase+pointerSize, d.HeapSize+ulongSize)
}
