package guitest

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
)

const (
	pageSize = 0x1000
	base     = uint64(0xffffa00000100000)

	Cookie = byte(0x5a)

	objectHeaderSize = 0x30
	nameInfoSize     = 0x20
	poolHeaderSize   = 0x10
	poolInPage       = 0x100
	scannedBodySize  = 0x200

	ethreadCid      = 0x40
	cidUniqueThread = 0x8
	eprocessPID     = 0x10
	eprocessImage   = 0x30
	objectTypeName  = 0x10
	objectTypeIndex = 0x28
	heapPages       = 4
)

var slots = map[string]byte{"WindowStation": 2, "Desktop": 3, "Thread": 4, "Process": 5, "File": 6}

type Spec struct {
	Layout   gui.Layout
	Stations []StationSpec
}

type StationSpec struct {
	Name     string
	Session  uint32
	Desktops []DesktopSpec
}

type DesktopSpec struct {
	Name    string
	Threads []ThreadSpec
	Window  *WindowSpec
}

type ThreadSpec struct {
	TID     uint64
	PID     uint64
	Process string
}

type WindowSpec struct {
	Text      string
	Procedure uint64
	// Index into the desktop's threads; -1 for none.
	Thread   int
	Children []WindowSpec
}

type Station struct {
	Address, Physical uint64
	Desktops          []Desktop
}

type Desktop struct {
	Address, Physical uint64
	Info, Heap        uint64
	Threads           []uint64
	Windows           []Window
}

type Window struct {
	Address, Shadow uint64
	Text            string
}

type Fixture struct {
	Ctx      tools.Context
	Layout   gui.Layout
	Memory   *testsupport.PagedMemory
	Kernel   *testsupport.AddressSpace
	Table    *symbols.Table
	Stations []Station

	next    uint64
	phys    map[uint64]uint64
	strings uint64
	strEnd  uint64
}

func Build(spec Spec) *Fixture {
	pm := testsupport.NewPagedMemory(32 << 20)
	f := &Fixture{Layout: spec.Layout, Memory: pm, Kernel: pm.NewAddressSpace(), next: base, phys: map[uint64]uint64{}}
	f.Table = table()
	f.writeKernelGlobals()
	var stations []Station
	for _, ss := range spec.Stations {
		stations = append(stations, f.station(ss))
	}
	for i := range stations {
		next := uint64(0)
		if i+1 < len(stations) {
			next = stations[i+1].Address
		}
		f.PutU64(stations[i].Address+f.Layout.Station.Next, next)
	}
	f.Stations = stations
	f.Ctx = tools.Context{
		Memory:  layers.NewProcessLayer(pm, f.Kernel.DTB, 64),
		Symbols: f.Table,
		Profile: profiles.WindowsX64Profile{},
		Options: map[string]any{
			tools.OptionPhysicalMemory: pm,
			tools.OptionKernelDTB:      f.Kernel.DTB,
			tools.OptionPagingMode:     layers.ModeX64.Name(),
		},
	}
	return f
}

func (f *Fixture) page() uint64 {
	va := f.next
	f.next += pageSize
	f.phys[va] = f.Kernel.MapPage(va)
	return va
}

func (f *Fixture) Physical(va uint64) uint64 {
	return f.phys[va&^(pageSize-1)] + va&(pageSize-1)
}

func (f *Fixture) PutU64(va, v uint64) { f.Memory.WriteU64(f.Physical(va), v) }
func (f *Fixture) PutU32(va uint64, v uint32) {
	f.Memory.WriteU32(f.Physical(va), v)
}
func (f *Fixture) PutBytes(va uint64, b []byte) { f.Memory.WriteAt(f.Physical(va), b) }

func (f *Fixture) text(s string) (uint64, uint16) {
	units := utf16.Encode([]rune(s))
	n := uint64(len(units) * 2)
	if f.strings == 0 || f.strings+n+2 > f.strEnd {
		f.strings = f.page()
		f.strEnd = f.strings + pageSize
	}
	va := f.strings
	b := make([]byte, n)
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	f.PutBytes(va, b)
	f.strings += (n + 2 + 7) &^ 7
	return va, uint16(n)
}

func (f *Fixture) writeKernelGlobals() {
	cookie := f.page()
	f.PutBytes(cookie, []byte{Cookie})
	f.Table.AddSymbol(symbols.Symbol{Name: "ObHeaderCookie", Address: cookie})

	masks := f.page()
	sizes := []byte{0x20, 0x20, 0x10, 0x20, 0x10, 0x10, 0x10, 0x4}
	table := make([]byte, 256)
	for m := range 256 {
		var sum byte
		for bit := range 8 {
			if m&(1<<bit) != 0 {
				sum += sizes[bit]
			}
		}
		table[m] = sum
	}
	f.PutBytes(masks, table)
	f.Table.AddSymbol(symbols.Symbol{Name: "ObpInfoMaskToOffset", Address: masks})

	types := f.page()
	for name, slot := range slots {
		t := f.page()
		buf, n := f.text(name)
		f.putUnicode(t+objectTypeName, buf, n)
		f.PutBytes(t+objectTypeIndex, []byte{slot})
		f.PutU64(types+uint64(slot)*8, t)
	}
	f.Table.AddSymbol(symbols.Symbol{Name: "ObTypeIndexTable", Address: types})
}

func (f *Fixture) putUnicode(va, buffer uint64, n uint16) {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint16(b[0:], n)
	binary.LittleEndian.PutUint16(b[2:], n+2)
	binary.LittleEndian.PutUint64(b[8:], buffer)
	f.PutBytes(va, b)
}

func EncodeTypeIndex(header uint64, slot byte) byte { return slot ^ Cookie ^ byte(header>>8) }

func (f *Fixture) TypeSlot(name string) byte { return slots[name] }

// A scanned object carries a pool header, a name and the object header the
// pool scan places from them.
func (f *Fixture) scanned(typeName, tag, name string) uint64 {
	page := f.page()
	pool := page + poolInPage
	hdr := make([]byte, poolHeaderSize)
	testsupport.WritePoolHeader(hdr, 0, tag, testsupport.BlocksFor(poolHeaderSize+nameInfoSize+objectHeaderSize+scannedBodySize),
		testsupport.PagedPoolType)
	f.PutBytes(pool, hdr)
	nameInfo := pool + poolHeaderSize
	buf, n := f.text(name)
	f.putUnicode(nameInfo+8, buf, n)
	header := nameInfo + nameInfoSize
	f.writeHeader(header, typeName, 0x2)
	return header + objectHeaderSize
}

func (f *Fixture) writeHeader(header uint64, typeName string, mask byte) {
	f.PutU64(header, 1)
	f.PutBytes(header+0x18, []byte{EncodeTypeIndex(header, slots[typeName])})
	f.PutBytes(header+0x1a, []byte{mask})
}

func (f *Fixture) plain(typeName string) uint64 {
	page := f.page()
	header := page + poolInPage
	f.writeHeader(header, typeName, 0)
	return header + objectHeaderSize
}

func (f *Fixture) station(ss StationSpec) Station {
	l := f.Layout
	st := Station{Address: f.scanned("WindowStation", gui.StationFilter.Tag, ss.Name)}
	st.Physical = f.Physical(st.Address)
	f.PutU32(st.Address+l.Station.SessionID, ss.Session)
	for _, ds := range ss.Desktops {
		st.Desktops = append(st.Desktops, f.desktop(st.Address, ds))
	}
	for i := range st.Desktops {
		next := uint64(0)
		if i+1 < len(st.Desktops) {
			next = st.Desktops[i+1].Address
		}
		f.PutU64(st.Desktops[i].Address+l.Desktop.Next, next)
	}
	if len(st.Desktops) > 0 {
		f.PutU64(st.Address+l.Station.Desktops, st.Desktops[0].Address)
	}
	return st
}

func (f *Fixture) desktop(station uint64, ds DesktopSpec) Desktop {
	l := f.Layout
	d := Desktop{Address: f.scanned("Desktop", gui.DesktopFilter.Tag, ds.Name)}
	d.Physical = f.Physical(d.Address)
	d.Info = f.page()
	d.Heap = f.page()
	for range heapPages - 1 {
		f.page()
	}
	f.PutU64(d.Address+l.Desktop.Info, d.Info)
	f.PutU64(d.Address+l.Desktop.Station, station)
	f.PutU64(d.Address+l.Desktop.HeapBase, d.Heap)
	f.PutU32(d.Address+l.Desktop.HeapSize, heapPages*pageSize)

	head := d.Address + l.Desktop.Threads
	prev := head
	for _, ts := range ds.Threads {
		info := f.thread(d.Address, ts)
		link := info + l.Thread.Link
		f.PutU64(prev, link)
		f.PutU64(link+8, prev)
		prev = link
		d.Threads = append(d.Threads, info)
	}
	f.PutU64(prev, head)
	f.PutU64(head+8, prev)

	if ds.Window != nil {
		heap := &heapCursor{at: d.Heap + 0x100, end: d.Heap + heapPages*pageSize}
		root := f.window(&d, heap, *ds.Window, 0)
		f.PutU64(d.Info+l.DesktopInfoWindow, root)
	}
	return d
}

func (f *Fixture) thread(desktop uint64, ts ThreadSpec) uint64 {
	l := f.Layout.Thread
	info := f.page()
	ethread := f.plain("Thread")
	eprocess := f.plain("Process")
	pinfo := f.page()
	f.PutU64(ethread+ethreadCid+cidUniqueThread, ts.TID)
	f.PutU64(eprocess+eprocessPID, ts.PID)
	f.PutBytes(eprocess+eprocessImage, append([]byte(ts.Process), 0))
	f.PutU64(pinfo+f.Layout.ProcessInfoProcess, eprocess)
	f.PutU64(info+l.EThread, ethread)
	f.PutU64(info+l.ProcessInfo, pinfo)
	f.PutU64(info+l.Desktop, desktop)
	return info
}

type heapCursor struct{ at, end uint64 }

func (h *heapCursor) take(n uint64) uint64 {
	va := h.at
	h.at += (n + 0xf) &^ 0xf
	if h.at > h.end {
		panic("guitest: desktop heap full")
	}
	return va
}

func (f *Fixture) window(d *Desktop, heap *heapCursor, ws WindowSpec, parent uint64) uint64 {
	l := f.Layout.Window
	w := f.page()
	f.PutU64(w+l.Self, w)
	f.PutU64(w+l.Desktop, d.Address)
	f.PutU64(w+l.Parent, parent)
	if ws.Thread >= 0 && ws.Thread < len(d.Threads) {
		f.PutU64(w+l.Thread, d.Threads[ws.Thread])
	}
	shadow := uint64(0)
	if l.HasShadow {
		shadow = heap.take(0x200)
		f.PutU64(w+l.Shadow, shadow)
		f.PutU64(w+l.ShadowOffset, shadow-d.Heap)
	}
	at := func(p gui.Place) uint64 {
		if p == gui.InShadow {
			return shadow
		}
		return w
	}
	if ws.Text != "" {
		units := utf16.Encode([]rune(ws.Text))
		n := uint64(len(units) * 2)
		buf := heap.take(n + 2)
		b := make([]byte, n)
		for i, u := range units {
			binary.LittleEndian.PutUint16(b[2*i:], u)
		}
		f.PutBytes(buf, b)
		f.PutU32(at(l.TextLength)+l.TextLengthAt, uint32(n))
		f.PutU32(at(l.TextMaximum)+l.TextMaximumAt, uint32(n+2))
		f.PutU64(w+l.TextBuffer, buf)
	}
	f.PutU64(at(l.ProcedureIn)+l.Procedure, ws.Procedure)
	d.Windows = append(d.Windows, Window{Address: w, Shadow: shadow, Text: ws.Text})
	var prev uint64
	for _, c := range ws.Children {
		cw := f.window(d, heap, c, w)
		if prev == 0 {
			f.PutU64(w+l.Child, cw)
		} else {
			f.PutU64(prev+l.Next, cw)
		}
		prev = cw
	}
	return w
}

func field(name string, off uint64, typ string) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: typ}}
}

func table() *symbols.Table {
	t := symbols.NewTable("guitest", 8)
	t.AddStruct(symbols.StructType{Name: "_POOL_HEADER", Size: poolHeaderSize, Fields: []symbols.Field{
		field("PoolIndex", 1, "unsigned char"),
		field("BlockSize", 2, "unsigned char"),
		field("PoolType", 3, "unsigned char"),
		field("PoolTag", 4, "unsigned long"),
	}})
	t.AddStruct(symbols.StructType{Name: "_OBJECT_HEADER", Size: 0x38, Fields: []symbols.Field{
		field("PointerCount", 0, "long long"),
		field("HandleCount", 8, "long long"),
		field("TypeIndex", 0x18, "unsigned char"),
		field("InfoMask", 0x1a, "unsigned char"),
		field("Body", objectHeaderSize, "_QUAD"),
	}})
	t.AddStruct(symbols.StructType{Name: "_OBJECT_HEADER_NAME_INFO", Size: nameInfoSize, Fields: []symbols.Field{
		{Name: "Directory", Offset: 0, Type: symbols.TypeRef{Name: "_OBJECT_DIRECTORY", IsPointer: true}},
		field("Name", 8, "_UNICODE_STRING"),
	}})
	t.AddStruct(symbols.StructType{Name: "_UNICODE_STRING", Size: 16, Fields: []symbols.Field{
		field("Length", 0, "unsigned short"),
		field("MaximumLength", 2, "unsigned short"),
		{Name: "Buffer", Offset: 8, Type: symbols.TypeRef{Name: "wchar", IsPointer: true}},
	}})
	t.AddStruct(symbols.StructType{Name: "_OBJECT_TYPE", Size: 0xd8, Fields: []symbols.Field{
		field("Name", objectTypeName, "_UNICODE_STRING"),
		field("Index", objectTypeIndex, "unsigned char"),
	}})
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 16, Fields: []symbols.Field{
		{Name: "Flink", Offset: 0, Type: symbols.TypeRef{Name: "_LIST_ENTRY", IsPointer: true}},
		{Name: "Blink", Offset: 8, Type: symbols.TypeRef{Name: "_LIST_ENTRY", IsPointer: true}},
	}})
	t.AddStruct(symbols.StructType{Name: "_CLIENT_ID", Size: 16, Fields: []symbols.Field{
		{Name: "UniqueProcess", Offset: 0, Type: symbols.TypeRef{Name: "void", IsPointer: true}},
		{Name: "UniqueThread", Offset: cidUniqueThread, Type: symbols.TypeRef{Name: "void", IsPointer: true}},
	}})
	t.AddStruct(symbols.StructType{Name: "_ETHREAD", Size: 0x100, Fields: []symbols.Field{
		field("Cid", ethreadCid, "_CLIENT_ID"),
	}})
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x100, Fields: []symbols.Field{
		{Name: "UniqueProcessId", Offset: eprocessPID, Type: symbols.TypeRef{Name: "void", IsPointer: true}},
		{Name: "ImageFileName", Offset: eprocessImage, Type: symbols.TypeRef{Name: "unsigned char", IsArray: true, ArrayLength: 15}},
	}})
	return t
}

// Two sessions: an interactive station with two desktops, one holding two
// threads and a window tree three levels deep, and a service station.
func Typical(l gui.Layout) Spec {
	threads := []ThreadSpec{
		{TID: 0x104, PID: 0x40, Process: "explorer.exe"},
		{TID: 0x208, PID: 0x80, Process: "notepad.exe"},
	}
	tree := &WindowSpec{Thread: 0, Procedure: 0xfffff80000123450, Children: []WindowSpec{
		{Text: "Program Manager", Thread: 0, Procedure: 0x7ff612340000, Children: []WindowSpec{
			{Text: "SHELLDLL_DefView", Thread: 0, Procedure: 0x7ff612341000},
		}},
		{Text: "Untitled - Notepad", Thread: 1, Procedure: 0x7ff698760000},
		{Thread: -1, Procedure: 0x7ff698761000},
	}}
	return Spec{Layout: l, Stations: []StationSpec{
		{Name: "WinSta0", Session: 1, Desktops: []DesktopSpec{
			{Name: "Default", Threads: threads, Window: tree},
			{Name: "Winlogon"},
		}},
		{Name: "Service-0x0-3e7$", Session: 0, Desktops: []DesktopSpec{{Name: "Default"}}},
	}}
}
