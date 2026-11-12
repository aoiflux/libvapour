package callbacklist

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

type sparse map[uint64][]byte

func (m sparse) page(at uint64) []byte {
	p := m[at&^0xFFF]
	if p == nil {
		p = make([]byte, 0x1000)
		m[at&^0xFFF] = p
	}
	return p
}

func (m sparse) write(at uint64, b []byte) {
	for i, v := range b {
		m.page(at + uint64(i))[(at+uint64(i))&0xFFF] = v
	}
}

func (m sparse) u64(at, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	m.write(at, b[:])
}

func (m sparse) u32(at uint64, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	m.write(at, b[:])
}

func (m sparse) u16(at uint64, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	m.write(at, b[:])
}

func (m sparse) ReadAt(at, size uint64) ([]byte, error) {
	out := make([]byte, 0, size)
	for uint64(len(out)) < size {
		cur := at + uint64(len(out))
		p, ok := m[cur&^0xFFF]
		if !ok {
			if len(out) == 0 {
				return nil, fmt.Errorf("unmapped 0x%x", cur)
			}
			return out, nil
		}
		n := min(0x1000-cur&0xFFF, size-uint64(len(out)))
		out = append(out, p[cur&0xFFF:cur&0xFFF+n]...)
	}
	return out, nil
}

func (m sparse) Size() uint64 { return 0 }

func (m sparse) unicode(at, buffer uint64, s string) {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	m.u16(at, uint16(len(b)))
	m.u16(at+2, uint16(len(b)))
	m.u64(at+8, buffer)
	m.write(buffer, b)
}

func (m sparse) link(head uint64, entries ...uint64) {
	all := append([]uint64{head}, entries...)
	for i, at := range all {
		m.u64(at, all[(i+1)%len(all)])
		m.u64(at+8, all[(i+len(all)-1)%len(all)])
	}
}

const (
	kernelBase  = uint64(0xFFFFF80000000000)
	driverBase  = uint64(0xFFFFF80010000000)
	pool        = uint64(0xFFFF900000000000)
	buildGlobal = kernelBase + 0x9000
	sharedData  = uint64(0xFFFFF78000000000)
)

var fixtureSymbols = map[string]uint64{
	"NtBuildNumber":                        buildGlobal,
	"PspCreateProcessNotifyRoutine":        kernelBase + 0x10000,
	"PspCreateThreadNotifyRoutine":         kernelBase + 0x10200,
	"PspLoadImageNotifyRoutine":            kernelBase + 0x10400,
	"CallbackListHead":                     kernelBase + 0x11000,
	"KeBugCheckCallbackListHead":           kernelBase + 0x11010,
	"KeBugCheckReasonCallbackListHead":     kernelBase + 0x11020,
	"IopNotifyShutdownQueueHead":           kernelBase + 0x11030,
	"IopNotifyLastChanceShutdownQueueHead": kernelBase + 0x11040,
	"IopFsNotifyChangeQueueHead":           kernelBase + 0x11050,
	"PopRegisteredPowerSettingCallbacks":   kernelBase + 0x11060,
	"PsProcessType":                        kernelBase + 0x11100,
	"PsThreadType":                         kernelBase + 0x11108,
	"ExDesktopObjectType":                  kernelBase + 0x11110,
}

func field(name string, off uint64) symbols.Field { return symbols.Field{Name: name, Offset: off} }

func fixtureTable() *symbols.Table {
	t := symbols.NewTable("s27", 8)
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 16, Fields: []symbols.Field{field("Flink", 0), field("Blink", 8)}})
	t.AddStruct(symbols.StructType{Name: "_KUSER_SHARED_DATA", Size: 0x800, Fields: []symbols.Field{
		field("NtBuildNumber", 0x260), field("NtMajorVersion", 0x26c), field("NtMinorVersion", 0x270)}})
	t.AddStruct(symbols.StructType{Name: "_EX_FAST_REF", Size: 8, Fields: []symbols.Field{
		field("Object", 0), {Name: "RefCnt", Offset: 0, Type: symbols.TypeRef{Name: "unsigned long long", BitLength: 4}},
		field("Value", 0)}})
	t.AddStruct(symbols.StructType{Name: "_UNICODE_STRING", Size: 16, Fields: []symbols.Field{
		field("Length", 0), field("MaximumLength", 2), field("Buffer", 8)}})
	t.AddStruct(symbols.StructType{Name: "_DEVICE_OBJECT", Size: 0x150, Fields: []symbols.Field{field("DriverObject", 8)}})
	t.AddStruct(symbols.StructType{Name: "_DRIVER_OBJECT", Size: 0x150, Fields: []symbols.Field{
		field("DriverName", 0x38), field("MajorFunction", 0x70)}})
	t.AddStruct(symbols.StructType{Name: "_OBJECT_TYPE", Size: 0xe0, Fields: []symbols.Field{
		field("Name", 0x10), field("CallbackList", 0xc8)}})
	for name, at := range fixtureSymbols {
		t.AddSymbol(symbols.Symbol{Name: name, Address: at})
	}
	return t
}

type fixture struct {
	mem   sparse
	table *symbols.Table
	mods  []modulelist.Module
	diags []string
}

func (f *fixture) ctx(strict bool) tools.Context {
	options := map[string]any{"diagnostics": &f.diags}
	if strict {
		options["strict"] = true
	}
	return tools.Context{Memory: f.mem, Symbols: f.table, Profile: profiles.WindowsX64Profile{}, Options: options,
		Limits: limits.Limits{}}
}

func (f *fixture) setBuild(build uint32) {
	f.mem.u32(buildGlobal, 0xF0000000|build)
	f.mem.u32(sharedData+0x260, build)
	f.mem.u32(sharedData+0x26c, 10)
	f.mem.u32(sharedData+0x270, 0)
}

const (
	driverObject = pool + 0x40000
	deviceObject = pool + 0x41000
	processType  = pool + 0x42000
	threadType   = pool + 0x43000
	desktopType  = pool + 0x44000
)

func routine(i uint64) uint64 { return driverBase + 0x1000 + i*0x10 }

// One registration of every kind, laid out as M1 to M7 measured them.
func newFixture() *fixture {
	f := &fixture{mem: sparse{}, table: fixtureTable()}
	f.mods = []modulelist.Module{
		{Base: kernelBase, Size: 0x100000, Name: "ntoskrnl.exe"},
		{Base: driverBase, Size: 0x100000, Name: "probe.sys"},
	}
	f.setBuild(26100)
	for i := uint64(0); i < 0x600; i += 8 {
		f.mem.u64(fixtureSymbols["PspCreateProcessNotifyRoutine"]+i, 0)
	}
	block := pool + 0x1000
	f.mem.u64(block+8, routine(1))
	f.mem.u64(fixtureSymbols["PspCreateProcessNotifyRoutine"]+3*8, block|0xF)
	f.mem.u64(block+0x108, routine(2))
	f.mem.u64(fixtureSymbols["PspCreateThreadNotifyRoutine"], (block+0x100)|0x7)
	f.mem.u64(block+0x208, routine(3))
	f.mem.u64(fixtureSymbols["PspLoadImageNotifyRoutine"]+63*8, block+0x200)

	reg := pool + 0x2000
	f.mem.link(fixtureSymbols["CallbackListHead"], reg)
	f.mem.u64(reg+0x28, routine(4))
	f.mem.unicode(reg+0x30, reg+0x100, "321000")

	bug := pool + 0x3000
	f.mem.link(fixtureSymbols["KeBugCheckCallbackListHead"], bug)
	f.mem.u64(bug+0x10, routine(5))
	f.mem.u64(bug+0x28, bug+0x100)
	f.mem.write(bug+0x100, []byte("probe\x00"))

	reason := pool + 0x4000
	f.mem.link(fixtureSymbols["KeBugCheckReasonCallbackListHead"], reason)
	f.mem.u64(reason+0x10, routine(6))
	f.mem.u64(reason+0x18, reason+0x100)
	f.mem.write(reason+0x100, []byte("probedump\x00"))
	f.mem.u32(reason+0x28, 2)

	f.mem.u16(driverObject, ioTypeDriver)
	f.mem.unicode(driverObject+0x38, driverObject+0x200, `\Driver\probe`)
	f.mem.u64(driverObject+0x70+irpMjShutdown*8, routine(7))
	f.mem.u16(deviceObject, ioTypeDevice)
	f.mem.u64(deviceObject+8, driverObject)
	shutdown := pool + 0x5000
	f.mem.link(fixtureSymbols["IopNotifyShutdownQueueHead"], shutdown)
	f.mem.u64(shutdown+0x10, deviceObject)
	last := pool + 0x5100
	f.mem.link(fixtureSymbols["IopNotifyLastChanceShutdownQueueHead"], last)
	f.mem.u64(last+0x10, deviceObject)

	fs := pool + 0x6000
	f.mem.link(fixtureSymbols["IopFsNotifyChangeQueueHead"], fs)
	f.mem.u64(fs+0x10, driverObject)
	f.mem.u64(fs+0x18, routine(8))

	power := pool + 0x7000
	f.mem.link(fixtureSymbols["PopRegisteredPowerSettingCallbacks"], power)
	f.mem.write(power+0x24, []byte{0x4d, 0x0f, 0x3e, 0xba, 0x17, 0xb8, 0x94, 0x40, 0xa2, 0xd1, 0xd5, 0x63, 0x79, 0xe6, 0xa0, 0xf3})
	f.mem.u64(power+0x50, routine(9))

	for sym, obj := range map[string]uint64{"PsProcessType": processType, "PsThreadType": threadType, "ExDesktopObjectType": desktopType} {
		f.mem.u64(fixtureSymbols[sym], obj)
		f.mem.link(obj + 0xc8)
	}
	f.mem.unicode(processType+0x10, processType+0x400, "Process")
	registration := pool + 0x8000
	f.mem.u32(registration, 0x10100)
	f.mem.unicode(registration+0x10, registration+0x100, "321000.5")
	entry := registration + 0x40
	f.mem.link(processType+0xc8, entry)
	f.mem.u32(entry+0x10, 3)
	f.mem.u64(entry+0x18, registration)
	f.mem.u64(entry+0x20, processType)
	f.mem.u64(entry+0x28, routine(10))
	f.mem.u64(entry+0x30, routine(11))
	return f
}
