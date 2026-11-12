package testsupport

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// The S64 fixture is a 64-bit kernel with real page tables. Its offsets are
// those the 26100 kernel tables give (S64 section 3), so a test written on
// it reads the members where a capture holds them.
const (
	S64DriverObjectSize   = uint64(0x150)
	S64DriverDeviceObject = uint64(0x08)
	S64DriverStart        = uint64(0x18)
	S64DriverSize         = uint64(0x20)
	S64DriverExtension    = uint64(0x30)
	S64DriverName         = uint64(0x38)
	S64DriverMajor        = uint64(0x70)
	S64ExtensionSize      = uint64(0x58)
	S64ExtensionKey       = uint64(0x18)

	S64DeviceObjectSize = uint64(0x150)
	S64DeviceDriver     = uint64(0x08)
	S64DeviceNext       = uint64(0x10)
	S64DeviceAttached   = uint64(0x18)
	S64DeviceType       = uint64(0x48)

	S64LoaderEntrySize = uint64(0xa0)
	S64LoaderDllBase   = uint64(0x30)
	S64LoaderSize      = uint64(0x40)
	S64LoaderFullName  = uint64(0x48)
	S64LoaderBaseName  = uint64(0x58)

	S64PcrSelf        = uint64(0x18)
	S64PcrCurrentPrcb = uint64(0x20)
	S64PcrPrcb        = uint64(0x180)
	S64PrcbNumber     = uint64(0x24)
	S64PrcbTimerTable = uint64(0x4100)
	S64TimerEntries   = uint64(0x200)
	S64TableEntrySize = uint64(0x20)
	S64TableEntryList = uint64(0x08)
	S64TimerBuckets   = uint64(512)

	S64TimerDueTime  = uint64(0x18)
	S64TimerLinks    = uint64(0x20)
	S64TimerDpc      = uint64(0x30)
	S64TimerPeriod   = uint64(0x3c)
	S64HeaderSignal  = uint64(0x04)
	S64DpcRoutine    = uint64(0x18)
	S64TimerSize     = uint64(0x40)
	S64DpcSize       = uint64(0x40)
	S64SharedData    = uint64(0xFFFFF78000000000)
	S64InterruptTime = uint64(0x08)
	S64SystemTime    = uint64(0x14)
	S64SystemRoot    = uint64(0x30)
	S64BuildNumber   = uint64(0x260)
	S64ProductType   = uint64(0x264)
	S64MajorVersion  = uint64(0x26c)
	S64MinorVersion  = uint64(0x270)

	s64PoolHeader     = uint64(0x00)
	s64NameInfo       = uint64(0x10)
	s64ObjectHeader   = uint64(0x30)
	S64PoolBodyOffset = uint64(0x60)
	s64InfoMaskValue  = 0x02
	s64NameInfoBack   = 0x20

	s64HeapVA        = uint64(0xffffa00000000000)
	s64ListHeadVA    = uint64(0xfffff80000001000)
	s64RangeStartVA  = uint64(0xfffff80000002000)
	s64InfoMaskVA    = uint64(0xfffff80000003000)
	s64GlobalsVA     = uint64(0xfffff80000004000)
	S64SystemStart   = uint64(0xffff800000000000)
	s64ModuleNamesVA = uint64(0xfffff80000100000)
)

type S64Kernel struct {
	Memory *PagedMemory
	Kernel *AddressSpace
	Table  *symbols.Table
	heap   uint64
	pages  map[uint64]uint64
	tail   uint64
	glob   uint64
}

func s64Field(name string, off uint64, typ string) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: typ}}
}

func s64Ptr(name string, off uint64, to string) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: to, IsPointer: true}}
}

func NewS64Kernel() *S64Kernel {
	pm := NewPagedMemory(64 << 20)
	k := &S64Kernel{Memory: pm, Kernel: pm.NewAddressSpace(), heap: s64HeapVA, pages: map[uint64]uint64{},
		glob: s64GlobalsVA}
	k.Table = s64Table()
	k.U64(s64RangeStartVA, S64SystemStart)
	k.U64(s64ListHeadVA, s64ListHeadVA)
	k.U64(s64ListHeadVA+8, s64ListHeadVA)
	k.tail = s64ListHeadVA
	k.Write(s64InfoMaskVA, []byte{0, s64NameInfoBack, s64NameInfoBack, 2 * s64NameInfoBack})
	k.U32(S64SharedData+S64MajorVersion, 10)
	k.U32(S64SharedData+S64MinorVersion, 0)
	k.U32(S64SharedData+S64BuildNumber, 26100)
	nt := k.Global("NtBuildNumber", 4)
	k.U32(nt, 0xF0000000|26100)
	return k
}

func s64Table() *symbols.Table {
	t := symbols.NewTable("s64", 8)
	add := func(name string, size uint64, fields ...symbols.Field) {
		t.AddStruct(symbols.StructType{Name: name, Size: size, Fields: fields})
	}
	add("_LIST_ENTRY", 0x10, s64Ptr("Flink", 0, "_LIST_ENTRY"), s64Ptr("Blink", 8, "_LIST_ENTRY"))
	add("_UNICODE_STRING", 0x10, s64Field("Length", 0, "unsigned short"),
		s64Field("MaximumLength", 2, "unsigned short"), s64Ptr("Buffer", 8, "wchar_t"))
	add("_KLDR_DATA_TABLE_ENTRY", S64LoaderEntrySize, s64Field("InLoadOrderLinks", 0, "_LIST_ENTRY"),
		s64Ptr("DllBase", S64LoaderDllBase, "void"), s64Field("SizeOfImage", S64LoaderSize, "unsigned int"),
		s64Field("FullDllName", S64LoaderFullName, "_UNICODE_STRING"),
		s64Field("BaseDllName", S64LoaderBaseName, "_UNICODE_STRING"))
	add("_POOL_HEADER", PoolHeaderSize, s64Field("PoolIndex", 1, "unsigned char"),
		s64Field("BlockSize", 2, "unsigned char"), s64Field("PoolType", 3, "unsigned char"),
		s64Field("PoolTag", PoolTagOffset, "unsigned long"))
	add("_POOL_TRACKER_BIG_PAGES", 0x18, s64Field("PoolType", 0x0c, "unsigned long"))
	add("_OBJECT_HEADER", 0x38, s64Field("PointerCount", 0, "long long"),
		s64Field("TypeIndex", 0x18, "unsigned char"), s64Field("InfoMask", 0x1a, "unsigned char"),
		s64Field("Body", s64ObjectHeader, "_QUAD"))
	add("_OBJECT_HEADER_NAME_INFO", 0x20, s64Ptr("Directory", 0, "_OBJECT_DIRECTORY"),
		s64Field("Name", 8, "_UNICODE_STRING"))
	add("_DRIVER_OBJECT", S64DriverObjectSize, s64Field("Type", 0, "short"), s64Field("Size", 2, "short"),
		s64Ptr("DeviceObject", S64DriverDeviceObject, "_DEVICE_OBJECT"),
		s64Ptr("DriverStart", S64DriverStart, "void"), s64Field("DriverSize", S64DriverSize, "unsigned int"),
		s64Ptr("DriverExtension", S64DriverExtension, "_DRIVER_EXTENSION"),
		s64Field("DriverName", S64DriverName, "_UNICODE_STRING"),
		symbols.Field{Name: "MajorFunction", Offset: S64DriverMajor, Type: symbols.TypeRef{Name: "void",
			IsArray: true, ArrayLength: 28, Element: &symbols.TypeRef{Name: "void", IsPointer: true}}})
	add("_DRIVER_EXTENSION", S64ExtensionSize, s64Ptr("DriverObject", 0, "_DRIVER_OBJECT"),
		s64Field("ServiceKeyName", S64ExtensionKey, "_UNICODE_STRING"))
	add("_DEVICE_OBJECT", S64DeviceObjectSize, s64Field("Type", 0, "short"),
		s64Field("Size", 2, "unsigned short"), s64Ptr("DriverObject", S64DeviceDriver, "_DRIVER_OBJECT"),
		s64Ptr("NextDevice", S64DeviceNext, "_DEVICE_OBJECT"),
		s64Ptr("AttachedDevice", S64DeviceAttached, "_DEVICE_OBJECT"),
		s64Field("DeviceType", S64DeviceType, "unsigned int"))
	add("_KPCR", 0xd080, s64Ptr("Self", S64PcrSelf, "_KPCR"), s64Ptr("CurrentPrcb", S64PcrCurrentPrcb, "_KPRCB"),
		s64Field("Prcb", S64PcrPrcb, "_KPRCB"))
	add("_KPRCB", 0xcf00, s64Field("Number", S64PrcbNumber, "unsigned int"),
		s64Field("TimerTable", S64PrcbTimerTable, "_KTIMER_TABLE"))
	inner := &symbols.TypeRef{Name: "_KTIMER_TABLE_ENTRY", IsArray: true, ArrayLength: 256,
		Element: &symbols.TypeRef{Name: "_KTIMER_TABLE_ENTRY"}}
	add("_KTIMER_TABLE", 0x4218, symbols.Field{Name: "TimerEntries", Offset: S64TimerEntries,
		Type: symbols.TypeRef{Name: "_KTIMER_TABLE_ENTRY", IsArray: true, ArrayLength: 2, Element: inner}})
	add("_KTIMER_TABLE_ENTRY", S64TableEntrySize, s64Field("Entry", S64TableEntryList, "_LIST_ENTRY"))
	add("_KTIMER", S64TimerSize, s64Field("Header", 0, "_DISPATCHER_HEADER"),
		s64Field("DueTime", S64TimerDueTime, "_ULARGE_INTEGER"),
		s64Field("TimerListEntry", S64TimerLinks, "_LIST_ENTRY"), s64Ptr("Dpc", S64TimerDpc, "_KDPC"),
		s64Field("Period", S64TimerPeriod, "unsigned int"))
	add("_DISPATCHER_HEADER", 0x18, s64Field("Type", 0, "unsigned char"),
		s64Field("SignalState", S64HeaderSignal, "int"))
	add("_KDPC", S64DpcSize, s64Field("Type", 0, "unsigned char"), s64Ptr("DeferredRoutine", S64DpcRoutine, "void"))
	add("_KAFFINITY_EX", 0x108, symbols.Field{Name: "StaticBitmap", Offset: 8, Type: symbols.TypeRef{
		Name: "unsigned long long", IsArray: true, ArrayLength: 32,
		Element: &symbols.TypeRef{Name: "unsigned long long"}}})
	add("_KUSER_SHARED_DATA", 0xa80, s64Field("InterruptTime", S64InterruptTime, "_KSYSTEM_TIME"),
		s64Field("SystemTime", S64SystemTime, "_KSYSTEM_TIME"),
		symbols.Field{Name: "NtSystemRoot", Offset: S64SystemRoot, Type: symbols.TypeRef{Name: "wchar_t",
			IsArray: true, ArrayLength: 260, Element: &symbols.TypeRef{Name: "wchar_t"}}},
		s64Field("NtBuildNumber", S64BuildNumber, "unsigned int"),
		s64Field("NtProductType", S64ProductType, "int"),
		s64Field("NtMajorVersion", S64MajorVersion, "unsigned int"),
		s64Field("NtMinorVersion", S64MinorVersion, "unsigned int"))
	t.AddEnum(symbols.EnumType{Name: "_KOBJECTS", Size: 4, Values: []symbols.EnumValue{
		{Name: "TimerNotificationObject", Value: 8}, {Name: "TimerSynchronizationObject", Value: 9},
		{Name: "DpcObject", Value: 19}, {Name: "ThreadedDpcObject", Value: 26}}})
	t.AddEnum(symbols.EnumType{Name: "_NT_PRODUCT_TYPE", Size: 4, Values: []symbols.EnumValue{
		{Name: "NtProductWinNt", Value: 1}, {Name: "NtProductServer", Value: 3}}})
	t.AddSymbol(symbols.Symbol{Name: "PsLoadedModuleList", Address: s64ListHeadVA})
	t.AddSymbol(symbols.Symbol{Name: "MmSystemRangeStart", Address: s64RangeStartVA})
	t.AddSymbol(symbols.Symbol{Name: "ObpInfoMaskToOffset", Address: s64InfoMaskVA})
	return t
}

func (k *S64Kernel) page(va uint64) uint64 {
	base := va &^ 0xFFF
	pa, ok := k.pages[base]
	if !ok {
		pa = k.Kernel.MapPage(base)
		k.pages[base] = pa
	}
	return pa + va&0xFFF
}

func (k *S64Kernel) Physical(va uint64) uint64 { return k.page(va) }

func (k *S64Kernel) Write(va uint64, b []byte) {
	for i := range b {
		k.Memory.WriteAt(k.page(va+uint64(i)), b[i:i+1])
	}
}

func (k *S64Kernel) U64(va, v uint64) { k.Write(va, binary.LittleEndian.AppendUint64(nil, v)) }
func (k *S64Kernel) U32(va uint64, v uint32) {
	k.Write(va, binary.LittleEndian.AppendUint32(nil, v))
}
func (k *S64Kernel) U16(va uint64, v uint16) {
	k.Write(va, binary.LittleEndian.AppendUint16(nil, v))
}

// Alloc returns page-aligned kernel memory of its own pages, so a test can
// leave a neighbour unmapped by never allocating it.
func (k *S64Kernel) Alloc(size uint64) uint64 {
	va := k.heap
	pages := (size + 0xFFF) / 0x1000
	if pages == 0 {
		pages = 1
	}
	for i := uint64(0); i < pages; i++ {
		k.page(va + i*0x1000)
	}
	k.heap += (pages + 1) * 0x1000
	return va
}

// Skip reserves address space that is never mapped.
func (k *S64Kernel) Skip() uint64 {
	va := k.heap
	k.heap += 0x2000
	return va
}

func (k *S64Kernel) Global(name string, size uint64) uint64 {
	va := k.glob
	k.glob += (size + 0xF) &^ 0xF
	k.page(va)
	k.page(va + size)
	k.Table.AddSymbol(symbols.Symbol{Name: name, Address: va})
	return va
}

func S64UTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func (k *S64Kernel) String(at uint64, s string) {
	b := S64UTF16(s)
	buf := k.Alloc(uint64(len(b)) + 2)
	k.Write(buf, b)
	k.U16(at, uint16(len(b)))
	k.U16(at+2, uint16(len(b)+2))
	k.U64(at+8, buf)
}

func (k *S64Kernel) AddModule(name string, base, size uint64) uint64 {
	entry := k.Alloc(S64LoaderEntrySize)
	k.U64(entry+S64LoaderDllBase, base)
	k.U32(entry+S64LoaderSize, uint32(size))
	k.String(entry+S64LoaderBaseName, name)
	k.String(entry+S64LoaderFullName, `\SystemRoot\system32\drivers\`+name)
	k.U64(entry, s64ListHeadVA)
	k.U64(entry+8, k.tail)
	k.U64(k.tail, entry)
	k.U64(s64ListHeadVA+8, entry)
	k.tail = entry
	return entry
}

// PoolObject lays out an allocation the way the scan expects one: pool
// header, name information, object header, body.
func (k *S64Kernel) PoolObject(tag string, body uint64, name string) uint64 {
	va := k.Alloc(S64PoolBodyOffset + body)
	// Without a name the object header follows the pool header directly.
	pool := s64PoolHeader
	if name == "" {
		pool = s64ObjectHeader - PoolHeaderSize
	}
	header := make([]byte, PoolHeaderSize)
	WritePoolHeader(header, 0, tag, BlocksFor(S64PoolBodyOffset-pool+body), NonPagedPoolType)
	k.Write(va+pool, header)
	k.U64(va+s64ObjectHeader, 1)
	if name != "" {
		k.Write(va+s64ObjectHeader+0x1a, []byte{s64InfoMaskValue})
		k.String(va+s64NameInfo+8, name)
	}
	return va + S64PoolBodyOffset
}

type S64Driver struct {
	Name, ObjectName, ServiceKey string
	Start, Size                  uint64
	Handlers                     []uint64
}

func (k *S64Kernel) AddDriver(d S64Driver) uint64 {
	body := k.PoolObject("Driv", S64DriverObjectSize, d.ObjectName)
	k.U16(body, 4)
	k.U16(body+2, uint16(S64DriverObjectSize))
	k.U64(body+S64DriverStart, d.Start)
	k.U32(body+S64DriverSize, uint32(d.Size))
	if d.Name != "" {
		k.String(body+S64DriverName, d.Name)
	}
	ext := k.Alloc(S64ExtensionSize)
	k.U64(ext, body)
	if d.ServiceKey != "" {
		k.String(ext+S64ExtensionKey, d.ServiceKey)
	}
	k.U64(body+S64DriverExtension, ext)
	for i, h := range d.Handlers {
		k.U64(body+S64DriverMajor+uint64(i)*8, h)
	}
	return body
}

func (k *S64Kernel) AddDevice(name string, owner uint64, deviceType uint32) uint64 {
	body := k.PoolObject("Devi", S64DeviceObjectSize, name)
	k.U16(body, 3)
	k.U64(body+S64DeviceDriver, owner)
	k.U32(body+S64DeviceType, deviceType)
	return body
}

func (k *S64Kernel) LinkDevices(driver uint64, devices ...uint64) {
	link := driver + S64DriverDeviceObject
	for _, d := range devices {
		k.U64(link, d)
		link = d + S64DeviceNext
	}
	k.U64(link, 0)
}

func (k *S64Kernel) Attach(lower, upper uint64) { k.U64(lower+S64DeviceAttached, upper) }

func (k *S64Kernel) Context() tools.Context {
	return tools.Context{
		Memory:  layers.NewProcessLayer(k.Memory, k.Kernel.DTB, 0),
		Symbols: k.Table,
		Profile: profiles.WindowsX64Profile{},
		Options: map[string]any{
			tools.OptionPhysicalMemory: memory.MemoryReader(k.Memory),
			tools.OptionKernelDTB:      k.Kernel.DTB,
			tools.OptionPagingMode:     "x64",
		},
	}
}
