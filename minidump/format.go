package minidump

import "fmt"

const (
	Signature  = uint32(0x504D444D)
	VersionLow = uint32(0xA793)
)

type StreamType uint32

const (
	StreamUnused         StreamType = 0
	StreamThreadList     StreamType = 3
	StreamModuleList     StreamType = 4
	StreamMemoryList     StreamType = 5
	StreamException      StreamType = 6
	StreamSystemInfo     StreamType = 7
	StreamMemory64List   StreamType = 9
	StreamHandleData     StreamType = 12
	StreamUnloadedModule StreamType = 14
	StreamMiscInfo       StreamType = 15
	StreamMemoryInfoList StreamType = 16
	StreamThreadInfoList StreamType = 17
)

var streamNames = map[StreamType]string{
	StreamUnused:         "UnusedStream",
	StreamThreadList:     "ThreadListStream",
	StreamModuleList:     "ModuleListStream",
	StreamMemoryList:     "MemoryListStream",
	StreamException:      "ExceptionStream",
	StreamSystemInfo:     "SystemInfoStream",
	StreamMemory64List:   "Memory64ListStream",
	StreamHandleData:     "HandleDataStream",
	StreamUnloadedModule: "UnloadedModuleListStream",
	StreamMiscInfo:       "MiscInfoStream",
	StreamMemoryInfoList: "MemoryInfoListStream",
	StreamThreadInfoList: "ThreadInfoListStream",
}

func (s StreamType) String() string {
	if n, ok := streamNames[s]; ok {
		return n
	}
	return fmt.Sprintf("stream type %d", uint32(s))
}

// The writer derives the header Flags from the streams it writes; the caller
// does not set them.
const (
	MiniDumpWithFullMemory     uint64 = 0x00000002
	MiniDumpWithHandleData     uint64 = 0x00000004
	MiniDumpWithFullMemoryInfo uint64 = 0x00000800
	MiniDumpWithThreadInfo     uint64 = 0x00001000
)

const (
	ProcessorArchitectureIntel   = uint16(0)
	ProcessorArchitectureARM     = uint16(5)
	ProcessorArchitectureAMD64   = uint16(9)
	ProcessorArchitectureARM64   = uint16(12)
	ProcessorArchitectureUnknown = uint16(0xFFFF)
)

// Zero is neither a state nor a type, so a region must name one of these.
const (
	MemCommit  = uint32(0x1000)
	MemReserve = uint32(0x2000)
	MemFree    = uint32(0x10000)

	MemPrivate = uint32(0x20000)
	MemMapped  = uint32(0x40000)
	MemImage   = uint32(0x1000000)
)

const (
	headerSize        = 32
	directoryEntry    = 12
	locationSize      = 8
	listCountSize     = 4
	systemInfoSize    = 56
	moduleSize        = 108
	fixedFileInfoSize = 52
	threadSize        = 48

	threadInfoHeaderSize = 12
	threadInfoSize       = 64
	handleHeaderSize     = 16
	handleDescriptorSize = 32
	handleDescriptor2    = 40
	memoryInfoHeaderSize = 16
	memoryInfoSize       = 48
	memory64HeaderSize   = 16
	memory64EntrySize    = 16

	threadInfoErrorThread    = uint32(0x1)
	threadInfoExited         = uint32(0x4)
	threadInfoInvalidContext = uint32(0x10)
	threadInfoInvalidTEB     = uint32(0x20)

	// Every stream starts on this boundary so its ULONG64 members are
	// naturally aligned for a reader that maps the file.
	streamAlign = 8
)

func knownState(s uint32) bool { return s == MemCommit || s == MemReserve || s == MemFree }

func knownType(t uint32) bool { return t == MemPrivate || t == MemMapped || t == MemImage }
