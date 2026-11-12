package minidump_test

import (
	"bytes"
	"fmt"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/minidump"
)

func ExampleWrite() {
	in := minidump.Input{
		System: minidump.SystemInfo{
			ProcessorArchitecture: minidump.ProcessorArchitectureAMD64,
			NumberOfProcessors:    2,
			MajorVersion:          10,
			BuildNumber:           26100,
			PlatformID:            2,
		},
		Modules: []minidump.Module{{Base: 0x140000000, Size: 0x2000, Name: `C:\tools\probe.exe`}},
		Regions: []minidump.Region{{
			BaseAddress: 0x140000000, AllocationBase: 0x140000000, Size: 0x2000,
			Protect: 0x20, AllocationProtect: 0x80,
			State: minidump.MemCommit, Type: minidump.MemImage, Dumpable: true,
		}},
		ReadMemory: func(base, size uint64) ([]byte, extract.GapMap) {
			b := make([]byte, size)
			copy(b, "MZ")
			return b, extract.GapMap{{Start: base + 0x1000, Length: 0x1000}}
		},
	}
	var dump bytes.Buffer
	result, err := minidump.Write(&dump, in)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, s := range result.Streams {
		fmt.Println(s.Type)
	}
	fmt.Printf("%d bytes read, %d padded\n", result.MemoryBytes, result.MemoryGaps.PaddedBytes())
	fmt.Println("valid:", minidump.Validate(dump.Bytes()).OK())
	// Output:
	// SystemInfoStream
	// ModuleListStream
	// ThreadListStream
	// ThreadInfoListStream
	// MemoryInfoListStream
	// Memory64ListStream
	// 4096 bytes read, 4096 padded
	// valid: true
}
