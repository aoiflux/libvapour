package pe_test

import (
	"fmt"

	"github.com/aoiflux/libvapour/pe"
)

func ExampleLookupExport() {
	exports := []pe.Export{
		{Name: "RtlGetVersion", Ordinal: 10, RVA: 0x41200},
		{Name: "HeapAlloc", Ordinal: 11, RVA: 0x8C010, Forwarder: "NTDLL.RtlAllocateHeap"},
	}
	const base = 0x7FFA10000000
	for _, name := range []string{"RtlGetVersion", "HeapAlloc"} {
		at, ok := pe.LookupExport(exports, name, base)
		fmt.Printf("%s 0x%x %v\n", name, at, ok)
	}
	// Output:
	// RtlGetVersion 0x7ffa10041200 true
	// HeapAlloc 0x0 false
}
