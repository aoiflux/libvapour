package layers

import (
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
)

const (
	tPID   = 0x440
	tLinks = 0x448
	tName  = 0x5a8
	tDTB   = 0x28
)

func processTable() *symbols.Table {
	t := symbols.NewTable("s53", 8)
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x800, Fields: []symbols.Field{
		{Name: "Pcb", Offset: 0}, {Name: "UniqueProcessId", Offset: tPID},
		{Name: "ActiveProcessLinks", Offset: tLinks}, {Name: "ImageFileName", Offset: tName},
	}})
	t.AddStruct(symbols.StructType{Name: "_KPROCESS", Size: 0x400, Fields: []symbols.Field{{Name: "DirectoryTableBase", Offset: tDTB}}})
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 16, Fields: []symbols.Field{{Name: "Flink", Offset: 0}, {Name: "Blink", Offset: 8}}})
	return t
}

func putProcess(img *physImage, at, pid uint64, name string, root, flink, blink uint64) {
	img.put8(at+tPID, pid)
	copy(img.buf[at+tName:], name+"\x00")
	img.put8(at+tDTB, root)
	img.put8(at+tLinks, flink)
	img.put8(at+tLinks+8, blink)
}

func TestTheFirstPlausibleSystemProcessIsTheBootstrap(t *testing.T) {
	img := newPhys(0x200000)
	img.put8(0x1000+8*0x1f0, 0x2000|fP)
	putProcess(img, 0x10000, 4, "System", 0x900000, kva, kva)
	putProcess(img, 0x12000, 4, "System", 0x3000, kva, kva)
	putProcess(img, 0x14000, 4, "System", 0x1000, 0x10000, kva)
	putProcess(img, 0x16000, 4, "System", 0x1000|1<<55, kva, kva)
	putProcess(img, 0x18000, 8, "System", 0x1000, kva, kva)
	putProcess(img, 0x1a000, 4, "Systemd", 0x1000, kva, kva)
	putProcess(img, 0x1c008, 4, "System", 0x1000, kva+0x10, kva+0x20)
	b, err := FindKernelBootstrap(img, processTable())
	if err != nil || *b != (KernelBootstrap{CR3: 0x1000, ListFlink: kva + 0x10, ListBlink: kva + 0x20}) {
		t.Fatalf("got %+v, %v", b, err)
	}
	if cr3, err := FindKernelCR3(img, processTable()); err != nil || cr3 != 0x1000 {
		t.Fatalf("FindKernelCR3 = 0x%x, %v", cr3, err)
	}
}

func TestTheScanReadsPastAHoleAndSaysWhenItFindsNothing(t *testing.T) {
	img := newPhys(0x900000)
	img.holes[0x10000] = true
	img.put8(0x1000+8*0x1f0, 0x2000|fP)
	putProcess(img, 0x20000, 4, "System", 0x1000, kva, kva)
	putProcess(img, 0x500000, 4, "System", 0x1000, kva+8, kva)
	b, err := FindKernelBootstrap(img, processTable())
	if err != nil || b.ListFlink != kva+8 {
		t.Fatalf("got %+v, %v", b, err)
	}

	empty := newPhys(0x800000)
	empty.holes[0x400000] = true
	if _, err := FindKernelBootstrap(empty, processTable()); err == nil || !strings.Contains(err.Error(), "readable part") {
		t.Fatalf("got %v", err)
	}
	if _, err := FindKernelBootstrap(newPhys(0x10000), processTable()); err == nil {
		t.Fatal("found a System process in zeros")
	}
}

func TestTheScanNeedsItsMembers(t *testing.T) {
	table := symbols.NewTable("s53", 8)
	if _, err := FindKernelBootstrap(newPhys(0x1000), table); err == nil || !strings.Contains(err.Error(), "UniqueProcessId") {
		t.Fatalf("got %v", err)
	}
	if _, err := FindKernelBootstrap(newPhys(0x1000), nil); err == nil {
		t.Fatal("no table scanned")
	}
}

func TestABootstrapWithoutBlinkKeepsZero(t *testing.T) {
	table := processTable()
	table.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 16, Fields: []symbols.Field{{Name: "Flink", Offset: 0}}})
	img := newPhys(0x100000)
	img.put8(0x1000+8*0x1f0, 0x2000|fP)
	putProcess(img, 0x10000, 4, "System", 0x1000, kva, kva+0x40)
	if b, err := FindKernelBootstrap(img, table); err != nil || b.ListBlink != 0 {
		t.Fatalf("got %+v, %v", b, err)
	}
}
