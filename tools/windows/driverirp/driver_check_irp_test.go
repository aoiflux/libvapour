package driverirp

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

func TestEachSlotIsAttributed(t *testing.T) {
	k := testsupport.NewS64Kernel()
	k.AddModule("ntoskrnl.exe", 0xfffff80000400000, 0x100000)
	k.AddModule("alpha.sys", 0xfffff80001000000, 0x5000)
	handlers := make([]uint64, 28)
	for i := range handlers {
		handlers[i] = 0xfffff80000400100
	}
	handlers[0] = 0xfffff80001000100
	handlers[14] = 0xfffff80009000000
	d := k.AddDriver(testsupport.S64Driver{Name: `\Driver\alpha`, ObjectName: "alpha", Start: 0xfffff80001000000,
		Size: 0x5000, Handlers: handlers})
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 28 {
		t.Fatalf("%d rows, want 28", len(rows))
	}
	for _, r := range rows {
		if r.Offset != d || r.Driver != `\Driver\alpha` || r.MajorName != MajorFunctionNames[r.Major] {
			t.Errorf("row %+v", r)
		}
		switch r.Major {
		case 0:
			if !r.InImage || r.Module != "alpha" || r.Unowned {
				t.Errorf("IRP_MJ_CREATE = %+v", r)
			}
		case 14:
			if !r.Unowned || r.InImage || r.Module != "" {
				t.Errorf("IRP_MJ_DEVICE_CONTROL = %+v", r)
			}
		default:
			if r.InImage || r.Module != "ntoskrnl" {
				t.Errorf("slot %d = %+v", r.Major, r)
			}
		}
	}
}

func TestTheNamesFollowWdm(t *testing.T) {
	if len(MajorFunctionNames) != 0x1c || MajorFunctionNames[0x0e] != "IRP_MJ_DEVICE_CONTROL" ||
		MajorFunctionNames[0x1b] != "IRP_MJ_PNP" || majorName(0x1c) != "0x1c" {
		t.Error("major function names do not follow wdm.h")
	}
}

func TestADriverWithoutAnObjectNameTakesItsHeaderName(t *testing.T) {
	k := testsupport.NewS64Kernel()
	k.AddModule("ntoskrnl.exe", 0xfffff80000400000, 0x100000)
	k.AddDriver(testsupport.S64Driver{ObjectName: "RAW"})
	rows, err := Run(k.Context())
	if err != nil || len(rows) != 28 || rows[0].Driver != "RAW" || !rows[0].Unowned {
		t.Errorf("rows %v, err %v", rows, err)
	}
}
