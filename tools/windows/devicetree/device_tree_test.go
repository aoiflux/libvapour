package devicetree

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

func TestDriversDevicesAndStacksAreListedInOrder(t *testing.T) {
	k := testsupport.NewS64Kernel()
	disk := k.AddDriver(testsupport.S64Driver{Name: `\Driver\disk`, ObjectName: "disk"})
	filter := k.AddDriver(testsupport.S64Driver{Name: `\Driver\filter`, ObjectName: "filter"})
	d0 := k.AddDevice("DR0", disk, 0x07)
	d1 := k.AddDevice("", disk, 0x2d)
	f0 := k.AddDevice("", filter, 0x07)
	f1 := k.AddDevice("", filter, 0x8001)
	k.LinkDevices(disk, d0, d1)
	k.LinkDevices(filter, f0, f1)
	k.Attach(d0, f0)
	k.Attach(f0, f1)
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		kind  Kind
		level int
		dev   uint64
		typ   string
	}{
		{KindDriver, 0, 0, ""}, {KindDevice, 1, d0, "FILE_DEVICE_DISK"}, {KindAttached, 2, f0, "FILE_DEVICE_DISK"},
		{KindAttached, 3, f1, "0x8001"}, {KindDevice, 1, d1, "FILE_DEVICE_MASS_STORAGE"},
		{KindDriver, 0, 0, ""}, {KindDevice, 1, f0, "FILE_DEVICE_DISK"}, {KindAttached, 2, f1, "0x8001"},
		{KindDevice, 1, f1, "0x8001"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %+v", rows)
	}
	for i, w := range want {
		r := rows[i]
		if r.Kind != w.kind || r.Level != w.level || r.DeviceAddress != w.dev || r.DeviceType != w.typ {
			t.Errorf("row %d = %+v, want %+v", i, r, w)
		}
	}
	if rows[1].DeviceName != "DR0" || rows[0].DriverName != "disk" || rows[0].DriverFullName != `\Driver\disk` {
		t.Errorf("names: %+v %+v", rows[0], rows[1])
	}
	if rows[2].AttachedDriverName != `\Driver\filter` || rows[2].AttachedDriverHeaderName != "filter" {
		t.Errorf("attached = %+v", rows[2])
	}
}

func TestADeviceNamingAnotherDriverOrACycleStopsTheChain(t *testing.T) {
	k := testsupport.NewS64Kernel()
	a := k.AddDriver(testsupport.S64Driver{Name: `\Driver\a`})
	b := k.AddDriver(testsupport.S64Driver{Name: `\Driver\b`})
	ok := k.AddDevice("", a, 0x22)
	stray := k.AddDevice("", b, 0x22)
	k.LinkDevices(a, ok, stray)
	loop := k.AddDevice("", b, 0x22)
	k.LinkDevices(b, loop)
	k.U64(loop+testsupport.S64DeviceNext, loop)
	ctx := k.Context()
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	devices := 0
	for _, r := range rows {
		if r.Kind == KindDevice {
			devices++
		}
	}
	if devices != 2 {
		t.Errorf("%d device rows, want the first of a and the loop's one: %+v", devices, rows)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Error("strict mode accepted a broken chain")
	}
}

func TestDeviceTypeNames(t *testing.T) {
	if DeviceTypeName(0x22) != "FILE_DEVICE_UNKNOWN" || DeviceTypeName(0x67) != "FILE_DEVICE_CXL_TYPE3" ||
		DeviceTypeName(0x9000) != "0x9000" || len(DeviceCodes) != 95 {
		t.Errorf("device type names do not follow wdm.h (%d codes)", len(DeviceCodes))
	}
}

func FuzzDeviceChain(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint16(3), uint8(0))
	k := testsupport.NewS64Kernel()
	d := k.AddDriver(testsupport.S64Driver{Name: `\Driver\f`})
	a := k.AddDevice("", d, 0x22)
	b := k.AddDevice("", d, 0x22)
	k.LinkDevices(d, a, b)
	ctx := k.Context()
	targets := []uint64{0, a, b, d, 0xfffff80000001000}
	f.Fuzz(func(t *testing.T, next, attached uint64, typ uint16, which uint8) {
		k.U64(a+testsupport.S64DeviceNext, targets[int(next%5)])
		k.U64(b+testsupport.S64DeviceAttached, targets[int(attached%5)])
		k.U16(targets[1+int(which)%2], typ)
		rows, err := Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[[2]uint64]bool{}
		for _, r := range rows {
			key := [2]uint64{r.DeviceAddress, uint64(r.Level)}
			if r.Kind != KindDriver && seen[key] && r.Kind == KindDevice {
				t.Errorf("device 0x%x listed twice", r.DeviceAddress)
			}
			seen[key] = true
		}
		if len(rows) > 16 {
			t.Errorf("%d rows from three objects", len(rows))
		}
	})
}
