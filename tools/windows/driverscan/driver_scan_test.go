package driverscan

import (
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

func TestDriverObjectsAreFoundWithTheirRangeAndNames(t *testing.T) {
	k := testsupport.NewS64Kernel()
	a := k.AddDriver(testsupport.S64Driver{Name: `\Driver\alpha`, ObjectName: "alpha", ServiceKey: "alpha",
		Start: 0xfffff80001000000, Size: 0x5000})
	b := k.AddDriver(testsupport.S64Driver{ObjectName: "RAW"})
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want 2", rows)
	}
	byVA := map[uint64]Driver{}
	for _, r := range rows {
		byVA[r.VirtualOffset] = r
	}
	got := byVA[a]
	if got.Start != 0xfffff80001000000 || got.Size != 0x5000 || got.Name != `\Driver\alpha` || got.ObjectName != "alpha" ||
		got.ServiceKey != "alpha" || got.NameUnreadable || got.ObjectNameUnreadable || got.ServiceKeyUnreadable {
		t.Errorf("alpha = %+v", got)
	}
	if got.Offset != k.Physical(a) {
		t.Errorf("Offset = 0x%x, want the physical body 0x%x", got.Offset, k.Physical(a))
	}
	raw := byVA[b]
	if raw.Start != 0 || raw.Name != "" || raw.NameUnreadable || raw.ObjectName != "RAW" || !raw.ServiceKeyUnreadable && raw.ServiceKey != "" {
		t.Errorf("RAW = %+v", raw)
	}
}

func TestABodyWhoseSizeIsNotTheDriverObjectsIsRefused(t *testing.T) {
	k := testsupport.NewS64Kernel()
	bad := k.AddDriver(testsupport.S64Driver{Name: `\Driver\bad`})
	k.U16(bad+2, 0x100)
	bodyType := k.AddDriver(testsupport.S64Driver{Name: `\Driver\other`})
	k.U16(bodyType, 3)
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %+v, want none", rows)
	}
}

func TestANameWhoseBufferDoesNotReadIsFlagged(t *testing.T) {
	k := testsupport.NewS64Kernel()
	d := k.AddDriver(testsupport.S64Driver{Name: `\Driver\x`, ObjectName: "x"})
	k.U64(d+testsupport.S64DriverName+8, k.Skip())
	k.U16(d+testsupport.S64DriverName, 5)
	rows, err := Run(k.Context())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %v, err %v", rows, err)
	}
	if !rows[0].NameUnreadable || rows[0].Name != "" {
		t.Errorf("row = %+v, want the name flagged", rows[0])
	}
}

func TestAMissingMemberIsAnError(t *testing.T) {
	k := testsupport.NewS64Kernel()
	st, _ := k.Table.Struct("_DRIVER_EXTENSION")
	st.Fields = st.Fields[:1]
	k.Table.AddStruct(st)
	if _, err := Run(k.Context()); err == nil || !strings.Contains(err.Error(), "ServiceKeyName") {
		t.Errorf("err = %v, want one naming ServiceKeyName", err)
	}
}

func TestNoPhysicalMemoryIsAnError(t *testing.T) {
	ctx := testsupport.NewS64Kernel().Context()
	ctx.Options = map[string]any{}
	if _, err := Run(ctx); err == nil {
		t.Error("no error without physical memory")
	}
}

func TestPlausibleNamesAndIdentity(t *testing.T) {
	for name, want := range map[string]bool{`\Driver\Tcpip`: true, "": false, "a\x01b": false, "�": false, "ok name": true} {
		if got := PlausibleName(name); got != want {
			t.Errorf("PlausibleName(%q) = %v, want %v", name, got, want)
		}
	}
	if !Identified("", "", "svc") || Identified("", "\x02", "") {
		t.Error("Identified does not follow PlausibleName")
	}
}

func FuzzReadSplit(f *testing.F) {
	f.Add([]byte{4, 0, 6, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0})
	k := testsupport.NewS64Kernel()
	k.String(0xffffa00000000000, "seed")
	mem := k.Context().Memory
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) < 16 {
			return
		}
		s, err := readSplit(raw, mem, unicodeLayout(), 8, 0xFFFF)
		if err != nil && s != "" {
			t.Errorf("an error with text %q", s)
		}
	})
}
