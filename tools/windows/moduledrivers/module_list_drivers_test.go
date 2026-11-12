package moduledrivers

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

func TestOnlyModulesNamedSysAreListed(t *testing.T) {
	k := testsupport.NewS64Kernel()
	k.AddModule("ntoskrnl.exe", 0xfffff80000400000, 0x100000)
	k.AddModule("Tcpip.SYS", 0xfffff80001000000, 0x5000)
	k.AddModule("hal.dll", 0xfffff80002000000, 0x5000)
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Name != "Tcpip.SYS" || rows[0].Base != 0xfffff80001000000 || rows[0].Size != 0x5000 {
		t.Errorf("rows = %+v", rows)
	}
}
