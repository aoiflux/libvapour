package librarylist

import (
	"testing"

	ts "github.com/aoiflux/libvapour/internal/testsupport"
)

// windows.pe.dump carves the modules this list gives (S55 4.6 step 2), so its
// fixture must list them here too (S55 O11).
func TestTheModuleDumpFixtureListsExplorersModule(t *testing.T) {
	w, err := ts.BuildS55World(ts.S55Explorer(), nil, ts.S55StandardModules())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := Run(w.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d rows, want explorer.exe's module: %+v", len(rows), rows)
	}
	d := rows[0]
	if d.PID != ts.S55ExplorerPID || d.Base != ts.S55UserBase || d.Size != uint64(ts.MappedPESize) || d.Name != "explorer.exe" ||
		d.FullPath != `C:\Windows\explorer.exe` || d.NameUnreadable || d.FullPathUnreadable || !d.InLoadOrder {
		t.Errorf("row %+v", d)
	}
}
