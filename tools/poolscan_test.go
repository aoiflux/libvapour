package tools

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
)

var win10 = kernel{major: 10, build: 19045, poolHeader: true, bodies: []string{"_EPROCESS"}}

func diagnosed(diags []string, part string) bool {
	for _, d := range diags {
		if strings.Contains(d, part) {
			return true
		}
	}
	return false
}

func TestThePoolSetupRunsTheGateFirst(t *testing.T) {
	old := win10
	old.major, old.minor = 6, 1
	ctx, _ := old.context(nil)
	if _, err := ctx.StructureScan("windows.test.scan", scan.ProcessFilter); !errors.Is(err, ErrPoolScanUnsupportedBuild) {
		t.Errorf("structure scan: %v", err)
	}
	if _, _, err := ctx.ExecutiveScan("windows.test.scan", scan.ProcessFilter, scan.TypeTag{}); !errors.Is(err, ErrPoolScanUnsupportedBuild) {
		t.Errorf("executive scan: %v", err)
	}
}

func TestAMissingPoolHeaderIsAnError(t *testing.T) {
	k := win10
	k.poolHeader = false
	ctx, _ := k.context(nil)
	_, err := ctx.StructureScan("windows.test.scan")
	if !errors.Is(err, scan.ErrNoPoolHeader) || !strings.HasPrefix(err.Error(), "windows.test.scan: pool header layout: ") {
		t.Errorf("%v", err)
	}
}

func TestAMissingObjectHeaderIsAnError(t *testing.T) {
	ctx, _ := win10.context(nil)
	_, _, err := ctx.ExecutiveScan("windows.test.scan", scan.ProcessFilter, scan.TypeTag{})
	if err == nil || !strings.HasPrefix(err.Error(), "windows.test.scan: object layout: ") {
		t.Errorf("%v", err)
	}
}

func TestAMissingBodyTypeStopsTheScanWithADiagnostic(t *testing.T) {
	k := win10
	k.bodies = nil
	ctx, diags := k.context(nil)
	_, err := ctx.StructureScan("windows.test.scan", scan.ProcessFilter)
	if !errors.Is(err, scan.ErrStructureUndescribed) {
		t.Fatalf("%v", err)
	}
	if !diagnosed(*diags, `pool tag "Proc"`) || !diagnosed(*diags, "pool scan not run") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestWithoutKernelFramesTheScanRunsAndSaysWhatItLoses(t *testing.T) {
	ctx, diags := win10.context(nil)
	layout, err := ctx.StructureScan("windows.test.scan", scan.ProcessFilter)
	if err != nil {
		t.Fatal(err)
	}
	if layout.TagOffset != 4 || layout.Size != 0x10 {
		t.Errorf("layout %+v", layout)
	}
	if !diagnosed(*diags, "no physical memory") || !diagnosed(*diags, "not ranked by kernel mapping") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestTheCookieFollowsTheGlobal(t *testing.T) {
	table, mem := win10.open()
	ctx := Context{Memory: mem, Symbols: table}
	if ctx.HasObjectHeaderCookie() {
		t.Error("cookie without the global")
	}
	table.AddSymbol(symbols.Symbol{Name: "ObHeaderCookie", Address: 0xFFFFF80000300000})
	if !ctx.HasObjectHeaderCookie() {
		t.Error("no cookie with the global")
	}
	if (Context{}).HasObjectHeaderCookie() {
		t.Error("cookie without a table")
	}
}
