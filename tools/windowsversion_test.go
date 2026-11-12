package tools

import (
	"errors"
	"strings"
	"testing"
)

func TestTheGateRefusesVersionsBeforeWindows8(t *testing.T) {
	for _, k := range []kernel{
		{major: 6, minor: 1, build: 7601},
		{major: 5, minor: 2, build: 3790},
		{major: 6, minor: 1, build: 9600},
	} {
		ctx, diags := k.context(nil)
		err := ctx.RequirePoolScanBuild("windows.test.scan")
		if !errors.Is(err, ErrPoolScanUnsupportedBuild) {
			t.Errorf("%d.%d build %d: %v, want a refusal", k.major, k.minor, k.build, err)
			continue
		}
		if len(*diags) != 1 || !strings.HasPrefix((*diags)[0], "windows.test.scan: windows ") {
			t.Errorf("%d.%d: diagnostics %q, want the refusal once under the tool's name", k.major, k.minor, *diags)
		}
	}
}

func TestTheGatePassesWindows8AndLater(t *testing.T) {
	for _, k := range []kernel{
		{major: 6, minor: 2, build: 9200},
		{major: 6, minor: 3, build: 9600},
		{major: 10, minor: 0, build: 14393},
		{major: 10, minor: 0, build: 26100},
		{major: 6, minor: 2, build: 7601},
	} {
		ctx, diags := k.context(nil)
		if err := ctx.RequirePoolScanBuild("windows.test.scan"); err != nil || len(*diags) != 0 {
			t.Errorf("%d.%d build %d: %v %q, want a pass", k.major, k.minor, k.build, err, *diags)
		}
	}
}

func TestWithoutTheVersionTheKernelBuildDecides(t *testing.T) {
	cases := []struct {
		k    kernel
		pass bool
	}{
		{kernel{build: 7601}, false},
		{kernel{build: 9199}, false},
		{kernel{build: 9200}, true},
		{kernel{build: 19045}, true},
		{kernel{zeroShared: true, build: 7601}, false},
		{kernel{zeroShared: true, build: 26100}, true},
	}
	for _, c := range cases {
		ctx, _ := c.k.context(nil)
		err := ctx.RequirePoolScanBuild("windows.test.scan")
		if c.pass != (err == nil) {
			t.Errorf("%+v: %v, want pass %v", c.k, err, c.pass)
		}
		if err != nil && !strings.Contains(err.Error(), "windows unread build ") {
			t.Errorf("%+v: %q does not say the version was unread", c.k, err)
		}
	}
}

func TestAnUnreadBuildPassesWithADiagnostic(t *testing.T) {
	for _, k := range []kernel{{}, {zeroShared: true}} {
		ctx, diags := k.context(nil)
		if err := ctx.RequirePoolScanBuild("windows.test.scan"); err != nil {
			t.Errorf("%+v: %v, want a pass", k, err)
		}
		if len(*diags) != 1 || !strings.Contains((*diags)[0], "windows build unread") {
			t.Errorf("%+v: diagnostics %q, want one saying the build is unread", k, *diags)
		}
	}
}

func TestNoReaderOrTableIsLeftToValidate(t *testing.T) {
	ctx, diags := kernel{major: 6, minor: 1}.context(nil)
	ctx.Memory = nil
	if err := ctx.RequirePoolScanBuild("windows.test.scan"); err != nil || len(*diags) != 0 {
		t.Errorf("no memory: %v %q", err, *diags)
	}
	ctx, _ = kernel{major: 6, minor: 1}.context(nil)
	ctx.Symbols = nil
	if err := ctx.RequirePoolScanBuild("windows.test.scan"); err != nil {
		t.Errorf("no table: %v", err)
	}
}
