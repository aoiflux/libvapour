package cli

import (
	"flag"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools"
)

func TestTheFlagsBecomeTheSessionConfig(t *testing.T) {
	var f Flags
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	f.Register(fs)
	err := fs.Parse([]string{"-os", "Linux", "-symbols", "k.vsym", "-cr3", "0x1aa000", "-offline", "-strict", "mem.lime"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.Config()
	if cfg.SymbolsPath != "k.vsym" || cfg.KernelCR3 != 0x1aa000 || !cfg.OfflineOnly || !cfg.Strict || !cfg.CollectDiagnostics {
		t.Errorf("Config() = %+v", cfg)
	}
	if f.Windows() {
		t.Error("-os Linux read as windows")
	}
	if image, err := Image(fs); err != nil || image != "mem.lime" {
		t.Errorf("Image = %q, %v", image, err)
	}
	if !(Flags{OS: " WINDOWS "}).Windows() {
		t.Error("-os WINDOWS not read as windows")
	}
}

func TestOneImageIsRequired(t *testing.T) {
	for _, args := range [][]string{nil, {"a", "b"}} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		_ = fs.Parse(args)
		if _, err := Image(fs); err == nil {
			t.Errorf("%q accepted as one image", args)
		}
	}
}

func TestAQuietRunCountsWhatItHides(t *testing.T) {
	var out strings.Builder
	PrintDiagnostics(&out, []string{"any.process.list: list at 0xffff8000: cut short"}, false)
	if !strings.Contains(out.String(), "1 diagnostic") || strings.Contains(out.String(), "0xffff8000") {
		t.Errorf("quiet run printed %q", out.String())
	}
	out.Reset()
	PrintDiagnostics(&out, nil, false)
	if out.Len() != 0 {
		t.Errorf("no diagnostics printed %q", out.String())
	}
	out.Reset()
	PrintDiagnostics(&out, []string{"one", "two\x1b[2J"}, true)
	if out.String() != "warning: one\nwarning: two\\x1b[2J\n" {
		t.Errorf("verbose run printed %q", out.String())
	}
}

func TestWithOptionsCopiesTheSessionMap(t *testing.T) {
	ctx := tools.Context{Options: map[string]any{"strict": true}}
	got := WithOptions(ctx, map[string]any{"pid": uint64(4)})
	if _, leaked := ctx.Options["pid"]; leaked {
		t.Error("the session's map was changed")
	}
	if got.Options["pid"] != uint64(4) || got.Options["strict"] != true {
		t.Errorf("merged options %v", got.Options)
	}
	if got := WithOptions(tools.Context{}, map[string]any{"pid": uint64(1)}); got.Options["pid"] != uint64(1) {
		t.Errorf("a context with no options gave %v", got.Options)
	}
}
