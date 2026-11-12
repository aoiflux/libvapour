package memorypattern

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/kernelpattern"
)

func s68Fixture(t *testing.T) *testsupport.ProcessFixture {
	t.Helper()
	f := testsupport.BuildPooledProcessFixture([]testsupport.FixtureProcess{
		{PID: 1200, Name: "one.exe", VADs: []testsupport.FixtureVAD{
			{Start: 0x10000, End: 0x1ffff, Protection: 4},
			{Start: 0x30000, End: 0x31fff, Protection: 4},
		}},
		{PID: 3000, Name: "two\xfe.exe", VADs: []testsupport.FixtureVAD{
			{Start: 0x10000, End: 0x10fff, Protection: 4},
		}},
	})
	page := func(text string) []byte {
		b := make([]byte, 0x1000)
		copy(b[0x100:], text)
		return b
	}
	f.Space(1200).MapData(0x10000, page("needle-one"))
	f.Space(1200).MapData(0x50000, page("needle-outside-every-vad"))
	// The match runs across the page boundary into the next mapped page.
	tail := make([]byte, 0x1000)
	copy(tail[0xffa:], "needle")
	f.Space(1200).MapData(0x30000, tail)
	f.Space(1200).MapData(0x31000, []byte("-across"))
	f.Space(3000).MapData(0x10000, page("needle-two"))
	return f
}

func run(t *testing.T, f *testsupport.ProcessFixture, opts map[string]any) ([]Match, []string, error) {
	t.Helper()
	ctx := f.Context()
	var diags []string
	ctx.Options["diagnostics"] = &diags
	for k, v := range opts {
		ctx.Options[k] = v
	}
	rows, err := Run(ctx)
	return rows, diags, err
}

func TestMatchesComeFromVADRangesOnlyInProcessAndAddressOrder(t *testing.T) {
	rows, _, err := run(t, s68Fixture(t), map[string]any{OptionPattern: `needle-[a-z]+`})
	if err != nil {
		t.Fatal(err)
	}
	want := []Match{
		{PID: 1200, Process: "one.exe", Address: 0x10100, Text: "needle-one"},
		{PID: 1200, Process: "one.exe", Address: 0x30ffa, Text: "needle-across"},
		{PID: 3000, Process: "two�.exe", Address: 0x10100, Text: "needle-two"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v, want %+v", rows, want)
	}
	for i, w := range want {
		r := rows[i]
		if r.PID != w.PID || r.Process != w.Process || r.Address != w.Address || r.Text != w.Text || !bytes.Equal(r.Bytes, []byte(w.Text)) {
			t.Errorf("row %d = %+v, want %+v", i, r, w)
		}
	}
}

func TestThePIDOptionAndTheMatchSizeApply(t *testing.T) {
	rows, _, err := run(t, s68Fixture(t), map[string]any{OptionPattern: `needle-[a-z]+`, OptionMaxSize: uint64(6), "pid": uint64(3000)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].PID != 3000 || string(rows[0].Bytes) != "needle" {
		t.Errorf("rows %+v, want pid 3000's match cut to 6 bytes", rows)
	}
}

func TestThePatternAndPhysicalMemoryAreRequired(t *testing.T) {
	if _, _, err := run(t, s68Fixture(t), nil); !errors.Is(err, kernelpattern.ErrNoPattern) {
		t.Errorf("no pattern: %v, want %v", err, kernelpattern.ErrNoPattern)
	}
	f := s68Fixture(t)
	ctx := f.Context()
	delete(ctx.Options, tools.OptionPhysicalMemory)
	ctx.Options[OptionPattern] = "x"
	if _, err := Run(ctx); !errors.Is(err, kernelpattern.ErrNoPhysical) {
		t.Errorf("no physical memory: %v, want %v", err, kernelpattern.ErrNoPhysical)
	}
}

func TestAProcessWithoutARootIsCountedNotSearched(t *testing.T) {
	f := s68Fixture(t)
	_, phys := f.EPROCESS(3000)
	f.Memory.WriteU64(phys+testsupport.FixtureDTBOffset, 0)
	rows, diags, err := run(t, f, map[string]any{OptionPattern: `needle-two`})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("rows %+v from a process with no root", rows)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "1 processes without a page-table root") {
		t.Errorf("diagnostics %q", diags)
	}
}
