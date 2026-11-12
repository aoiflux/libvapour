package memorytree

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
)

func s68Fixture() *testsupport.ProcessFixture {
	return testsupport.BuildProcessFixture([]testsupport.FixtureProcess{
		{PID: 4, Name: "System", NoPeb: true, VADs: []testsupport.FixtureVAD{
			{Start: 0x10000, End: 0x1ffff},
			{Start: 0x7ff60000, End: 0x7ff63fff, Path: `\Windows\System32\ntdll.dll`},
			{Start: 0x20000, End: 0x2ffff},
			{Start: 0x30000, End: 0x30fff, Tag: "VadF"},
		}},
		{PID: 404, Name: "smss\xffexe", NoPeb: true, VADs: []testsupport.FixtureVAD{
			{Start: 0x40000, End: 0x4ffff},
		}},
	})
}

func withDiagnostics(ctx tools.Context) (tools.Context, *[]string) {
	var diags []string
	if ctx.Options == nil {
		ctx.Options = map[string]any{}
	}
	ctx.Options["diagnostics"] = &diags
	return ctx, &diags
}

func TestEveryKeptNodeIsARowInProcessThenAddressOrder(t *testing.T) {
	ctx := s68Fixture().Context()
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := memoryranges.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(ranges) || len(rows) != 5 {
		t.Fatalf("%d rows for %d ranges, want 5 of each", len(rows), len(ranges))
	}
	byAddress := map[uint64]Row{}
	for i, r := range rows {
		m := ranges[i]
		if r.PID != m.PID || r.Address != m.VadAddress || r.Start != m.Start || r.End != m.End || r.Tag != m.Tag {
			t.Errorf("row %d = %+v, the range listing has pid %d VAD 0x%x 0x%x-0x%x %q", i, r, m.PID, m.VadAddress, m.Start, m.End, m.Tag)
		}
		byAddress[r.Address] = r
	}
	if rows[4].Process != "smss�exe" {
		t.Errorf("process name %q, want invalid UTF-8 replaced", rows[4].Process)
	}
	roots := 0
	for _, r := range rows {
		if r.Parent == 0 {
			roots++
			continue
		}
		p, ok := byAddress[r.Parent]
		if !ok || p.PID != r.PID {
			t.Errorf("row at 0x%x names parent 0x%x, not a node of its process", r.Address, r.Parent)
			continue
		}
		if p.Left != r.Address && p.Right != r.Address {
			t.Errorf("parent 0x%x of 0x%x links to 0x%x and 0x%x, not to it", p.Address, r.Address, p.Left, p.Right)
		}
		if (p.Left == r.Address && r.End >= p.Start) || (p.Right == r.Address && r.Start <= p.End) {
			t.Errorf("child 0x%x-0x%x is on the wrong side of 0x%x-0x%x", r.Start, r.End, p.Start, p.End)
		}
	}
	if roots != 2 {
		t.Errorf("%d roots, want one per process", roots)
	}
}

func TestThePIDOptionKeepsOnlyTheProcessesItNames(t *testing.T) {
	ctx := s68Fixture().Context()
	ctx.Options = map[string]any{"pid": uint64(404)}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].PID != 404 || rows[0].Start != 0x40000 {
		t.Errorf("rows %+v, want pid 404's one range", rows)
	}
}

func TestAnUnreadableNodeIsLeftOutAndStrictModeStops(t *testing.T) {
	f := s68Fixture()
	whole, err := Run(f.Context())
	if err != nil {
		t.Fatal(err)
	}
	var lost Row
	for _, r := range whole {
		if r.PID == 4 && r.Start == 0x7ff60000 {
			lost = r
		}
	}
	ctx, diags := withDiagnostics(f.Context())
	ctx.Memory = testsupport.HoleReader{MemoryReader: ctx.Memory, From: lost.Address, To: lost.Address + 0x40}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Address == lost.Address {
			t.Errorf("the unreadable node is still a row")
		}
	}
	if len(rows) != len(whole)-1 {
		t.Errorf("%d rows, want %d", len(rows), len(whole)-1)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "VAD tree nodes left out") {
		t.Errorf("diagnostics %q do not say a node was left out", *diags)
	}

	ctx.Options["strict"] = true
	if _, err := Run(ctx); !errors.Is(err, memoryranges.ErrVADUnread) {
		t.Errorf("strict run: %v, want %v", err, memoryranges.ErrVADUnread)
	}
}

func TestATableWithoutParentLinksIsRefused(t *testing.T) {
	f := s68Fixture()
	st, err := f.Table.Struct("_RTL_BALANCED_NODE")
	if err != nil {
		t.Fatal(err)
	}
	kept := st.Fields[:0]
	for _, fl := range st.Fields {
		if fl.Name != "ParentValue" {
			kept = append(kept, fl)
		}
	}
	st.Fields = kept
	f.Table.AddStruct(st)
	if _, err := Run(f.Context()); !errors.Is(err, memoryranges.ErrVADLayout) {
		t.Errorf("Run: %v, want %v", err, memoryranges.ErrVADLayout)
	}
}

func TestOnlyWindowsProfilesRun(t *testing.T) {
	ctx := s68Fixture().Context()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "unsupported profile os") {
		t.Errorf("Run on Linux: %v", err)
	}
}
