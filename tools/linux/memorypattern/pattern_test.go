package memorypattern

import (
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const areaBase = uint64(0x7f0000000000)

type patternCase struct {
	k     *lt.Kernel
	us    *lt.UserSpaces
	tasks []uint64
}

func newPatternCase() *patternCase {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	return &patternCase{k: k, us: k.NewUserSpaces(8 << 20)}
}

// process maps the first page of each area and writes text at its offset
// into the area.
func (c *patternCase) process(pid int32, texts map[uint64]string, areas ...lt.VMA) {
	pgd, as := c.us.New()
	mm := c.k.AddMM(lt.MM{PGD: pgd, VMAs: areas})
	for _, a := range areas {
		as.MapPage(a.Start)
	}
	for at, s := range texts {
		pa := as.MapPage(at &^ 0xfff)
		c.us.PM.WriteAt(pa+at&0xfff, []byte(s))
	}
	c.tasks = append(c.tasks, c.k.AddTask(lt.Task{PID: pid, TGID: pid, Comm: "p", MM: mm}))
}

func (c *patternCase) run(t *testing.T, options map[string]any) ([]Match, []string, error) {
	t.Helper()
	c.k.LinkTasks(c.tasks...)
	ctx, diags := c.us.Context(options)
	rows, err := Run(ctx)
	return rows, *diags, err
}

func TestMatchesInsideTheAreasAreReportedAtTheirAddress(t *testing.T) {
	c := newPatternCase()
	c.process(100, map[uint64]string{areaBase + 0x10: "GLIBC_2.34 x", areaBase + 0x1ff0: "GLIBC_2.2.5"},
		lt.VMA{Start: areaBase, End: areaBase + 0x2000})
	c.process(200, map[uint64]string{areaBase + 0x5000: "GLIBC_2.17"}, lt.VMA{Start: areaBase, End: areaBase + 0x1000})
	rows, diags, err := c.run(t, map[string]any{OptionPattern: `GLIBC_2\.[0-9]+`})
	if err != nil {
		t.Fatal(err)
	}
	want := []Match{
		{PID: 100, Process: "p", Address: areaBase + 0x10, Text: "GLIBC_2.34", Bytes: []byte("GLIBC_2.34")},
		{PID: 100, Process: "p", Address: areaBase + 0x1ff0, Text: "GLIBC_2.2", Bytes: []byte("GLIBC_2.2")},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v diags %q", rows, diags)
	}
	for i := range want {
		w, r := want[i], rows[i]
		if r.PID != w.PID || r.Address != w.Address || r.Text != w.Text || !slices.Equal(r.Bytes, w.Bytes) {
			t.Errorf("row %d: %+v, want %+v", i, r, w)
		}
	}
	rows, _, err = c.run(t, map[string]any{OptionPattern: `GLIBC_2\.[0-9]+`, OptionMaxSize: uint64(5)})
	if err != nil || len(rows) != 2 || string(rows[0].Bytes) != "GLIBC" {
		t.Errorf("max size: %+v err %v", rows, err)
	}
}

func TestThePatternOptionIsRequired(t *testing.T) {
	c := newPatternCase()
	if _, _, err := c.run(t, nil); err == nil || !strings.HasPrefix(err.Error(), Name+": ") {
		t.Errorf("no pattern: %v", err)
	}
	if _, _, err := c.run(t, map[string]any{OptionPattern: "("}); err == nil {
		t.Error("a pattern that does not compile was taken")
	}
}

func TestAChunkPastTheMatchCapIsSaid(t *testing.T) {
	c := newPatternCase()
	c.process(100, map[uint64]string{areaBase + 0x10: "ab ab ab"}, lt.VMA{Start: areaBase, End: areaBase + 0x1000})
	c.k.LinkTasks(c.tasks...)
	ctx, diags := c.us.Context(map[string]any{OptionPattern: `ab`})
	ctx.Limits = limits.Default()
	ctx.Limits.MaxMatchesPerChunk = 2
	rows, err := Run(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if len(*diags) != 1 || !strings.HasPrefix((*diags)[0], Name+": 1 chunks held more than MaxMatchesPerChunk (2) matches") {
		t.Errorf("diagnostics %q", *diags)
	}
}
