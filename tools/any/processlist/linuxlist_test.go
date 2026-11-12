package processlist

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func TestLinuxProcessRowsFollowTheWalk(t *testing.T) {
	s := newLinuxTasks()
	ctx, diags := s.k.Context(nil)
	rows, err := runLinux(ctx, runOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
	want := s.rows()
	if !slices.Equal(rows, want) {
		t.Errorf("rows %+v, want %+v", rows, want)
	}
}

func TestLinuxProcessIDIsTheThreadGroupID(t *testing.T) {
	s := newLinuxTasks()
	s.k.Mem.U32(s.srv+lt.TaskPID, 999)
	ctx, _ := s.k.Context(nil)
	rows, err := runLinux(ctx, runOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(rows); !slices.Equal(got, []uint64{1, 2, 300}) {
		t.Errorf("PIDs %v, want the tgid of each task", got)
	}
}

func TestLinuxPIDFilterIsAppliedByTheWalk(t *testing.T) {
	s := newLinuxTasks()
	ctx, _ := s.k.Context(map[string]any{"pid": "2,300"})
	rows, err := runLinux(ctx, runOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(rows); !slices.Equal(got, []uint64{2, 300}) {
		t.Errorf("PIDs %v, want 2 and 300", got)
	}
}

func TestLinuxTaskThatDoesNotReadIsLeftOut(t *testing.T) {
	s := newLinuxTasks()
	ctx, _ := s.k.Context(nil)
	if p, err := linuxProcess(linuxobj.New(ctx), unmapped); err == nil {
		t.Fatalf("unmapped task gave %+v", p)
	}
}

type fixedChecker struct {
	keep map[uint64]bool
	err  error
}

func (c fixedChecker) Confirm(p Process) (bool, error) { return c.keep[p.PID], c.err }

func TestLinuxCrossCheckDropsUnconfirmedRows(t *testing.T) {
	s := newLinuxTasks()
	ctx, diags := s.k.Context(nil)
	rows, err := runLinux(ctx, runOptions{crossChecker: fixedChecker{keep: map[uint64]bool{1: true, 300: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(rows); !slices.Equal(got, []uint64{1, 300}) {
		t.Errorf("PIDs %v, want 1 and 300", got)
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "process 2 is not in the snapshot") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestLinuxCrossCheckFailureKeepsRowsUnlessStrict(t *testing.T) {
	s := newLinuxTasks()
	bad := fixedChecker{err: errors.New("snapshot unreadable")}
	ctx, diags := s.k.Context(nil)
	rows, err := runLinux(ctx, runOptions{crossChecker: bad})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || len(*diags) != 3 {
		t.Errorf("rows %d, diagnostics %q; want 3 rows each with a diagnostic", len(rows), *diags)
	}
	ctx, _ = s.k.Context(map[string]any{"strict": true})
	if _, err := runLinux(ctx, runOptions{crossChecker: bad}); err == nil || !strings.Contains(err.Error(), "cross-check: snapshot unreadable") {
		t.Errorf("strict: %v", err)
	}
}

func TestLinuxBrokenWalkIsRefusedInStrictMode(t *testing.T) {
	s := newLinuxTasks()
	s.k.Mem.U64(s.kthread+lt.TaskTasks, unmapped)
	ctx, diags := s.k.Context(nil)
	if _, err := runLinux(ctx, runOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(*diags) == 0 {
		t.Error("a broken walk gave no diagnostic")
	}
	ctx, _ = s.k.Context(map[string]any{"strict": true})
	if _, err := runLinux(ctx, runOptions{}); err == nil || !strings.Contains(err.Error(), "strict mode: the process walk left tasks out") {
		t.Errorf("strict: %v", err)
	}
}
