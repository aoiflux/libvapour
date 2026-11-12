package processcredentials

import (
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func TestACredHeldByTwoThreadGroupsIsListed(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	initCred := k.AddCred(lt.Cred{})
	k.Table.AddSymbol(symbols.Symbol{Name: "init_cred", Address: initCred})
	shared := k.AddCred(lt.Cred{UID: 1000})
	a := k.AddTask(lt.Task{PID: 30, TGID: 30, Comm: "a", Cred: shared})
	b := k.AddTask(lt.Task{PID: 20, TGID: 20, Comm: "b", Cred: shared})
	own := k.AddTask(lt.Task{PID: 40, TGID: 40, Comm: "own"})
	r1 := k.AddTask(lt.Task{PID: 90, TGID: 90, Comm: "r1", Cred: initCred})
	r2 := k.AddTask(lt.Task{PID: 5, TGID: 5, Comm: "r2", Cred: initCred})
	k.LinkTasks(a, b, own, r1, r2)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(*diags) != 0 {
		t.Fatalf("err %v diagnostics %v", err, *diags)
	}
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	if r := rows[0]; r.CredAddress != initCred || !r.InitCred || !slices.Equal(r.PIDs, []int64{5, 90}) {
		t.Errorf("row 0 %+v", r)
	}
	if r := rows[1]; r.CredAddress != shared || r.InitCred || !slices.Equal(r.PIDs, []int64{20, 30}) {
		t.Errorf("row 1 %+v", r)
	}
}

func TestAProcessWithoutAReadableCredIsCounted(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	a := k.AddTask(lt.Task{PID: 30, TGID: 30, Comm: "a"})
	k.Mem.U64(a+lt.TaskCred, 0)
	k.LinkTasks(a)
	ctx, diags := k.Context(nil)
	if rows, err := Run(ctx); err != nil || len(rows) != 0 || len(*diags) != 1 ||
		!strings.Contains((*diags)[0], "1 processes without a readable cred") {
		t.Errorf("rows %+v err %v diagnostics %v", rows, err, *diags)
	}
	strict, _ := k.Context(map[string]any{"strict": true})
	if _, err := Run(strict); err == nil || !strings.HasPrefix(err.Error(), Name+": strict mode:") {
		t.Errorf("strict: %v", err)
	}
}
