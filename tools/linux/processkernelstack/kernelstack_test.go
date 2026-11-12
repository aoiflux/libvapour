package processkernelstack

import (
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	textBase    uint64 = 0xffffffff81000000
	taskThread         = 0x180
	taskStack          = 0x1a0
	threadSP           = 0x08
	stackBytes         = 4 * pageSize
	switchFrame        = textBase + 0x123
)

func stackKernel(t *testing.T) *lt.Kernel {
	t.Helper()
	k := lt.NewKernel(1700000000, 0)
	st, err := k.Table.Struct("task_struct")
	if err != nil {
		t.Fatal(err)
	}
	voidp := symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: "void"}}
	st.Fields = append(st.Fields, symbols.Field{Name: "thread", Offset: taskThread, Type: symbols.TypeRef{Name: "thread_struct"}},
		symbols.Field{Name: "stack", Offset: taskStack, Type: voidp})
	k.Table.AddStruct(st)
	k.Table.AddStruct(symbols.StructType{Name: "thread_struct", Size: 0x20, Fields: []symbols.Field{
		{Name: "sp", Offset: threadSP, Type: symbols.TypeRef{Name: "long unsigned int"}},
	}})
	k.AddKallsyms(textBase, []lt.KSym{
		{Type: 'T', Name: "_stext", Address: textBase},
		{Type: 'T', Name: "__switch_to_asm", Address: textBase + 0x100},
		{Type: 't', Name: "schedule", Address: textBase + 0x200},
		{Type: 'T', Name: "_etext", Address: textBase + 0x1000},
	})
	return k
}

func withStack(k *lt.Kernel, tid int32, depth uint64, words ...uint64) (task, base uint64) {
	task = k.AddTask(lt.Task{PID: tid, TGID: tid, Comm: "worker"})
	base = k.Alloc(stackBytes)
	sp := base + stackBytes - depth
	for i, w := range words {
		k.Mem.U64(sp+uint64(i)*8, w)
	}
	k.Mem.U64(task+taskStack, base)
	k.Mem.U64(task+taskThread+threadSP, sp)
	return task, base
}

func TestNamedWordsFromTheSavedSPUpAreListed(t *testing.T) {
	k := stackKernel(t)
	task, base := withStack(k, 9, 0x40, 0, 0x1234, switchFrame, textBase+0x210)
	k.LinkTasks(task)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(*diags) != 0 {
		t.Fatalf("err %v diagnostics %v", err, *diags)
	}
	sp := base + stackBytes - 0x40
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	if r := rows[0]; r.Slot != 2 || r.SlotAddress != sp+16 || r.Symbol != "__switch_to_asm" || r.Offset != 0x23 ||
		r.SymbolType != "T" || r.Module != "kernel" || !r.Named {
		t.Errorf("row 0 %+v", r)
	}
	if r := rows[1]; r.Slot != 3 || r.Symbol != "schedule" || r.Offset != 0x10 {
		t.Errorf("row 1 %+v", r)
	}
	ctx, _ = k.Context(map[string]any{OptionUnresolved: true})
	all, err := Run(ctx)
	if err != nil || len(all) != 3 || all[0].Named || all[0].Value != 0x1234 {
		t.Errorf("unresolved rows %+v err %v", all, err)
	}
}

func TestANonCanonicalWordIsNotNamed(t *testing.T) {
	k := stackKernel(t)
	lowBitsOfSchedule := (textBase + 0x210) &^ (0xff << 56)
	task, _ := withStack(k, 9, 0x40, lowBitsOfSchedule, textBase+0x210)
	k.LinkTasks(task)
	ctx, _ := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].Slot != 1 || rows[0].Symbol != "schedule" {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	ctx, _ = k.Context(map[string]any{OptionUnresolved: true})
	all, err := Run(ctx)
	if err != nil || len(all) != 2 || all[0].Named || all[0].Value != lowBitsOfSchedule || !all[1].Named {
		t.Errorf("unresolved rows %+v err %v", all, err)
	}
}

func TestAnSPOutsideTheStackSkipsTheTask(t *testing.T) {
	k := stackKernel(t)
	task, base := withStack(k, 9, 0x40, switchFrame)
	k.Mem.U64(task+taskThread+threadSP, base+stackBytes+8)
	gone := k.AddTask(lt.Task{PID: 10, TGID: 10, Comm: "zombie"})
	k.LinkTasks(task, gone)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 || len(*diags) != 1 || !strings.Contains((*diags)[0], "1 tasks whose saved sp is outside their stack") {
		t.Fatalf("rows %+v err %v diagnostics %v", rows, err, *diags)
	}
	strict, _ := k.Context(map[string]any{"strict": true})
	if _, err := Run(strict); err == nil || !strings.HasPrefix(err.Error(), Name+": strict mode:") {
		t.Errorf("strict: %v", err)
	}
}

func TestTheStackSizeFollowsKASAN(t *testing.T) {
	k := stackKernel(t)
	ctx, _ := k.Context(nil)
	if n := ThreadSize(newKernel(ctx)); n != 16<<10 {
		t.Errorf("without KASAN %#x", n)
	}
	k.Table.AddSymbol(symbols.Symbol{Name: kasanSymbol, Address: textBase + 0x300})
	ctx, _ = k.Context(nil)
	if n := ThreadSize(newKernel(ctx)); n != 32<<10 {
		t.Errorf("with KASAN %#x", n)
	}
}

func TestAPageThatDoesNotReadEndsTheWords(t *testing.T) {
	k := stackKernel(t)
	task, base := withStack(k, 9, pageSize+0x10, switchFrame)
	sp := base + stackBytes - pageSize - 0x10
	k.Mem.Unmap(sp&^(pageSize-1) + pageSize)
	k.LinkTasks(task)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || len(*diags) != 1 || !strings.Contains((*diags)[0], "1 stacks cut") {
		t.Errorf("rows %+v err %v diagnostics %v", rows, err, *diags)
	}
}

func FuzzReadWords(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, uint64(0xff8), uint64(16), uint8(8))
	f.Fuzz(func(t *testing.T, data []byte, sp, span uint64, width uint8) {
		m := lt.NewMemory()
		m.Write(0x1000, data)
		end := sp + span%(4*pageSize)
		words, full := readWords(m, sp, end, uint64(width))
		if width != 4 && width != 8 {
			if len(words) != 0 || !full {
				t.Fatalf("width %d gave %d words", width, len(words))
			}
			return
		}
		if end > sp && uint64(len(words)) > (end-sp)/uint64(width) {
			t.Fatalf("%d words from %d bytes", len(words), end-sp)
		}
		if full && end > sp && uint64(len(words)) != (end-sp)/uint64(width) {
			t.Fatalf("full read of %d bytes gave %d words", end-sp, len(words))
		}
	})
}

func newKernel(ctx tools.Context) *linuxobj.Kernel { return linuxobj.New(ctx) }
