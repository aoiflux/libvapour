package keyboardnotifiers

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const (
	listHead = Data + 0x5000
	heap     = 0xffff888000000000
	keyMod   = ModuleArea + 0x10000
	keyText  = ModuleArea + 0x20000
	kbdCall  = Text + 0x500
	mask     = 1<<48 - 1
)

func fixture() *Fixture {
	f := NewFixture(0)
	f.Types.Struct("atomic_notifier_head", 16, map[string]F{
		"lock": {Off: 0, Type: Struct("spinlock")}, "head": {Off: 8, Type: Ptr(Struct("notifier_block"))},
	})
	f.Types.Struct("notifier_block", 24, map[string]F{
		"notifier_call": {Off: 0, Type: Ptr(Fn())}, "next": {Off: 8, Type: Ptr(Struct("notifier_block"))},
		"priority": {Off: 16, Type: Base("int")},
	})
	f.Types.Symbol("keyboard_notifier_list", listHead, Struct("atomic_notifier_head"))
	f.Types.Symbol("vt_kbd_notifier", kbdCall, Fn())
	f.Mem.Map(listHead, 16)
	f.AddModule(ModuleSpec{At: keyMod, Name: "keylog", Base: keyText, TextSize: 0x1000})
	return f
}

type nb struct {
	call uint64
	prio int32
}

func chainOf(f *Fixture, blocks ...nb) []uint64 {
	var at []uint64
	for i := range blocks {
		at = append(at, heap+uint64(i)*0x40)
	}
	for i, b := range blocks {
		f.Mem.U64(at[i], b.call)
		next := uint64(0)
		if i+1 < len(at) {
			next = at[i+1]
		}
		f.Mem.U64(at[i]+8, next)
		f.Mem.U32(at[i]+16, uint32(b.prio))
	}
	if len(at) > 0 {
		f.Mem.U64(listHead+8, at[0])
	}
	return at
}

func TestEmptyChainGivesNoRows(t *testing.T) {
	ctx, diags := fixture().Context(t, nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 || len(*diags) != 0 {
		t.Errorf("rows %v err %v diags %q", rows, err, *diags)
	}
}

func TestChainInOrderWithOwners(t *testing.T) {
	f := fixture()
	at := chainOf(f, nb{kbdCall, 10}, nb{keyText + 0x20, 0}, nb{heap + 0x100000, -5})
	ctx, diags := f.Context(t, nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{
		{BlockAddress: at[0] & mask, Address: kbdCall & mask, Priority: 10, Module: linuxmodule.KernelOwner,
			Symbol: "vt_kbd_notifier", ModuleFound: true},
		{BlockAddress: at[1] & mask, Address: (keyText + 0x20) & mask, Module: "keylog", ModuleAddress: keyMod & mask,
			ModuleFound: true},
		{BlockAddress: at[2] & mask, Address: (heap + 0x100000) & mask, Priority: -5},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows\n got %+v\nwant %+v", rows, want)
	}
	if len(*diags) != 0 {
		t.Errorf("diags %q", *diags)
	}
}

func TestAPriorityAboveItsPredecessorIsReported(t *testing.T) {
	f := fixture()
	chainOf(f, nb{kbdCall, 0}, nb{kbdCall, 7})
	ctx, diags := f.Context(t, nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %v err %v", rows, err)
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "priority 7 is above the 0") {
		t.Errorf("diags %q", *diags)
	}
}

func TestACycleEndsTheWalkAndFailsStrictMode(t *testing.T) {
	f := fixture()
	at := chainOf(f, nb{kbdCall, 0}, nb{kbdCall, 0})
	f.Mem.U64(at[1]+8, at[0])
	ctx, diags := f.Context(t, nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %v err %v", rows, err)
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "chain ends") {
		t.Errorf("diags %q", *diags)
	}
	ctx, _ = f.Context(t, map[string]any{"strict": true})
	if _, err := Run(ctx); err == nil {
		t.Error("strict mode accepted a cycle")
	}
}

func TestTheChainStopsAtMaxListEntries(t *testing.T) {
	f := fixture()
	chainOf(f, nb{kbdCall, 3}, nb{kbdCall, 2}, nb{kbdCall, 1})
	ctx, _ := f.Context(t, nil)
	ctx.Limits = limits.Limits{MaxListEntries: 2}
	rows, err := Run(ctx)
	if err != nil || len(rows) != 2 {
		t.Errorf("rows %v err %v", rows, err)
	}
}

func TestNoList(t *testing.T) {
	ctx, _ := NewFixture(0).Context(t, nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoList) {
		t.Errorf("err = %v, want ErrNoList", err)
	}
}

func FuzzWalkChain(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0}, uint8(4))
	f.Add([]byte{}, uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, most uint8) {
		n := uint64(len(raw) / 8)
		read := func(at uint64) (block, error) {
			if at == 0 || at > n {
				return block{}, errors.New("unmapped")
			}
			var next uint64
			for i := 7; i >= 0; i-- {
				next = next<<8 | uint64(raw[(at-1)*8+uint64(i)])
			}
			return block{at: at, next: next % (n + 2), priority: int64(next)}, nil
		}
		c := walkChain(1, int(most), read)
		if len(c.blocks) > int(most) || uint64(len(c.blocks)) > n {
			t.Fatalf("%d blocks from %d records, cap %d", len(c.blocks), n, most)
		}
		if c.end == linuxwalk.Closed && len(c.blocks) > 0 && c.blocks[len(c.blocks)-1].next != 0 {
			t.Fatal("closed chain whose last block has a next")
		}
		seen := map[uint64]bool{}
		for _, b := range c.blocks {
			if seen[b.at] {
				t.Fatal("a block is listed twice")
			}
			seen[b.at] = true
		}
		_ = outOfOrder(c.blocks)
	})
}
