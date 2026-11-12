package keyboardnotifiers

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const Name = "linux.keyboard.list_notifiers"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "List the callbacks on the Linux keyboard notifier chain and the module or kernel code that holds them"},
		RunAny,
	)
}

var ErrNoList = errors.New("keyboardnotifiers: keyboard_notifier_list not in the symbol table")

type Row struct {
	BlockAddress  uint64
	Address       uint64
	Priority      int64
	Module        string
	Symbol        string
	ModuleAddress uint64
	ModuleFound   bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	head, err := k.Symbol("keyboard_notifier_list")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoList)
	}
	for _, m := range [][2]string{{"atomic_notifier_head", "head"}, {"notifier_block", "notifier_call"},
		{"notifier_block", "next"}, {"notifier_block", "priority"}} {
		if _, err := k.Member(m[0], m[1]); err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
	}
	first, err := k.Ptr(head, "atomic_notifier_head", "head")
	if err != nil {
		return nil, fmt.Errorf("%s: keyboard_notifier_list at %#x: head: %w", Name, head, err)
	}
	ch := walkChain(first, ctx.Bounds().MaxListEntries, func(at uint64) (block, error) {
		call, err1 := k.Ptr(at, "notifier_block", "notifier_call")
		next, err2 := k.Ptr(at, "notifier_block", "next")
		prio, err3 := k.Int(at, "notifier_block", "priority")
		return block{at: at, call: call, next: next, priority: prio}, errors.Join(err1, err2, err3)
	})
	lossy := false
	if ch.end != linuxwalk.Closed {
		lossy = true
		ctx.AddDiagnostic("%s: notifier_block at %#x: chain ends %s after %d blocks", Name, ch.at, ch.end,
			len(ch.blocks))
	}
	for _, i := range outOfOrder(ch.blocks) {
		ctx.AddDiagnostic("%s: notifier_block at %#x: priority %d is above the %d of the block before it", Name,
			ch.blocks[i].at, ch.blocks[i].priority, ch.blocks[i-1].priority)
	}
	owners := newOwners(k, ctx.AddDiagnostic)
	out := make([]Row, 0, len(ch.blocks))
	for _, b := range ch.blocks {
		o := owners.of(b.call)
		out = append(out, Row{BlockAddress: b.at, Address: b.call, Priority: b.priority, Module: o.module,
			Symbol: o.symbol, ModuleAddress: o.moduleAddress, ModuleFound: o.found})
	}
	if (lossy || owners.lossy) && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: the chain or the module views were read in part", Name)
	}
	return out, nil
}
