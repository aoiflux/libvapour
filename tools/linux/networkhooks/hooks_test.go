package networkhooks

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	text0     = uint64(0xffffffff81000000)
	acceptAll = text0 + 0x500
	kernelFn  = text0 + 0x600
	modBase   = uint64(0xffffffffc0000000)
	hostNS    = 4026531840
	opsPF     = 0x28
	opsNum    = 0x2c
	mask48    = uint64(1)<<48 - 1
	intMin    = -1 << 31
)

type fixture struct {
	k    *lt.Kernel
	n    *lt.Net
	net  uint64
	devs []uint64
}

func newFixture() *fixture {
	k := lt.NewKernel(1700000000, 0)
	n := lt.AddNetTypes(k)
	mods := lt.AddModuleTypes(k)
	voidp := symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: "void"}}
	k.Table.AddStruct(symbols.StructType{Name: "nf_hook_ops", Size: lt.NFHookOpsSize, Fields: []symbols.Field{
		{Name: "list", Offset: lt.NFHookOpsList, Type: symbols.TypeRef{Name: "list_head"}},
		{Name: "hook", Offset: lt.NFHookOpsHook, Type: voidp},
		{Name: "pf", Offset: opsPF, Type: symbols.TypeRef{Name: "unsigned char"}},
		{Name: "hooknum", Offset: opsNum, Type: symbols.TypeRef{Name: "unsigned int"}},
		{Name: "priority", Offset: lt.NFHookOpsPriority, Type: symbols.TypeRef{Name: "int"}},
	}})
	k.Table.AddSymbol(symbols.Symbol{Name: "_text", Address: text0})
	k.Table.AddSymbol(symbols.Symbol{Name: "_etext", Address: text0 + 0x100000})
	k.Table.AddSymbol(symbols.Symbol{Name: "accept_all", Address: acceptAll})
	k.Table.AddSymbol(symbols.Symbol{Name: "ipv4_conntrack_defrag", Address: kernelFn})
	ct := mods.Add("nf_conntrack", modBase, 0x10000,
		[]lt.ModuleSymbol{{Name: "ipv4_conntrack_in", Value: modBase + 0x100}}, 1)
	mods.List(ct)
	net := n.AddNamespace(hostNS)
	devs := n.AddDevices(net, lt.Device{Name: "lo", Ifindex: 1}, lt.Device{Name: "eth0", Ifindex: 2})
	return &fixture{k: k, n: n, net: net, devs: devs}
}

type reg struct {
	fn, entryFn  uint64
	pf, hooknum  uint32
	priority     int32
	unreadableOp bool
}

func (f *fixture) ops(r reg) uint64 {
	if r.unreadableOp {
		return 0xffff888077000000
	}
	k := f.k
	at := k.Alloc(lt.NFHookOpsSize)
	k.Mem.U64(at+lt.NFHookOpsHook, r.fn)
	k.Mem.Write(at+opsPF, []byte{byte(r.pf)})
	k.Mem.U32(at+opsNum, r.hooknum)
	k.Mem.U32(at+lt.NFHookOpsPriority, uint32(r.priority))
	return at
}

func (f *fixture) chain(head uint64, count uint16, regs ...reg) uint64 {
	k := f.k
	size := lt.NFHookEntriesHook + uint64(len(regs))*(lt.NFHookEntrySize+8)
	block := k.Alloc(size)
	k.Mem.Write(block, []byte{byte(count), byte(count >> 8)})
	opsAt := block + lt.NFHookEntriesHook + uint64(len(regs))*lt.NFHookEntrySize
	for i, r := range regs {
		fn := r.entryFn
		if fn == 0 {
			fn = r.fn
		}
		k.Mem.U64(block+lt.NFHookEntriesHook+uint64(i)*lt.NFHookEntrySize, fn)
		k.Mem.U64(opsAt+uint64(i)*8, f.ops(r))
	}
	k.Mem.U64(head, block)
	return block
}

func (f *fixture) ipv4(hook uint64) uint64 { return f.net + lt.NetNF + lt.NFHooksIPv4 + 8*hook }

func TestRunListsEachEntryWithItsCheck(t *testing.T) {
	f := newFixture()
	f.chain(f.ipv4(1), 6,
		reg{fn: kernelFn, pf: 2, hooknum: 1, priority: -400},
		reg{fn: modBase + 0x100, pf: 1, hooknum: 1, priority: -200},
		reg{fn: acceptAll, priority: intMin},
		reg{fn: kernelFn, entryFn: modBase + 0x180, pf: 2, hooknum: 1, priority: 0},
		reg{fn: kernelFn, pf: 2, hooknum: 3, priority: 100},
		reg{fn: 0xffffffffa0000000, pf: 2, hooknum: 1, priority: 300})
	f.chain(f.devs[1]+lt.DevHooksIngr, 2,
		reg{fn: modBase + 0x100, pf: 5, hooknum: 0, priority: 0},
		reg{fn: modBase + 0x100, pf: 1, hooknum: 5, priority: 10})
	ctx, diags := f.k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	type got struct {
		proto, hook, dev, module, symbol, registered string
		priority                                     int64
		check                                        Check
	}
	var have []got
	for _, r := range rows {
		if r.NetNS != hostNS || !r.NetNSKnown {
			t.Errorf("namespace %+v", r)
		}
		have = append(have, got{r.Protocol, r.Hook, r.Device, r.Module.Value, r.Symbol.Value, r.Registered,
			r.Priority, r.Check})
	}
	want := []got{
		{"NFPROTO_IPV4", "NF_INET_LOCAL_IN", "", "kernel", "ipv4_conntrack_defrag", "NFPROTO_IPV4", -400, CheckConsistent},
		{"NFPROTO_IPV4", "NF_INET_LOCAL_IN", "", "nf_conntrack", "ipv4_conntrack_in", "NFPROTO_INET", -200, CheckConsistent},
		{"NFPROTO_IPV4", "NF_INET_LOCAL_IN", "", "kernel", "accept_all", "NFPROTO_UNSPEC", intMin, CheckRemoved},
		{"NFPROTO_IPV4", "NF_INET_LOCAL_IN", "", "nf_conntrack", "ipv4_conntrack_in+0x80", "NFPROTO_IPV4", 0, CheckFunctionDiffers},
		{"NFPROTO_IPV4", "NF_INET_LOCAL_IN", "", "kernel", "ipv4_conntrack_defrag", "NFPROTO_IPV4", 100, CheckOtherChain},
		{"NFPROTO_IPV4", "NF_INET_LOCAL_IN", "", "", "", "NFPROTO_IPV4", 300, CheckNoOwner},
		{"NFPROTO_NETDEV", "NF_NETDEV_INGRESS", "eth0", "nf_conntrack", "ipv4_conntrack_in", "NFPROTO_NETDEV", 0, CheckConsistent},
		{"NFPROTO_NETDEV", "NF_NETDEV_INGRESS", "eth0", "nf_conntrack", "ipv4_conntrack_in", "NFPROTO_INET", 10, CheckConsistent},
	}
	if !slices.Equal(have, want) {
		t.Errorf("got\n%+v\nwant\n%+v\ndiagnostics %q", have, want, *diags)
	}
	if rows[0].FunctionAddress != kernelFn&mask48 || rows[0].Index != 0 || rows[5].Index != 5 {
		t.Errorf("first row %+v, last %+v", rows[0], rows[5])
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestRunCountsChainsOutOfOrderAndRefusesBadCounts(t *testing.T) {
	f := newFixture()
	f.chain(f.ipv4(0), 2, reg{fn: kernelFn, pf: 2, hooknum: 0, priority: 10},
		reg{fn: kernelFn, pf: 2, hooknum: 0, priority: -10})
	f.chain(f.ipv4(2), 0, reg{fn: kernelFn, pf: 2, hooknum: 2})
	f.chain(f.ipv4(3), maxChainEntries+1, reg{fn: kernelFn, pf: 2, hooknum: 3})
	f.chain(f.ipv4(4), 1, reg{fn: kernelFn, pf: 2, hooknum: 4, unreadableOp: true})
	ctx, diags := f.k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[2].Check != CheckOpsUnread {
		t.Errorf("rows %+v", rows)
	}
	joined := strings.Join(*diags, "\n")
	for _, want := range []string{"1 chains are not in ascending priority order", "count 0 is outside 1 to 1024",
		"count 1025 is outside 1 to 1024", "nf_hook_ops at 0x888077000000: does not read"} {
		if !strings.Contains(joined, want) {
			t.Errorf("diagnostics lack %q: %q", want, *diags)
		}
	}
	ctx, _ = f.k.Context(map[string]any{"strict": true})
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Errorf("strict: %v", err)
	}
}

func TestRunStopsAChainAtAnEntryThatDoesNotRead(t *testing.T) {
	f := newFixture()
	page := uint64(0xffff888070000000)
	f.k.Mem.Map(page, 0x1000)
	block := page + 0x1000 - lt.NFHookEntriesHook - lt.NFHookEntrySize
	f.k.Mem.Write(block, []byte{3, 0})
	f.k.Mem.U64(block+lt.NFHookEntriesHook, kernelFn)
	f.k.Mem.U64(f.ipv4(0), block)
	ctx, diags := f.k.Context(nil)
	rows, _ := Run(ctx)
	if len(rows) != 0 {
		t.Errorf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "of 3 does not read") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestRunRefusesATableWithoutTheChainTypes(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	lt.AddNetTypes(k)
	lt.AddModuleTypes(k)
	k.Table.AddStruct(symbols.StructType{Name: "net", Size: lt.NetSize, Fields: []symbols.Field{
		{Name: "list", Offset: lt.NetList, Type: symbols.TypeRef{Name: "list_head"}},
	}})
	ctx, _ := k.Context(nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoHookTypes) {
		t.Errorf("err %v", err)
	}
}

func TestSameChainFollowsTheRegistrationRules(t *testing.T) {
	for _, tc := range []struct {
		c    chain
		r    registration
		want bool
	}{
		{chain{proto: 2, hook: 1}, registration{proto: 2, hooknum: 1}, true},
		{chain{proto: 10, hook: 1}, registration{proto: protoINET, hooknum: 1}, true},
		{chain{proto: 3, hook: 1}, registration{proto: protoINET, hooknum: 1}, false},
		{chain{proto: 2, hook: 1}, registration{proto: 10, hooknum: 1}, false},
		{chain{proto: protoNetdev, hook: hookIngress}, registration{proto: protoINET, hooknum: inetIngress}, true},
		{chain{proto: protoNetdev, hook: hookEgress}, registration{proto: protoINET, hooknum: inetIngress}, false},
		{chain{proto: protoNetdev, hook: hookEgress}, registration{proto: protoNetdev, hooknum: hookEgress}, true},
	} {
		if got := sameChain(tc.c, tc.r); got != tc.want {
			t.Errorf("sameChain(%+v, %+v) = %v", tc.c, tc.r, got)
		}
	}
}

func TestProtocolNamesFallBackToTheNumber(t *testing.T) {
	if protoName(10) != "NFPROTO_IPV6" || protoName(99) != "NFPROTO 99" {
		t.Error(protoName(10), protoName(99))
	}
}
