package linuxobj_test

import (
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func FuzzKallsymsLists(f *testing.F) {
	f.Add([]byte{}, uint16(0))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, uint16(lt.ModuleSyms))
	f.Add([]byte{0x00, 0x10, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f}, uint16(0x1000))
	f.Fuzz(func(t *testing.T, data []byte, at uint16) {
		k, l, a := listedModules(false)
		m := l.FtraceMap(a, []lt.FtraceFunc{{Name: "alpha_init", IP: 0xffffffffd0000000, Size: 0x20}})
		s := l.BPF("bpf_prog_0000000000000000", 0xffffffffa0001000, 0xffffffffa0001080)
		l.Trampoline(0xffffffffc0400000, 0x100)
		for i, b := range data {
			off := uint64(at) + uint64(i)
			switch i % 3 {
			case 0:
				k.Mem.Write(a+off%0x1200, []byte{b})
			case 1:
				k.Mem.Write(m+off%lt.FtraceModMapSize, []byte{b})
			default:
				k.Mem.Write(s+off%lt.BPFKsymSize, []byte{b})
			}
		}
		ls := lister(k)
		_, _ = ls.ModuleSymbols()
		_ = ls.FtraceSymbols()
		_ = ls.BPFSymbols()
		_ = ls.Report()
	})
}

func FuzzLatchTree(f *testing.F) {
	f.Add([]byte{}, uint8(0), uint64(moduleA+0x150))
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0}, uint8(1), uint64(moduleC+0x44))
	f.Fuzz(func(t *testing.T, data []byte, which uint8, addr uint64) {
		tk := newTreeKernel()
		kinds := []lt.RegionRef{{Module: moduleA}, {Module: moduleB}, {Module: moduleC}, {Module: moduleB, Kind: 4}}
		node := lt.RegionNode(kinds[int(which)%len(kinds)]) - lt.ModTreeNodeNode - lt.ModuleMemoryMtn
		tk.k.Mem.Write(node, data[:min(len(data), lt.ModuleMemorySize)])
		if len(data) > lt.ModuleMemorySize {
			tk.k.Mem.Write(tk.tree.Root, data[lt.ModuleMemorySize:min(len(data), lt.ModuleMemorySize+lt.ModTreeRootSize)])
		}
		ctx, _ := tk.k.Context(nil)
		ks, err := linuxobj.New(ctx).NewKallsyms()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = ks.SymbolAt(addr)
		_, _ = ks.SymbolAt(moduleA + 0x150)
	})
}
