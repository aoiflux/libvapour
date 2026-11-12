package linuxobj_test

import (
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxkern"
	kt "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

// FuzzPages writes arbitrary bytes over a mapping's tree node and the struct
// pages it points at: the walk must end, and keep within MaxTableEntries.
func FuzzPages(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x02, 0, 0, 0, 0, 0, 0, 0}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1})
	f.Fuzz(func(t *testing.T, slots, pages []byte) {
		fx := kt.NewPageCacheFixture(kt.PageCacheOptions{Folio: true})
		sb, _ := fx.AddSuperBlock("ext4", "sda1", 8, 1)
		in := fx.AddInode(sb, kt.InodeSpec{Mode: 0o100644, Ino: 12, Size: 1 << 20})
		head := fx.CacheFolio(in, 0, 2, nil)
		fx.Cache(in, 9, nil)
		ctx, _ := fx.Context(t, nil)
		ctx.Limits.MaxTableEntries = 256
		node, _ := fx.Mem.ReadAt(in+kt.InData+kt.ASPages+8, 8)
		at := uint64(node[0]) | uint64(node[1])<<8 | uint64(node[2])<<16 | uint64(node[3])<<24 |
			uint64(node[4])<<32 | uint64(node[5])<<40 | uint64(node[6])<<48 | uint64(node[7])<<56
		if len(slots) > 64*8 {
			slots = slots[:64*8]
		}
		fx.Mem.Write(at&^3+kt.XANodeSlots, slots)
		if len(pages) > 8*kt.PCPageSize {
			pages = pages[:8*kt.PCPageSize]
		}
		fx.Mem.Write(head, pages)
		k, err := linuxkern.New(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c, err := linuxobj.NewPageCache(k.Walker(), ctx.PhysicalMemory(), false)
		if err != nil {
			t.Fatal(err)
		}
		mp, err := c.Pages((in+kt.InData)&(1<<48-1), 1<<8)
		if err != nil {
			return
		}
		if len(mp.Pages) > 256 {
			t.Fatalf("%d pages past the cap", len(mp.Pages))
		}
		for _, p := range mp.Pages {
			_ = c.FlagNames(p.Flags)
			_, _ = c.Frame(p)
		}
	})
}
