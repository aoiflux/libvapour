package pagecache_test

import (
	"io"
	"testing"

	"github.com/aoiflux/libvapour/tools/linux/pagecache"
	kt "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

// FuzzFiles writes arbitrary bytes over an inode, a dentry and a mount: the
// listing and the archive must end without a panic.
func FuzzFiles(f *testing.F) {
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add([]byte{0xff, 0xa1, 0, 0, 0xff, 0xff}, []byte{0x01, 0x02}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0xff})
	f.Fuzz(func(t *testing.T, inode, dentry, mount []byte) {
		s := newScene(kt.PageCacheOptions{Folio: true})
		trim := func(b []byte, n int) []byte { return b[:min(len(b), n)] }
		s.f.Mem.Write(s.passwd, trim(inode, kt.InodeSize))
		s.f.Mem.Write(s.etcD, trim(dentry, kt.DSize))
		s.f.Mem.Write(s.rootMnt, trim(mount, kt.MntSize))
		ctx, _ := s.ctx(t, nil)
		ctx.Limits.MaxPathSteps = 64
		ctx.Limits.MaxListEntries = 64
		if _, err := pagecache.RunFiles(ctx); err != nil {
			return
		}
		ctx.Options[pagecache.OptionListPagesFind] = "/etc/passwd"
		_, _ = pagecache.RunListPages(ctx)
		_, _ = pagecache.DumpFilesTo(ctx, io.Discard)
	})
}
