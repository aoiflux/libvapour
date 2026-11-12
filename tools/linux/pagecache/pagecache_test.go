package pagecache_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linux/pagecache"
	kt "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const mask = 1<<48 - 1

type scene struct {
	f                                *kt.PageCacheFixture
	root, etcD, mntD, tmpRoot        uint64
	rootSB, tmpSB, rootMnt           uint64
	passwd, link, pageLink, su, note uint64
	unnamed, uncached                uint64
}

var passwdText = []byte("fixture page one: seven blue lanterns\n")

func newScene(o kt.PageCacheOptions) *scene {
	f := kt.NewPageCacheFixture(o)
	s := &scene{f: f}
	s.rootSB, s.root = f.AddSuperBlock("ext4", "sda1", 8, 1)
	s.rootMnt = f.Mount(s.rootSB, 0, 0, f.InitNS)
	etc := f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o040755, Ino: 10})
	s.etcD = f.Name(etc, s.root, "etc")
	s.passwd = f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o100644, Ino: 11, Size: 5000, UID: 0, GID: 0,
		Times: [3][2]int64{{1700000000, 5}, {1600000000, 6}, {1650000000, 7}}})
	f.Name(s.passwd, s.etcD, "passwd")
	f.Cache(s.passwd, 0, passwdText)
	s.link = f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o120777, Ino: 12, Size: 11, Link: "/usr/bin/sh"})
	f.Name(s.link, s.etcD, "sh")
	s.pageLink = f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o120777, Ino: 13, Size: 6})
	f.Name(s.pageLink, s.etcD, "long")
	f.Cache(s.pageLink, 0, []byte("target-and-more"))
	s.su = f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o104755, Ino: 14, Size: 4, UID: 0})
	f.Name(s.su, s.etcD, "su")
	f.Cache(s.su, 0, []byte("\x7fELF"))
	s.uncached = f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o100644, Ino: 15, Size: 100})
	f.Name(s.uncached, s.etcD, "hosts")
	s.unnamed = f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o100600, Ino: 16, Size: 3})
	f.Cache(s.unnamed, 0, []byte("abc"))
	mnt := f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o040755, Ino: 17})
	s.mntD = f.Name(mnt, s.root, "mnt")
	s.tmpSB, s.tmpRoot = f.AddSuperBlock("tmpfs", "tmpfs", 0, 30)
	f.Mount(s.tmpSB, s.rootMnt, s.mntD, f.InitNS)
	s.note = f.AddInode(s.tmpSB, kt.InodeSpec{Mode: 0o100640, Ino: 3, Size: 3, UID: 1000, GID: 1000})
	f.Name(s.note, s.tmpRoot, "note")
	f.Cache(s.note, 0, []byte("hey"))
	return s
}

func (s *scene) ctx(t *testing.T, opts map[string]any) (tools.Context, *[]string) {
	t.Helper()
	return s.f.Context(t, opts)
}

func byPath(rows []pagecache.File) map[string]pagecache.File {
	out := map[string]pagecache.File{}
	for _, r := range rows {
		out[r.Path] = r
	}
	return out
}

func TestListFilesNamesEachInodeUnderItsMount(t *testing.T) {
	s := newScene(kt.PageCacheOptions{Folio: true})
	ctx, diags := s.ctx(t, nil)
	rows, err := pagecache.RunFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := byPath(rows)
	p, ok := got["/etc/passwd"]
	if !ok {
		t.Fatalf("no /etc/passwd in %+v (%q)", rows, *diags)
	}
	want := pagecache.File{SuperBlockAddress: s.rootSB & mask, FSType: "ext4", Device: "8:1", MountPoint: "/",
		InodeAddress: s.passwd & mask, InodeNumber: 11, Type: pagecache.Regular, Mode: "-rw-r--r--", Size: 5000,
		Pages: 2, CachedPages: 1, Accessed: time.Unix(1700000000, 5).UTC(), AccessedOK: true,
		Modified: time.Unix(1600000000, 6).UTC(), ModifiedOK: true, Changed: time.Unix(1650000000, 7).UTC(),
		ChangedOK: true, Path: "/etc/passwd"}
	if p != want {
		t.Errorf("passwd\n got %+v\nwant %+v", p, want)
	}
	if n := got["/mnt/note"]; n.MountPoint != "/mnt" || n.FSType != "tmpfs" || n.UID != 1000 || n.Mode != "-rw-r-----" {
		t.Errorf("note %+v", n)
	}
	if r := got["/"]; r.Type != pagecache.Directory || r.InodeNumber != 2 {
		t.Errorf("root %+v", r)
	}
	if u := got[""]; u.InodeAddress != s.unnamed&mask || u.MountPoint != "" {
		t.Errorf("unnamed %+v", u)
	}
	if l := got["/etc/sh"]; l.Type != pagecache.Symlink || l.Mode != "lrwxrwxrwx" {
		t.Errorf("link %+v", l)
	}
	if len(rows) != 11 {
		t.Errorf("%d rows, want 11", len(rows))
	}
}

func TestListFilesFiltersByTypeAndPath(t *testing.T) {
	s := newScene(kt.PageCacheOptions{})
	ctx, _ := s.ctx(t, map[string]any{pagecache.OptionFilesType: "lnk,dir"})
	rows, err := pagecache.RunFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Type != pagecache.Symlink && r.Type != pagecache.Directory {
			t.Errorf("type %s passed the filter", r.Type)
		}
	}
	if len(rows) != 6 {
		t.Errorf("%d rows, want 6", len(rows))
	}
	ctx, _ = s.ctx(t, map[string]any{pagecache.OptionFilesFind: "/mnt/note"})
	if rows, err = pagecache.RunFiles(ctx); err != nil || len(rows) != 1 || rows[0].InodeAddress != s.note&mask {
		t.Errorf("find: %+v, %v", rows, err)
	}
	ctx, _ = s.ctx(t, map[string]any{pagecache.OptionFilesType: "file"})
	if _, err := pagecache.RunFiles(ctx); !errors.Is(err, pagecache.ErrFileType) {
		t.Errorf("an unknown type: %v", err)
	}
}

func TestInodeTimesInBothLayouts(t *testing.T) {
	for _, o := range []kt.PageCacheOptions{{}, {Timespec: true}} {
		f := kt.NewPageCacheFixture(o)
		sb, root := f.AddSuperBlock("ext4", "sda1", 8, 1)
		f.Mount(sb, 0, 0, f.InitNS)
		ctime := int64(9)
		if !o.Timespec {
			ctime |= 1 << 31
		}
		in := f.AddInode(sb, kt.InodeSpec{Mode: 0o100644, Ino: 20, Times: [3][2]int64{{10, 1}, {20, 1_000_000_000}, {30, ctime}}})
		f.Name(in, root, "f")
		ctx, _ := f.Context(t, nil)
		rows, err := pagecache.RunFiles(ctx)
		if err != nil {
			t.Fatal(err)
		}
		r := byPath(rows)["/f"]
		if !r.AccessedOK || !r.Accessed.Equal(time.Unix(10, 1)) {
			t.Errorf("%+v: accessed %v %v", o, r.Accessed, r.AccessedOK)
		}
		if r.ModifiedOK {
			t.Errorf("%+v: nanoseconds of 10^9 are not a time", o)
		}
		if !r.ChangedOK || !r.Changed.Equal(time.Unix(30, 9)) {
			t.Errorf("%+v: changed %v %v: I_CTIME_QUERIED is not part of the time", o, r.Changed, r.ChangedOK)
		}
	}
}

func TestDetachedAndForeignInodesAreCountedAndStrictFails(t *testing.T) {
	s := newScene(kt.PageCacheOptions{})
	f := s.f
	other := f.Alloc(kt.DSize)
	f.Mem.U64(other+kt.DParent, other)
	lost := f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o100644, Ino: 30})
	f.Name(lost, other, "lost")
	f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o100644, Ino: 31, ForeignSuper: s.tmpSB})
	ctx, diags := s.ctx(t, nil)
	rows, err := pagecache.RunFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.InodeNumber == 31 {
			t.Error("an inode that names another superblock is listed")
		}
		if r.InodeNumber == 30 && r.Path != "" {
			t.Errorf("a detached dentry gives the path %q", r.Path)
		}
	}
	joined := strings.Join(*diags, "\n")
	if !strings.Contains(joined, pagecache.ErrDetached.Error()) || !strings.Contains(joined, pagecache.ErrForeign.Error()) {
		t.Errorf("diagnostics %q", *diags)
	}
	ctx, _ = s.ctx(t, map[string]any{"strict": true})
	if _, err := pagecache.RunFiles(ctx); !errors.Is(err, pagecache.ErrStrict) {
		t.Errorf("strict: %v", err)
	}
}

func TestABrokenInodeListIsWalkedFromBothEnds(t *testing.T) {
	s := newScene(kt.PageCacheOptions{})
	first := s.passwd + kt.InSBList
	s.f.Mem.U64(s.link+kt.InSBList, first)
	ctx, diags := s.ctx(t, nil)
	rows, err := pagecache.RunFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 11 {
		t.Errorf("%d rows, want all 11", len(rows))
	}
	joined := strings.Join(*diags, "\n")
	if !strings.Contains(joined, "forward walk") || !strings.Contains(joined, "backward walk adds") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestListPagesByPathAndByInode(t *testing.T) {
	s := newScene(kt.PageCacheOptions{Folio: true})
	dir := t.TempDir()
	ctx, _ := s.ctx(t, map[string]any{pagecache.OptionListPagesFind: "/etc/passwd", pagecache.OptionListPagesDump: true,
		tools.OptionOutputDir: dir})
	rows, err := pagecache.RunListPages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	name := extract.Name{Kind: extract.KindInode, Scope: extract.Kernel, Width: 8, Addresses: []uint64{s.passwd & mask},
		Ext: extract.ExtBytes}.String()
	if len(rows) != 1 || rows[0].Index != 0 || rows[0].Flags != "PG_uptodate,PG_lru" || rows[0].File != name ||
		rows[0].MappingAddress != (s.passwd+kt.InData)&mask || rows[0].InodeAddress != s.passwd&mask {
		t.Fatalf("rows %+v", rows)
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 5000)
	copy(want, passwdText)
	if !bytes.Equal(data, want) {
		t.Errorf("content %d bytes, want the cached page and zeros to 5000", len(data))
	}
	ctx, _ = s.ctx(t, map[string]any{pagecache.OptionListPagesInode: s.note})
	if rows, err := pagecache.RunListPages(ctx); err != nil || len(rows) != 1 || rows[0].File != "" {
		t.Errorf("by inode: %+v, %v", rows, err)
	}
}

func TestListPagesRefusesBadTargets(t *testing.T) {
	s := newScene(kt.PageCacheOptions{})
	for _, c := range []struct {
		opts map[string]any
		want error
	}{
		{map[string]any{}, pagecache.ErrNoTarget},
		{map[string]any{pagecache.OptionListPagesFind: "/etc/passwd", pagecache.OptionListPagesInode: s.passwd}, pagecache.ErrTwoTargets},
		{map[string]any{pagecache.OptionListPagesFind: "/etc/passwd", pagecache.OptionListPagesDump: true}, pagecache.ErrNoOutputDir},
		{map[string]any{pagecache.OptionListPagesInode: s.root}, pagecache.ErrNotInode},
	} {
		ctx, _ := s.ctx(t, c.opts)
		if _, err := pagecache.RunListPages(ctx); !errors.Is(err, c.want) {
			t.Errorf("%v: %v, want %v", c.opts, err, c.want)
		}
	}
}

type member struct {
	h    *tar.Header
	data []byte
}

func readArchive(t *testing.T, b []byte) (map[string]member, []byte) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]member{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(tr)
		out[h.Name] = member{h, data}
	}
	return out, raw
}

func TestDumpFilesWritesAPOSIXArchive(t *testing.T) {
	s := newScene(kt.PageCacheOptions{Folio: true})
	ctx, diags := s.ctx(t, nil)
	var buf bytes.Buffer
	rows, err := pagecache.DumpFilesTo(ctx, &buf)
	if err != nil {
		t.Fatal(err)
	}
	got, raw := readArchive(t, buf.Bytes())
	if string(raw[257:263]) != "ustar\x00" || string(raw[263:265]) != "00" {
		t.Errorf("magic %q version %q, want the POSIX ustar ones", raw[257:263], raw[263:265])
	}
	want := map[string]byte{"ext4.8.1/": tar.TypeDir, "ext4.8.1/etc/": tar.TypeDir, "ext4.8.1/mnt/": tar.TypeDir,
		"ext4.8.1/etc/passwd": tar.TypeReg, "ext4.8.1/etc/sh": tar.TypeSymlink, "ext4.8.1/etc/long": tar.TypeSymlink,
		"ext4.8.1/etc/su": tar.TypeReg, "tmpfs.0.30/": tar.TypeDir, "tmpfs.0.30/note": tar.TypeReg}
	if len(got) != len(want) || len(rows) != len(want) {
		t.Errorf("%d members, %d rows, want %d (%q)", len(got), len(rows), len(want), *diags)
	}
	for name, typ := range want {
		if m, ok := got[name]; !ok || m.h.Typeflag != typ {
			t.Errorf("member %s missing or of type %c", name, m.h.Typeflag)
		}
	}
	if m := got["ext4.8.1/etc/passwd"]; len(m.data) != 5000 || !bytes.HasPrefix(m.data, passwdText) ||
		!m.h.ModTime.Equal(time.Unix(1600000000, 6)) {
		t.Errorf("passwd: %d bytes, mtime %v", len(m.data), m.h.ModTime)
	}
	if got["ext4.8.1/etc/sh"].h.Linkname != "/usr/bin/sh" || got["ext4.8.1/etc/long"].h.Linkname != "target" {
		t.Errorf("links %q %q", got["ext4.8.1/etc/sh"].h.Linkname, got["ext4.8.1/etc/long"].h.Linkname)
	}
	if m := got["ext4.8.1/etc/su"]; m.h.Mode != 0o755 {
		t.Errorf("su mode %o: set-user-ID is not carried", m.h.Mode)
	}
	for _, r := range rows {
		if r.Member == "ext4.8.1/etc/passwd" && (r.MemberSize != 5000 || r.RecoveredBytes != int64(kt.PageSize)) {
			t.Errorf("row %+v", r)
		}
	}
	if !strings.Contains(strings.Join(*diags, "\n"), pagecache.ErrNotCached.Error()) {
		t.Errorf("the uncached file is not reported: %q", *diags)
	}
}

func TestDumpFilesOptions(t *testing.T) {
	s := newScene(kt.PageCacheOptions{})
	ctx, _ := s.ctx(t, map[string]any{pagecache.OptionDumpFilesTmpfsOnly: true})
	var buf bytes.Buffer
	if _, err := pagecache.DumpFilesTo(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	got, _ := readArchive(t, buf.Bytes())
	for name := range got {
		if !strings.HasPrefix(name, "tmpfs.") {
			t.Errorf("tmpfs only: %s", name)
		}
	}
	ctx, _ = s.ctx(t, map[string]any{pagecache.OptionDumpFilesCompression: "xz"})
	if _, err := pagecache.DumpFilesTo(ctx, io.Discard); !errors.Is(err, pagecache.ErrCompression) {
		t.Errorf("xz: %v", err)
	}
	dir := t.TempDir()
	ctx, _ = s.ctx(t, map[string]any{tools.OptionOutputDir: dir})
	if _, err := pagecache.RunDumpFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, pagecache.ArchiveName)); err != nil {
		t.Error(err)
	}
	if _, err := pagecache.RunDumpFiles(ctx); !errors.Is(err, extract.ErrArtifactExists) {
		t.Errorf("a second run: %v", err)
	}
	ctx, _ = s.ctx(t, nil)
	if _, err := pagecache.RunDumpFiles(ctx); !errors.Is(err, pagecache.ErrNoOutputDir) {
		t.Errorf("no output directory: %v", err)
	}
}

// The scene's regular members are 5000, 4 and 3 bytes. The dump limit bounds
// each member and MaxArchiveBytes their sum (O8, follow-up D4).
func TestTheDumpLimitBoundsEachMemberAndTheArchiveLimitTheirSum(t *testing.T) {
	for _, c := range []struct {
		member, archive uint64
		want            error
		written         int
	}{
		{4999, 0, pagecache.ErrTooLarge, 2},
		{5007, 5004, pagecache.ErrArchiveFull, 2},
		{5000, 5007, nil, 3},
		{5000, 0, nil, 3},
	} {
		s := newScene(kt.PageCacheOptions{})
		run := func(strict bool) (tools.Context, *[]string) {
			ctx, diags := s.ctx(t, map[string]any{tools.OptionMaxDumpSize: c.member, "strict": strict})
			ctx.Limits = limits.Limits{MaxArchiveBytes: int64(c.archive)}
			return ctx, diags
		}
		ctx, diags := run(false)
		rows, err := pagecache.DumpFilesTo(ctx, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		written, total := 0, uint64(0)
		for _, r := range rows {
			if r.Type == pagecache.Regular {
				written++
				total += uint64(r.MemberSize)
			}
		}
		text := strings.Join(*diags, "\n")
		if written != c.written || c.archive > 0 && total > c.archive {
			t.Errorf("member %d, archive %d: %d regular members, %d bytes", c.member, c.archive, written, total)
		}
		for _, e := range []error{pagecache.ErrTooLarge, pagecache.ErrArchiveFull} {
			if strings.Contains(text, e.Error()) != (e == c.want) {
				t.Errorf("member %d, archive %d: diagnostics %q", c.member, c.archive, *diags)
			}
		}
		ctx, _ = run(true)
		if _, err := pagecache.DumpFilesTo(ctx, io.Discard); (err != nil) != (c.want != nil) {
			t.Errorf("member %d, archive %d, strict: %v", c.member, c.archive, err)
		}
	}
}

// With the default limits a member the size of MaxArtifactBytes still leaves
// the archive room for more: the default archive bound is the larger.
func TestTheDefaultArchiveLimitExceedsTheMemberLimit(t *testing.T) {
	if d := limits.Default(); d.MaxArchiveBytes <= d.MaxArtifactBytes {
		t.Errorf("MaxArchiveBytes %d, MaxArtifactBytes %d", d.MaxArchiveBytes, d.MaxArtifactBytes)
	}
}

func TestDumpFilesNeverWritesThroughASymlink(t *testing.T) {
	s := newScene(kt.PageCacheOptions{})
	f := s.f
	shD := f.Name(0, s.etcD, "sh")
	f.Alias(s.link, shD)
	evil := f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o100644, Ino: 40, Size: 3})
	f.Name(evil, shD, "evil")
	f.Cache(evil, 0, []byte("bad"))
	dup := f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o100644, Ino: 41, Size: 3})
	f.Name(dup, s.etcD, "passwd")
	f.Cache(dup, 0, []byte("new"))
	ctx, diags := s.ctx(t, nil)
	var buf bytes.Buffer
	if _, err := pagecache.DumpFilesTo(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	got, _ := readArchive(t, buf.Bytes())
	if _, ok := got["ext4.8.1/etc/sh/evil"]; ok {
		t.Error("a member under a symlink member")
	}
	dupName := "ext4.8.1/etc/passwd." + "0x" + strings.Repeat("0", 4) + strings.TrimPrefix(hex(dup&mask), "0x")
	if _, ok := got[dupName]; !ok {
		t.Errorf("no %s among %v", dupName, keys(got))
	}
	if !strings.Contains(strings.Join(*diags, "\n"), pagecache.ErrThroughLink.Error()) {
		t.Errorf("diagnostics %q", *diags)
	}
}

func hex(v uint64) string {
	const digits = "0123456789abcdef"
	var b []byte
	for v > 0 {
		b = append([]byte{digits[v&15]}, b...)
		v >>= 4
	}
	return "0x" + string(b)
}

func keys(m map[string]member) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestModeString(t *testing.T) {
	for mode, want := range map[uint64]string{
		0o100644: "-rw-r--r--", 0o040755: "drwxr-xr-x", 0o104755: "-rwsr-xr-x", 0o104644: "-rwSr--r--",
		0o102755: "-rwxr-sr-x", 0o041777: "drwxrwxrwt", 0o041776: "drwxrwxrwT", 0o120777: "lrwxrwxrwx",
		0o140755: "srwxr-xr-x", 0o020620: "crw--w----", 0o060660: "brw-rw----", 0o010644: "prw-r--r--",
		0o000644: "?rw-r--r--",
	} {
		if got := pagecache.ModeString(mode); got != want {
			t.Errorf("%o: %s, want %s", mode, got, want)
		}
	}
}

func TestSuperBlocksGiveTheirMounts(t *testing.T) {
	s := newScene(kt.PageCacheOptions{})
	other := s.f.Alloc(0x40)
	s.f.Mount(s.tmpSB, 0, 0, other)
	ctx, _ := s.ctx(t, nil)
	sbs, err := pagecache.SuperBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sbs) != 2 || sbs[1].FSType != "tmpfs" || sbs[1].ID != "tmpfs" || len(sbs[1].Views) != 1 ||
		sbs[1].Views[0] != (pagecache.View{Root: "/", Point: "/mnt", Init: true}) {
		t.Errorf("superblocks %+v", sbs)
	}
}

// S12 4.2 step 4: a root that another namespace's mount shows first is still
// shown through the initial namespace's mount.
func TestSharedRootShowsThroughTheInitialNamespace(t *testing.T) {
	s := newScene(kt.PageCacheOptions{})
	devSB, devRoot := s.f.AddSuperBlock("devtmpfs", "devtmpfs", 0, 6)
	s.f.Mount(devSB, 0, 0, s.f.Alloc(0x40))
	devD := s.f.Name(s.f.AddInode(s.rootSB, kt.InodeSpec{Mode: 0o040755, Ino: 18}), s.root, "dev")
	s.f.Mount(devSB, s.rootMnt, devD, s.f.InitNS)
	null := s.f.AddInode(devSB, kt.InodeSpec{Mode: 0o020666, Ino: 4})
	s.f.Name(null, devRoot, "null")
	ctx, _ := s.ctx(t, nil)
	sbs, err := pagecache.SuperBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sbs) != 3 || len(sbs[2].Views) != 1 || sbs[2].Views[0] != (pagecache.View{Root: "/", Point: "/dev", Init: true}) {
		t.Fatalf("superblocks %+v", sbs)
	}
	rows, err := pagecache.RunFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := byPath(rows)["/dev/null"]
	if !ok || r.MountPoint != "/dev" {
		t.Errorf("/dev/null: %+v (found %v)", r, ok)
	}
}
