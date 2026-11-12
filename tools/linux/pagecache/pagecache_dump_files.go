package pagecache

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const (
	OptionDumpFilesTmpfsOnly   = "linux.pagecache.dump_files.tmpfs_only"
	OptionDumpFilesCompression = "linux.pagecache.dump_files.compression_format"
)

var ArchiveName = extract.Name{Kind: extract.KindPageCache, Scope: extract.Kernel, Ext: extract.ExtTarGzip}.String()

var (
	ErrArchiveFull  = errors.New("pagecache: file does not fit in what the archive limit leaves of the archive")
	ErrCompression  = errors.New("pagecache: compression format not available; only gz is written")
	ErrNoLinkTarget = errors.New("pagecache: symlink target neither at i_link nor in a cached page")
	ErrNotCached    = errors.New("pagecache: regular file has no cached page inside its size")
	ErrThroughLink  = errors.New("pagecache: member path runs through a symlink member")
)

type Recovered struct {
	File
	Member         string
	MemberSize     int64
	RecoveredBytes int64
}

func RunDumpFilesAny(ctx tools.Context) (any, error) { return RunDumpFiles(ctx) }

func RunDumpFiles(ctx tools.Context) ([]Recovered, error) {
	m, tmpfsOnly, err := openDump(ctx)
	if err != nil {
		return nil, err
	}
	dir, ok := ctx.OutputDir()
	if !ok {
		return nil, fmt.Errorf("%s: %w", DumpFilesName, ErrNoOutputDir)
	}
	f, err := extract.CreateNew(dir, ArchiveName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", DumpFilesName, err)
	}
	rows, werr := m.archive(f, tmpfsOnly)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, fmt.Errorf("%s: %w", DumpFilesName, errors.Join(werr, extract.RemoveArtifact(dir, ArchiveName)))
	}
	return rows, nil
}

func DumpFilesTo(ctx tools.Context, out io.Writer) ([]Recovered, error) {
	m, tmpfsOnly, err := openDump(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := m.archive(out, tmpfsOnly)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", DumpFilesName, err)
	}
	return rows, nil
}

func openDump(ctx tools.Context) (*model, bool, error) {
	m, err := open(ctx, DumpFilesName)
	if err != nil {
		return nil, false, err
	}
	tmpfsOnly, err := ctx.BoolOption(OptionDumpFilesTmpfsOnly)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", DumpFilesName, err)
	}
	format, err := ctx.StringOption(OptionDumpFilesCompression)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", DumpFilesName, err)
	}
	if format != "" && format != "gz" {
		return nil, false, fmt.Errorf("%s: %s %q: %w", DumpFilesName, OptionDumpFilesCompression, format, ErrCompression)
	}
	return m, tmpfsOnly, nil
}

type archiver struct {
	m       *model
	tw      *tar.Writer
	cap     uint64
	archive uint64
	total   uint64
	links   map[string]bool
	written map[string]bool
	prefix  map[string]bool
	out     []Recovered
	err     error
	skipped map[error]int
}

func (m *model) archive(w io.Writer, tmpfsOnly bool) ([]Recovered, error) {
	sbs, err := m.superBlocks()
	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(w)
	a := &archiver{m: m, tw: tar.NewWriter(gz), cap: m.ctx.DumpLimit(),
		archive: uint64(m.ctx.Bounds().MaxArchiveBytes), links: map[string]bool{},
		written: map[string]bool{}, prefix: map[string]bool{}, skipped: map[error]int{}}
	tops := topNames(sbs)
	if tmpfsOnly {
		var keep []SuperBlock
		for _, sb := range sbs {
			if sb.FSType == "tmpfs" {
				keep = append(keep, sb)
			}
		}
		sbs = keep
	}
	m.files(sbs, func(sb SuperBlock, in inode) bool {
		a.add(tops[sb.Address], in)
		return a.err == nil
	})
	for _, e := range []error{ErrNotCached, ErrNoLinkTarget, ErrTooLarge, ErrArchiveFull, ErrThroughLink} {
		if n := a.skipped[e]; n > 0 {
			m.diag("%s: %d inodes left out of the archive: %v", m.tool, n, e)
		}
	}
	m.lost.pages += a.skipped[ErrTooLarge] + a.skipped[ErrArchiveFull] + a.skipped[ErrThroughLink]
	err = errors.Join(a.err, a.tw.Close(), gz.Close())
	if err != nil {
		return nil, err
	}
	if err := m.strict(); err != nil {
		return nil, err
	}
	return a.out, nil
}

// topNames gives each superblock its archive directory, <fstype>.<major>.<minor>,
// and adds the superblock address when two would share a name.
func topNames(sbs []SuperBlock) map[uint64]string {
	out := map[uint64]string{}
	used := map[string]bool{}
	for _, sb := range sbs {
		fs := extract.Label(sb.FSType)
		if fs == "" {
			fs = "unknown"
		}
		name := fs + "." + strconv.FormatUint(sb.Major, 10) + "." + strconv.FormatUint(sb.Minor, 10)
		if used[name] {
			name += "." + fmt.Sprintf("0x%016x", sb.Address)
		}
		used[name] = true
		out[sb.Address] = name
	}
	return out
}

func (a *archiver) add(top string, in inode) {
	if !in.Named || in.Rel == "" {
		return
	}
	switch in.Type {
	case Directory, Regular, Symlink:
	default:
		return
	}
	member := top + in.Rel
	if in.Rel == "/" {
		member = top
	}
	if a.written[member] {
		member += "." + fmt.Sprintf("0x%016x", in.InodeAddress)
	}
	if err := a.safe(member, in.Type == Symlink); err != nil {
		a.skipped[err]++
		return
	}
	// The special bits are dropped so that an extracted file cannot carry
	// set-user-ID or set-group-ID onto the examiner's host.
	h := &tar.Header{Name: member, Mode: int64(in.mode & 0o777), Uid: int(in.UID), Gid: int(in.GID),
		Format: tar.FormatPAX, ModTime: time.Unix(0, 0).UTC()}
	if in.ModifiedOK {
		h.ModTime = in.Modified
	}
	if in.AccessedOK {
		h.AccessTime = in.Accessed
	}
	if in.ChangedOK {
		h.ChangeTime = in.Changed
	}
	row := Recovered{File: in.File, Member: member}
	switch in.Type {
	case Directory:
		h.Typeflag, h.Name = tar.TypeDir, member+"/"
		row.Member = h.Name
		a.err = a.tw.WriteHeader(h)
	case Symlink:
		target, err := a.m.linkTarget(in)
		if err != nil {
			a.skipped[ErrNoLinkTarget]++
			return
		}
		h.Typeflag, h.Linkname = tar.TypeSymlink, target
		a.err = a.tw.WriteHeader(h)
	case Regular:
		size := max(in.Size, 0)
		pages := a.m.pages(in)
		if len(pages) == 0 || pages[0].Index*linuxobj.FrameSize >= uint64(size) {
			a.skipped[ErrNotCached]++
			return
		}
		if uint64(size) > a.cap {
			a.skipped[ErrTooLarge]++
			return
		}
		// The archive has its own, larger bound: most of a member's bytes can
		// be the zeros of uncached holes, so one bound for both would drop
		// small files once a few large ones are written.
		if uint64(size) > a.archive-a.total {
			a.skipped[ErrArchiveFull]++
			return
		}
		h.Typeflag, h.Size = tar.TypeReg, size
		if a.err = a.tw.WriteHeader(h); a.err != nil {
			return
		}
		rec, err := a.m.content(a.tw, pages, size)
		if err != nil {
			a.err = err
			return
		}
		if rec.unread > 0 {
			a.m.lost.pages += rec.unread
			a.m.diag("%s: inode at %#x: %d page frames: %v", a.m.tool, in.InodeAddress, rec.unread, linuxobj.ErrFrameUnread)
		}
		a.total += uint64(size)
		row.MemberSize, row.RecoveredBytes = size, rec.fromCache
	}
	if a.err != nil {
		return
	}
	a.written[member] = true
	if in.Type == Symlink {
		a.links[member] = true
	}
	for p := member; ; {
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			break
		}
		p = p[:i]
		a.prefix[p] = true
	}
	a.out = append(a.out, row)
}

// safe refuses a member that an extractor would write through an earlier
// symlink member, and a symlink that would sit above an earlier member.
func (a *archiver) safe(member string, link bool) error {
	for p := member; ; {
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			break
		}
		p = p[:i]
		if a.links[p] {
			return ErrThroughLink
		}
	}
	if link && a.prefix[member] {
		return ErrThroughLink
	}
	return nil
}

// S12 F7, F8: a fast symlink keeps its target at i_link; otherwise the target
// is page 0 of the mapping, cut at i_size and at PAGE_SIZE - 1.
func (m *model) linkTarget(in inode) (string, error) {
	if in.Link != 0 {
		s, ok := m.cString(in.Link, uint64(m.ctx.Bounds().MaxNameBytes))
		if !ok {
			return "", ErrUnread
		}
		if s == "" {
			return "", ErrNoLinkTarget
		}
		return s, nil
	}
	for _, p := range m.pages(in) {
		if p.Index != 0 {
			continue
		}
		frame, err := m.cache.Frame(p)
		if err != nil {
			return "", err
		}
		n := min(uint64(max(in.Size, 0)), linuxobj.FrameSize-1)
		s := string(frame[:n])
		if i := strings.IndexByte(s, 0); i >= 0 {
			s = s[:i]
		}
		if s == "" {
			return "", ErrNoLinkTarget
		}
		return s, nil
	}
	return "", ErrNoLinkTarget
}
