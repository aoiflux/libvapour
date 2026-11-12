package pagecache

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const (
	OptionListPagesFind  = "linux.pagecache.list_pages.find"
	OptionListPagesInode = "linux.pagecache.list_pages.inode"
	OptionListPagesDump  = "linux.pagecache.list_pages.dump"
)

var (
	ErrNoTarget    = errors.New("pagecache: one of " + OptionListPagesInode + " or " + OptionListPagesFind + " is required")
	ErrTwoTargets  = errors.New("pagecache: " + OptionListPagesInode + " and " + OptionListPagesFind + " are exclusive")
	ErrNoOutputDir = errors.New("pagecache: " + tools.OptionOutputDir + " not set")
	ErrNotInode    = errors.New("pagecache: address is not an inode of a listed super_block")
	ErrTooLarge    = errors.New("pagecache: file is larger than the dump limit")
)

type Page struct {
	InodeAddress   uint64
	MappingAddress uint64
	PageAddress    uint64
	Physical       uint64
	Index          uint64
	Offset         uint64
	Flags          string
	File           string
}

func RunListPagesAny(ctx tools.Context) (any, error) { return RunListPages(ctx) }

func RunListPages(ctx tools.Context) ([]Page, error) {
	m, err := open(ctx, ListPagesName)
	if err != nil {
		return nil, err
	}
	find, err := ctx.StringOption(OptionListPagesFind)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ListPagesName, err)
	}
	addr, haveAddr, err := ctx.UintOption(OptionListPagesInode)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ListPagesName, err)
	}
	dump, err := ctx.BoolOption(OptionListPagesDump)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ListPagesName, err)
	}
	switch {
	case haveAddr && find != "":
		return nil, fmt.Errorf("%s: %w", ListPagesName, ErrTwoTargets)
	case !haveAddr && find == "":
		return nil, fmt.Errorf("%s: %w", ListPagesName, ErrNoTarget)
	}
	dir, haveDir := ctx.OutputDir()
	if dump && !haveDir {
		return nil, fmt.Errorf("%s: %w", ListPagesName, ErrNoOutputDir)
	}
	sbs, err := m.superBlocks()
	if err != nil {
		return nil, err
	}
	var targets []inode
	if find != "" {
		m.files(sbs, func(_ SuperBlock, in inode) bool {
			if in.Path == find {
				targets = append(targets, in)
			}
			return true
		})
		if len(targets) == 0 {
			m.diag("%s: no inode has the path %s", ListPagesName, find)
		}
	} else {
		in, err := m.inodeAt(sbs, m.form(addr))
		if err != nil {
			return nil, fmt.Errorf("%s: inode at %#x: %w", ListPagesName, m.form(addr), err)
		}
		targets = append(targets, in)
	}
	var out []Page
	for _, in := range targets {
		pages := m.pages(in)
		var file string
		if dump {
			file = m.dumpInode(dir, in, pages)
		}
		for _, p := range pages {
			out = append(out, Page{InodeAddress: in.InodeAddress, MappingAddress: in.Mapping, PageAddress: p.Address,
				Physical: p.Physical, Index: p.Index, Offset: p.Index * linuxobj.FrameSize,
				Flags: strings.Join(m.cache.FlagNames(p.Flags), ","), File: file})
		}
	}
	if err := m.strict(); err != nil {
		return nil, err
	}
	return out, nil
}

func (m *model) inodeAt(sbs []SuperBlock, at uint64) (inode, error) {
	b, ok := m.read(at, m.s.iSize)
	if !ok {
		return inode{}, ErrUnread
	}
	owner := m.ptr(b, m.s.iSB)
	for _, sb := range sbs {
		if sb.Address == owner {
			in, err := m.inode(sb, at)
			if errors.Is(err, ErrUnread) || errors.Is(err, ErrForeign) {
				return inode{}, err
			}
			if err != nil {
				m.diag("%s: inode at %#x: path: %v", m.tool, at, err)
			}
			return in, nil
		}
	}
	return inode{}, ErrNotInode
}

// Entries that fail S12 4.5 are reported once per mapping, not per entry.
func (m *model) pages(in inode) []linuxobj.CachedPage {
	if in.Mapping == 0 {
		return nil
	}
	mp, err := m.cache.Pages(in.Mapping, in.Pages)
	if err != nil {
		m.lost.pages++
		m.diag("%s: address_space at %#x: %v", m.tool, in.Mapping, err)
		return nil
	}
	t := mp.Tree
	if n := mp.Rejects.Total() + t.Unread + t.Inconsistent; n > 0 || mp.Capped || t.Capped {
		m.lost.pages += n
		m.diag("%s: address_space at %#x: %d entries left out (outside %d, misaligned %d, unread %d, "+
			"other mapping %d, wrong index %d, unread nodes %d, inconsistent nodes %d), capped %v",
			m.tool, in.Mapping, n, mp.Rejects.Outside, mp.Rejects.Misaligned, mp.Rejects.Unread, mp.Rejects.Foreign,
			mp.Rejects.Misplaced, t.Unread, t.Inconsistent, mp.Capped || t.Capped)
	}
	slices.SortStableFunc(mp.Pages, func(a, b linuxobj.CachedPage) int {
		switch {
		case a.Index < b.Index:
			return -1
		case a.Index > b.Index:
			return 1
		}
		return 0
	})
	return mp.Pages
}

type recovery struct {
	fromCache int64
	unread    int
}

// content writes exactly size bytes: cached pages at their offsets, zeros
// where no page is cached or a frame does not read.
func (m *model) content(w io.Writer, pages []linuxobj.CachedPage, size int64) (recovery, error) {
	var rec recovery
	zeros := make([]byte, linuxobj.FrameSize)
	var at int64
	fill := func(to int64) error {
		for at < to {
			n := min(to-at, int64(len(zeros)))
			if _, err := w.Write(zeros[:n]); err != nil {
				return err
			}
			at += n
		}
		return nil
	}
	for _, p := range pages {
		if p.Index > uint64(size)/linuxobj.FrameSize {
			break
		}
		off := int64(p.Index) * linuxobj.FrameSize
		if off < at || off >= size {
			continue
		}
		if err := fill(off); err != nil {
			return rec, err
		}
		frame, err := m.cache.Frame(p)
		if err != nil {
			rec.unread++
			continue
		}
		n := min(size-off, int64(len(frame)))
		if _, err := w.Write(frame[:n]); err != nil {
			return rec, err
		}
		at += n
		rec.fromCache += n
	}
	return rec, fill(size)
}

func (m *model) dumpInode(dir string, in inode, pages []linuxobj.CachedPage) string {
	name := extract.Name{Kind: extract.KindInode, Scope: extract.Kernel, Width: 8,
		Addresses: []uint64{in.InodeAddress}, Ext: extract.ExtBytes}.String()
	size := max(in.Size, 0)
	if uint64(size) > m.ctx.DumpLimit() {
		m.lost.pages++
		m.diag("%s: inode at %#x: %d bytes: %v", m.tool, in.InodeAddress, size, ErrTooLarge)
		return ""
	}
	f, err := extract.CreateNew(dir, name)
	if err != nil {
		m.diag("%s: inode at %#x: %v", m.tool, in.InodeAddress, err)
		return ""
	}
	rec, werr := m.content(f, pages, size)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		m.diag("%s: inode at %#x: write %s: %v", m.tool, in.InodeAddress, name, errors.Join(werr, extract.RemoveArtifact(dir, name)))
		return ""
	}
	if rec.unread > 0 {
		m.lost.pages += rec.unread
		m.diag("%s: inode at %#x: %d page frames: %v", m.tool, in.InodeAddress, rec.unread, linuxobj.ErrFrameUnread)
	}
	return name
}
