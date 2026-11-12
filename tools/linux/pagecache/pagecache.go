// Package pagecache reads the Linux page cache (S12): the superblocks and
// their inodes, each inode's cached pages, and the files those pages rebuild.
package pagecache

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const (
	FilesName     = "linux.pagecache.list_files"
	ListPagesName = "linux.pagecache.list_pages"
	DumpFilesName = "linux.pagecache.dump_files"
)

const (
	OptionFilesType = "linux.pagecache.list_files.type"
	OptionFilesFind = "linux.pagecache.list_files.find"
)

var (
	ErrNoSuperBlocks = errors.New("pagecache: super_blocks is not in the symbol table")
	ErrWalk          = errors.New("pagecache: list walk did not come back to its head")
	ErrUnread        = errors.New("pagecache: structure does not read")
	ErrForeign       = errors.New("pagecache: inode names another super_block")
	ErrName          = errors.New("pagecache: dentry name is empty, too long or holds a separator")
	ErrPathSteps     = errors.New("pagecache: path is longer than Limits.MaxPathSteps")
	ErrDetached      = errors.New("pagecache: dentry chain ends at a root other than the super_block's")
	ErrStrict        = errors.New("pagecache: strict mode: the walk left objects out")
	ErrFileType      = errors.New("pagecache: file type not one of REG, DIR, LNK, CHR, BLK, FIFO, SOCK")
)

func init() {
	tools.MustRegister(
		tools.Spec{Name: FilesName, Description: "List the inodes the Linux kernel holds in memory, with path, " +
			"times and cached page count"},
		RunFilesAny,
	)
	tools.MustRegister(
		tools.Spec{Name: ListPagesName, Description: "List the cached pages of one Linux inode, given by " +
			OptionListPagesInode + " or " + OptionListPagesFind + "; " + OptionListPagesDump + " writes its content"},
		RunListPagesAny,
	)
	tools.MustRegister(
		tools.Spec{Name: DumpFilesName, Description: "Write the Linux page cache's directories, files and links " +
			"into a gzip-compressed POSIX tar archive in the output directory"},
		RunDumpFilesAny,
	)
}

type FileType string

// S12 V1: the S_IFMT values of include/uapi/linux/stat.h, named by their
// S_IF suffix.
const (
	Regular   FileType = "REG"
	Directory FileType = "DIR"
	Symlink   FileType = "LNK"
	CharDev   FileType = "CHR"
	BlockDev  FileType = "BLK"
	FIFO      FileType = "FIFO"
	Socket    FileType = "SOCK"
)

const (
	sIFMT   = 0o170000
	sIFSOCK = 0o140000
	sIFLNK  = 0o120000
	sIFREG  = 0o100000
	sIFBLK  = 0o060000
	sIFDIR  = 0o040000
	sIFCHR  = 0o020000
	sIFIFO  = 0o010000
)

func typeOf(mode uint64) FileType {
	switch mode & sIFMT {
	case sIFREG:
		return Regular
	case sIFDIR:
		return Directory
	case sIFLNK:
		return Symlink
	case sIFCHR:
		return CharDev
	case sIFBLK:
		return BlockDev
	case sIFIFO:
		return FIFO
	case sIFSOCK:
		return Socket
	}
	return ""
}

func ParseFileType(s string) (FileType, error) {
	t := FileType(strings.ToUpper(strings.TrimSpace(s)))
	switch t {
	case Regular, Directory, Symlink, CharDev, BlockDev, FIFO, Socket:
		return t, nil
	}
	return "", fmt.Errorf("%q: %w", s, ErrFileType)
}

// S12 V3: the POSIX ls long-format mode string; 's' for a socket is the
// common choice for the type POSIX leaves to the implementation.
func ModeString(mode uint64) string {
	var b [10]byte
	switch typeOf(mode) {
	case Directory:
		b[0] = 'd'
	case Symlink:
		b[0] = 'l'
	case CharDev:
		b[0] = 'c'
	case BlockDev:
		b[0] = 'b'
	case FIFO:
		b[0] = 'p'
	case Socket:
		b[0] = 's'
	case Regular:
		b[0] = '-'
	default:
		b[0] = '?'
	}
	const rwx = "rwx"
	for i := 0; i < 9; i++ {
		b[1+i] = '-'
		if mode&(1<<uint(8-i)) != 0 {
			b[1+i] = rwx[i%3]
		}
	}
	special := func(at int, bit uint64, set, unset byte) {
		if mode&bit == 0 {
			return
		}
		if b[at] == 'x' {
			b[at] = set
		} else {
			b[at] = unset
		}
	}
	special(3, 0o4000, 's', 'S')
	special(6, 0o2000, 's', 'S')
	special(9, 0o1000, 't', 'T')
	return string(b[:])
}

type File struct {
	SuperBlockAddress uint64
	FSType            string
	Device            string
	MountPoint        string
	InodeAddress      uint64
	InodeNumber       uint64
	Type              FileType
	Mode              string
	UID               uint32
	GID               uint32
	Size              int64
	Pages             uint64
	CachedPages       uint64
	Accessed          time.Time
	AccessedOK        bool
	Modified          time.Time
	ModifiedOK        bool
	Changed           time.Time
	ChangedOK         bool
	Path              string
}

type resolver struct {
	sym symbols.SymbolTable
	err error
}

func (v *resolver) fail(typ string, path []string, err error) {
	if v.err == nil {
		v.err = fmt.Errorf("pagecache: %s.%s: %w: %w", typ, strings.Join(path, "."), linuxwalk.ErrUnsupported, err)
	}
}

func (v *resolver) walk(typ string, path []string) (string, uint64, bool) {
	cur, off := typ, uint64(0)
	for i, name := range path[:len(path)-1] {
		f, err := v.sym.Field(cur, name)
		if err != nil || f.Type.IsPointer || f.Type.Name == "" {
			v.fail(typ, path[:i+1], err)
			return "", 0, false
		}
		cur, off = f.Type.Name, off+f.Offset
	}
	return cur, off, true
}

func (v *resolver) off(typ string, path ...string) uint64 {
	parent, base, ok := v.walk(typ, path)
	if !ok {
		return 0
	}
	f, err := v.sym.Field(parent, path[len(path)-1])
	if err != nil {
		v.fail(typ, path, err)
		return 0
	}
	return base + f.Offset
}

func (v *resolver) num(typ string, path ...string) symbols.IntField {
	parent, base, ok := v.walk(typ, path)
	if !ok {
		return symbols.IntField{}
	}
	f, err := symbols.ResolveIntField(v.sym, parent, path[len(path)-1])
	if err != nil {
		v.fail(typ, path, err)
		return symbols.IntField{}
	}
	f.Offset += base
	return f
}

func (v *resolver) size(typ string) uint64 {
	st, err := v.sym.Struct(typ)
	if err != nil || st.Size == 0 {
		v.fail(typ, []string{"(size)"}, err)
		return 0
	}
	return st.Size
}

func (v *resolver) has(typ, member string) bool {
	_, err := v.sym.Field(typ, member)
	return err == nil
}

type stamp struct {
	sec, nsec symbols.IntField
}

type shape struct {
	sbSize, sbType, sbRoot, sbInodes, sbMounts, sbID, sbIDLen uint64
	sbDev                                                     symbols.IntField
	fsName                                                    uint64

	iSize, iSB, iMapping, iDentry, iLink uint64
	iMode, iIno, iBytes, iUID, iGID      symbols.IntField
	times                                [3]stamp

	dSize, dParent, dName, dAlias uint64
	nameLen                       symbols.IntField

	mounts                                  bool
	mSize, mParent, mPoint, mRoot, mNS, mIn uint64
}

func resolve(sym symbols.SymbolTable) (shape, error) {
	v := &resolver{sym: sym}
	var s shape
	s.sbSize = v.size("super_block")
	s.sbDev = v.num("super_block", "s_dev")
	s.sbType = v.off("super_block", "s_type")
	s.sbRoot = v.off("super_block", "s_root")
	s.sbInodes = v.off("super_block", "s_inodes")
	s.sbMounts = v.off("super_block", "s_mounts")
	s.sbID = v.off("super_block", "s_id")
	if f, err := sym.Field("super_block", "s_id"); err == nil {
		s.sbIDLen = f.Type.ArrayLength
	}
	s.fsName = v.off("file_system_type", "name")

	s.iSize = v.size("inode")
	s.iSB = v.off("inode", "i_sb")
	s.iMapping = v.off("inode", "i_mapping")
	s.iDentry = v.off("inode", "i_dentry")
	s.iLink = v.off("inode", "i_link")
	s.iMode = v.num("inode", "i_mode")
	s.iIno = v.num("inode", "i_ino")
	s.iBytes = v.num("inode", "i_size")
	s.iUID = v.num("inode", "i_uid", "val")
	s.iGID = v.num("inode", "i_gid", "val")
	for n, name := range []string{"atime", "mtime", "ctime"} {
		if v.has("inode", "i_"+name+"_sec") {
			s.times[n] = stamp{sec: v.num("inode", "i_"+name+"_sec"), nsec: v.num("inode", "i_"+name+"_nsec")}
		} else {
			s.times[n] = stamp{sec: v.num("inode", "i_"+name, "tv_sec"), nsec: v.num("inode", "i_"+name, "tv_nsec")}
		}
	}

	s.dSize = v.size("dentry")
	s.dParent = v.off("dentry", "d_parent")
	s.dName = v.off("dentry", "d_name", "name")
	s.nameLen = v.num("dentry", "d_name", "len")
	s.dAlias = v.off("dentry", "d_u", "d_alias")
	if v.err != nil {
		return shape{}, v.err
	}

	m := &resolver{sym: sym}
	s.mSize = m.size("mount")
	s.mParent = m.off("mount", "mnt_parent")
	s.mPoint = m.off("mount", "mnt_mountpoint")
	s.mRoot = m.off("mount", "mnt", "mnt_root")
	s.mNS = m.off("mount", "mnt_ns")
	s.mIn = m.off("mount", "mnt_instance")
	s.mounts = m.err == nil
	return s, nil
}

type SuperBlock struct {
	Address uint64
	FSType  string
	Device  string
	Major   uint64
	Minor   uint64
	ID      string
	Root    uint64
	Views   []View
}

type View struct {
	Root  string
	Point string
	Init  bool
}

// viewOf gives the mount that shows rel and the path rel has under it: a
// mount of the initial namespace before any other, then the mount whose root
// is the deepest prefix of rel.
func (sb SuperBlock) viewOf(rel string) (View, string, bool) {
	for _, v := range sb.Views {
		if v.Root == "/" {
			return v, mountJoin(v.Point, rel), true
		}
		if rel == v.Root {
			return v, v.Point, true
		}
		if strings.HasPrefix(rel, v.Root+"/") {
			return v, mountJoin(v.Point, rel[len(v.Root):]), true
		}
	}
	return View{}, "", false
}

type losses struct {
	walks, unread, foreign, unnamed, detached, pages int
}

func (l losses) total() int {
	return l.walks + l.unread + l.foreign + l.unnamed + l.detached + l.pages
}

type model struct {
	k      *linuxkern.Kernel
	r      linuxwalk.Reader
	s      shape
	cache  *linuxobj.PageCache
	tool   string
	ctx    tools.Context
	initNS uint64
	lost   losses
	names  map[uint64]string
}

func open(ctx tools.Context, tool string) (*model, error) {
	if err := ctx.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	if k.PtrSize != 8 {
		return nil, fmt.Errorf("%s: %d-byte pointers: %w", tool, k.PtrSize, linuxwalk.ErrUnsupported)
	}
	s, err := resolve(k.Sym)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	r := k.Walker()
	la57 := ctx.PagingMode() == layers.ModeLA57.Name()
	cache, err := linuxobj.NewPageCache(r, ctx.PhysicalMemory(), la57)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	m := &model{k: k, r: r, s: s, cache: cache, tool: tool, ctx: ctx, names: map[uint64]string{}}
	m.initNS = m.initialNamespace()
	return m, nil
}

// S12 F11: init_mount_tree makes the initial mount namespace init_task's.
func (m *model) initialNamespace() uint64 {
	task, err := m.k.Symbol("init_task")
	if err != nil {
		return 0
	}
	v := &resolver{sym: m.k.Sym}
	proxy, ns := v.off("task_struct", "nsproxy"), v.off("nsproxy", "mnt_ns")
	if v.err != nil {
		return 0
	}
	b, ok := m.read(task+proxy, 8)
	if !ok {
		return 0
	}
	b, ok = m.read(m.ptr(b, 0)+ns, 8)
	if !ok {
		return 0
	}
	return m.ptr(b, 0)
}

func (m *model) diag(format string, args ...any) { m.ctx.AddDiagnostic(format, args...) }

func (m *model) form(v uint64) uint64 { return v & m.k.Mask }

func (m *model) read(addr, n uint64) ([]byte, bool) {
	if addr == 0 || n == 0 || addr+n < addr {
		return nil, false
	}
	b, err := m.k.Mem.ReadAt(addr, n)
	if err != nil || uint64(len(b)) < n {
		return nil, false
	}
	return b, true
}

func word(b []byte, off uint64) uint64 {
	if off > uint64(len(b)) || uint64(len(b))-off < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(b[off:])
}

func (m *model) ptr(b []byte, off uint64) uint64 { return m.form(word(b, off)) }

func decode(f symbols.IntField, b []byte) uint64 {
	v, err := f.Decode(b)
	if err != nil {
		return 0
	}
	return v
}

func signed(f symbols.IntField, b []byte) int64 {
	v := decode(f, b)
	if f.Width > 0 && f.Width < 8 && f.BitLength == 0 && v&(1<<(8*f.Width-1)) != 0 {
		v |= ^uint64(0) << (8 * f.Width)
	}
	return int64(v)
}

func (m *model) cString(addr, most uint64) (string, bool) {
	var out []byte
	for uint64(len(out)) < most {
		n := min(linuxobj.FrameSize-addr%linuxobj.FrameSize, most-uint64(len(out)))
		b, ok := m.read(addr, n)
		if !ok {
			return "", false
		}
		if i := slices.Index(b, 0); i >= 0 {
			return string(append(out, b[:i]...)), true
		}
		out, addr = append(out, b...), addr+n
	}
	return string(out), true
}

// list walks a list forward and, when the walk breaks, backward from the
// head as well: a list caught while it changed can break in one direction
// only, and the entries past the break are still linked from the other end.
func (m *model) list(what string, at, head uint64, container, member string) ([]uint64, error) {
	l, err := m.r.List(head, container, member, linuxwalk.Forward)
	if err != nil {
		return nil, err
	}
	if !l.Broken() {
		return l.Entries, nil
	}
	m.lost.walks++
	m.diag("%s: %s at %#x: %v", m.tool, what, at, fmt.Errorf("forward walk: %s at %#x: %w", l.End, l.At, ErrWalk))
	back, err := m.r.List(head, container, member, linuxwalk.Backward)
	if err != nil {
		return l.Entries, nil
	}
	seen := make(map[uint64]bool, len(l.Entries))
	for _, e := range l.Entries {
		seen[e] = true
	}
	var extra []uint64
	for _, e := range back.Entries {
		if !seen[e] {
			seen[e] = true
			extra = append(extra, e)
		}
	}
	slices.Reverse(extra)
	m.diag("%s: %s at %#x: the backward walk adds %d entries and ends because %s", m.tool, what, at, len(extra), back.End)
	return append(l.Entries, extra...), nil
}

const nameMax = 255

// S12 V2: s_dev splits into a 12-bit major and 20-bit minor (MINORBITS).
const minorBits = 20

func (m *model) superBlocks() ([]SuperBlock, error) {
	head, err := m.k.Symbol("super_blocks")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", m.tool, ErrNoSuperBlocks)
	}
	entries, err := m.list("super_blocks", head, head, "super_block", "s_list")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", m.tool, err)
	}
	var out []SuperBlock
	unborn := 0
	for _, at := range entries {
		b, ok := m.read(at, m.s.sbSize)
		if !ok {
			m.lost.unread++
			m.diag("%s: super_block at %#x: %v", m.tool, at, ErrUnread)
			continue
		}
		sb := SuperBlock{Address: at, Root: m.ptr(b, m.s.sbRoot)}
		if sb.Root == 0 {
			unborn++
			continue
		}
		dev := decode(m.s.sbDev, b)
		sb.Major, sb.Minor = dev>>minorBits, dev&(1<<minorBits-1)
		sb.Device = strconv.FormatUint(sb.Major, 10) + ":" + strconv.FormatUint(sb.Minor, 10)
		if t := m.ptr(b, m.s.sbType); t != 0 {
			if tb, ok := m.read(t+m.s.fsName, 8); ok {
				sb.FSType, _ = m.cString(m.form(word(tb, 0)), nameMax)
			}
		}
		if m.s.sbIDLen > 0 && m.s.sbID+m.s.sbIDLen <= uint64(len(b)) {
			id := b[m.s.sbID : m.s.sbID+m.s.sbIDLen]
			if i := slices.Index(id, 0); i >= 0 {
				id = id[:i]
			}
			sb.ID = string(id)
		}
		sb.Views = m.views(sb)
		out = append(out, sb)
	}
	if unborn > 0 {
		m.diag("%s: %d super_blocks have no root dentry and are skipped", m.tool, unborn)
	}
	return out, nil
}

// S12 F10: kern_mount marks internal mounts with MNT_NS_INTERNAL, ERR_PTR(-EINVAL).
const internalNS = 1<<64 - 22

func (m *model) views(sb SuperBlock) []View {
	if !m.s.mounts {
		return nil
	}
	mounts, err := m.list("s_mounts of super_block", sb.Address, sb.Address+m.s.sbMounts, "mount", "mnt_instance")
	if err != nil {
		return nil
	}
	var out []View
	seen := map[string]int{}
	for _, mnt := range mounts {
		b, ok := m.read(mnt, m.s.mSize)
		if !ok {
			continue
		}
		ns := m.ptr(b, m.s.mNS)
		if ns == 0 || ns == m.form(internalNS) {
			continue
		}
		root, err := m.pathIn(m.ptr(b, m.s.mRoot), sb.Root)
		if err != nil {
			continue
		}
		init := m.initNS != 0 && ns == m.initNS
		at, dup := seen[root]
		if dup && (out[at].Init || !init) {
			continue
		}
		p, ok := m.mountPath(mnt)
		if !ok {
			continue
		}
		// A root shared with another namespace's mount, such as devtmpfs at /
		// in the namespace of its own kernel thread, shows through the initial
		// namespace's mount where there is one.
		if dup {
			out[at] = View{Root: root, Point: p, Init: init}
			continue
		}
		seen[root] = len(out)
		out = append(out, View{Root: root, Point: p, Init: init})
	}
	slices.SortStableFunc(out, func(a, b View) int {
		if a.Init != b.Init {
			if a.Init {
				return -1
			}
			return 1
		}
		return len(b.Root) - len(a.Root)
	})
	return out
}

func (m *model) mountPath(mnt uint64) (string, bool) {
	var parts []string
	b, ok := m.read(mnt, m.s.mSize)
	if !ok {
		return "", false
	}
	d := m.ptr(b, m.s.mRoot)
	steps := m.ctx.Bounds().MaxPathSteps
	for range steps {
		if d == m.ptr(b, m.s.mRoot) {
			parent := m.ptr(b, m.s.mParent)
			if parent == mnt {
				return join(parts), true
			}
			d, mnt = m.ptr(b, m.s.mPoint), parent
			if b, ok = m.read(mnt, m.s.mSize); !ok {
				return "", false
			}
			continue
		}
		name, parent, err := m.dentryName(d)
		if err != nil || parent == d {
			return "", false
		}
		parts, d = append(parts, name), parent
	}
	return "", false
}

func join(reversed []string) string {
	if len(reversed) == 0 {
		return "/"
	}
	var sb strings.Builder
	for i := len(reversed) - 1; i >= 0; i-- {
		sb.WriteByte('/')
		sb.WriteString(reversed[i])
	}
	return sb.String()
}

// S12 F6: a root dentry is its own parent and has no name.
func (m *model) dentryName(d uint64) (string, uint64, error) {
	b, ok := m.read(d, m.s.dSize)
	if !ok {
		return "", 0, ErrUnread
	}
	parent := m.ptr(b, m.s.dParent)
	if parent == d {
		return "", d, nil
	}
	n := decode(m.s.nameLen, b)
	if n == 0 || n > nameMax {
		return "", 0, ErrName
	}
	raw, ok := m.read(m.ptr(b, m.s.dName), n)
	if !ok {
		return "", 0, ErrUnread
	}
	name := string(raw)
	if strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return "", 0, ErrName
	}
	return name, parent, nil
}

func (m *model) pathIn(d, root uint64) (string, error) {
	var parts []string
	var seen []uint64
	steps := m.ctx.Bounds().MaxPathSteps
	for range steps {
		if p, ok := m.names[d]; ok {
			return m.remember(seen, parts, p), nil
		}
		name, parent, err := m.dentryName(d)
		if err != nil {
			return "", err
		}
		if parent == d {
			if d != root {
				return "", ErrDetached
			}
			return m.remember(seen, parts, "/"), nil
		}
		seen, parts, d = append(seen, d), append(parts, name), parent
	}
	return "", ErrPathSteps
}

// remember caches the path of every dentry the walk passed through, so
// siblings share their parents' walk.
func (m *model) remember(seen []uint64, parts []string, top string) string {
	p := top
	for i := len(parts) - 1; i >= 0; i-- {
		if p == "/" {
			p = "/" + parts[i]
		} else {
			p = p + "/" + parts[i]
		}
		m.names[seen[i]] = p
	}
	return p
}

type inode struct {
	File
	Mapping uint64
	Link    uint64
	mode    uint64
	Rel     string
	Named   bool
}

func (m *model) inode(sb SuperBlock, at uint64) (inode, error) {
	b, ok := m.read(at, m.s.iSize)
	if !ok {
		return inode{}, ErrUnread
	}
	if m.ptr(b, m.s.iSB) != sb.Address {
		return inode{}, ErrForeign
	}
	mode := decode(m.s.iMode, b)
	in := inode{File: File{SuperBlockAddress: sb.Address, FSType: sb.FSType, Device: sb.Device,
		InodeAddress: at, InodeNumber: decode(m.s.iIno, b), Type: typeOf(mode), Mode: ModeString(mode),
		UID: uint32(decode(m.s.iUID, b)), GID: uint32(decode(m.s.iGID, b)), Size: signed(m.s.iBytes, b)},
		Mapping: m.ptr(b, m.s.iMapping), mode: mode}
	if in.Size > 0 {
		in.Pages = (uint64(in.Size) + linuxobj.FrameSize - 1) / linuxobj.FrameSize
	}
	if in.Type == Symlink {
		in.Link = m.ptr(b, m.s.iLink)
	}
	in.Accessed, in.AccessedOK = stampTime(m.s.times[0], b, false)
	in.Modified, in.ModifiedOK = stampTime(m.s.times[1], b, false)
	in.Changed, in.ChangedOK = stampTime(m.s.times[2], b, true)
	if in.Mapping != 0 {
		if n, err := m.cache.NrPages(in.Mapping); err == nil {
			in.CachedPages = n
		}
	}
	if first := m.ptr(b, m.s.iDentry); first != 0 {
		if first < m.s.dAlias {
			return in, ErrName
		}
		rel, err := m.pathIn(first-m.s.dAlias, sb.Root)
		if err != nil {
			return in, err
		}
		in.Rel, in.Named = rel, true
		in.Path = rel
		if v, p, ok := sb.viewOf(rel); ok {
			in.MountPoint, in.Path = v.Point, p
		}
	}
	return in, nil
}

func mountJoin(mount, rel string) string {
	switch {
	case mount == "/":
		return rel
	case rel == "/":
		return mount
	}
	return mount + rel
}

// S12 F4: the ctime nanoseconds carry I_CTIME_QUERIED in bit 31.
const ctimeQueried = 1 << 31

const nsPerSecond = 1_000_000_000

func stampTime(s stamp, b []byte, ctime bool) (time.Time, bool) {
	sec := signed(s.sec, b)
	nsec := decode(s.nsec, b)
	if ctime {
		nsec &^= ctimeQueried
	}
	if nsec >= nsPerSecond {
		return time.Time{}, false
	}
	return time.Unix(sec, int64(nsec)).UTC(), true
}

func (m *model) files(sbs []SuperBlock, visit func(SuperBlock, inode) bool) {
	for _, sb := range sbs {
		entries, err := m.list("s_inodes of super_block", sb.Address, sb.Address+m.s.sbInodes, "inode", "i_sb_list")
		if err != nil {
			m.lost.walks++
			m.diag("%s: s_inodes of super_block at %#x: %v", m.tool, sb.Address, err)
			continue
		}
		var counts [4]int
		for _, at := range entries {
			in, err := m.inode(sb, at)
			switch {
			case errors.Is(err, ErrUnread):
				counts[0]++
				continue
			case errors.Is(err, ErrForeign):
				counts[1]++
				continue
			case errors.Is(err, ErrDetached):
				counts[3]++
			case err != nil:
				counts[2]++
			}
			if !visit(sb, in) {
				return
			}
		}
		m.lost.unread += counts[0]
		m.lost.foreign += counts[1]
		m.lost.unnamed += counts[2]
		m.lost.detached += counts[3]
		for n, e := range []error{ErrUnread, ErrForeign, ErrName, ErrDetached} {
			if counts[n] > 0 {
				m.diag("%s: super_block at %#x: %d inodes: %v", m.tool, sb.Address, counts[n], e)
			}
		}
	}
}

func (m *model) strict() error {
	if m.ctx.StrictMode() && m.lost.total() > 0 {
		return fmt.Errorf("%s: %w", m.tool, ErrStrict)
	}
	return nil
}

func SuperBlocks(ctx tools.Context) ([]SuperBlock, error) {
	m, err := open(ctx, FilesName)
	if err != nil {
		return nil, err
	}
	return m.superBlocks()
}

func RunFilesAny(ctx tools.Context) (any, error) { return RunFiles(ctx) }

func RunFiles(ctx tools.Context) ([]File, error) {
	m, err := open(ctx, FilesName)
	if err != nil {
		return nil, err
	}
	raw, err := ctx.StringListOption(OptionFilesType)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FilesName, err)
	}
	var types []FileType
	for _, s := range raw {
		t, err := ParseFileType(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", FilesName, OptionFilesType, err)
		}
		types = append(types, t)
	}
	find, err := ctx.StringOption(OptionFilesFind)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FilesName, err)
	}
	sbs, err := m.superBlocks()
	if err != nil {
		return nil, err
	}
	var out []File
	m.files(sbs, func(_ SuperBlock, in inode) bool {
		if len(types) > 0 && !slices.Contains(types, in.Type) {
			return true
		}
		if find != "" && in.Path != find {
			return true
		}
		out = append(out, in.File)
		return true
	})
	if err := m.strict(); err != nil {
		return nil, err
	}
	return out, nil
}
