package kerntest

import (
	"sort"
	"testing"

	"github.com/aoiflux/libvapour/tools"
)

// S12 fixture: superblocks, inodes, dentries, mounts and a page cache over
// a struct page array, laid out as the S12 section 3 members say.

const (
	PCPageArray  = 0xffffea0000000000
	PCDirectMap  = 0xffff888000000000
	PCHeap       = 0xffff888100000000
	PCSuperList  = Data + 0x2000
	PCVmemmapVar = Data + 0x2100
	PCDirectVar  = Data + 0x2108
	PCInitTask   = Data + 0x3000
	PCPageSize   = 64
)

const (
	SBList   = 0x00
	SBDev    = 0x10
	SBType   = 0x28
	SBRoot   = 0x68
	SBID     = 0x80
	SBInodes = 0xa8
	SBMounts = 0xe0
	SBSize   = 0x100

	InMode    = 0x00
	InUID     = 0x04
	InGID     = 0x08
	InSB      = 0x28
	InMapping = 0x30
	InIno     = 0x40
	InSize    = 0x50
	InTimes   = 0x58
	InSBList  = 0x110
	InDentry  = 0x130
	InData    = 0x170
	InLink    = 0x1f0
	InodeSize = 0x200

	ASPages   = 0x08
	ASNrPages = 0x58

	DParent = 0x18
	DName   = 0x20
	DInode  = 0x30
	DAlias  = 0xb0
	DSize   = 0xc0

	MntParent   = 0x10
	MntPoint    = 0x18
	MntRoot     = 0x20
	MntInstance = 0x80
	MntNS       = 0xe8
	MntSize     = 0x160

	PgFlags   = 0x00
	PgHead    = 0x08
	PgMapping = 0x18
	PgIndex   = 0x20

	XANodeSlots = 0x28
	XANodeSize  = 0x228
)

type PageCacheOptions struct {
	Folio    bool
	Timespec bool
	NoDirect bool
	NoArray  bool
}

type PageCacheFixture struct {
	*Fixture
	Phys    *Memory
	Opts    PageCacheOptions
	InitNS  uint64
	heap    uint64
	pfn     uint64
	trees   map[uint64]map[uint64]uint64
	folios  map[uint64]map[uint64]uint
	sbRoots map[uint64]uint64
}

func NewPageCacheFixture(o PageCacheOptions) *PageCacheFixture {
	f := &PageCacheFixture{Fixture: NewFixture(0), Phys: NewMemory(), Opts: o, heap: PCHeap, pfn: 0x100,
		trees: map[uint64]map[uint64]uint64{}, folios: map[uint64]map[uint64]uint{}, sbRoots: map[uint64]uint64{}}
	addPageCacheTypes(f.Types, o)
	i := f.Types
	i.Symbol("super_blocks", PCSuperList, Struct("list_head"))
	if !o.NoArray {
		i.Symbol("vmemmap_base", PCVmemmapVar, Base("long unsigned int"))
	}
	if !o.NoDirect {
		i.Symbol("page_offset_base", PCDirectVar, Base("long unsigned int"))
	}
	i.Symbol("init_task", PCInitTask, Struct("task_struct"))
	f.Mem.U64(PCSuperList, PCSuperList)
	f.Mem.U64(PCSuperList+8, PCSuperList)
	f.Mem.U64(PCVmemmapVar, PCPageArray)
	f.Mem.U64(PCDirectVar, PCDirectMap)
	f.InitNS = f.Alloc(0x40)
	proxy := f.Alloc(0x40)
	f.Mem.U64(PCInitTask+0x10, proxy)
	f.Mem.U64(proxy+0x8, f.InitNS)
	return f
}

func addPageCacheTypes(i *Types, o PageCacheOptions) {
	ptr := func(n string) T { return Ptr(Struct(n)) }
	i.Struct("hlist_head", 8, map[string]F{"first": {0, ptr("hlist_node"), false}})
	i.Struct("hlist_node", 16, map[string]F{"next": {0, ptr("hlist_node"), false}, "pprev": {8, Ptr(ptr("hlist_node")), false}})
	i.Struct("file_system_type", 0x48, map[string]F{"name": {0, Ptr(Base("char")), false}})
	i.Struct("super_block", SBSize, map[string]F{
		"s_list": {SBList, Struct("list_head"), false}, "s_dev": {SBDev, Base("unsigned int"), false},
		"s_type": {SBType, ptr("file_system_type"), false}, "s_root": {SBRoot, ptr("dentry"), false},
		"s_id": {SBID, Arr(32, Base("char")), false}, "s_inodes": {SBInodes, Struct("list_head"), false},
		"s_mounts": {SBMounts, Struct("list_head"), false},
	})
	i.Struct("kuid_t", 4, map[string]F{"val": {0, Base("unsigned int"), false}})
	i.Struct("kgid_t", 4, map[string]F{"val": {0, Base("unsigned int"), false}})
	i.Struct("xarray", 16, map[string]F{"xa_flags": {4, Base("unsigned int"), false}, "xa_head": {8, Ptr(Void()), false}})
	i.Struct("xa_node", XANodeSize, map[string]F{
		"shift": {0, Base("unsigned char"), false}, "offset": {1, Base("unsigned char"), false},
		"parent": {8, ptr("xa_node"), false}, "array": {0x10, ptr("xarray"), false},
		"slots": {XANodeSlots, Arr(64, Ptr(Void())), false},
	})
	i.Struct("address_space", 0x60, map[string]F{
		"host": {0, ptr("inode"), false}, "i_pages": {ASPages, Struct("xarray"), false},
		"nrpages": {ASNrPages, Base("long unsigned int"), false},
	})
	inode := map[string]F{
		"i_mode": {InMode, Base("short unsigned int"), false}, "i_uid": {InUID, Struct("kuid_t"), false},
		"i_gid": {InGID, Struct("kgid_t"), false}, "i_sb": {InSB, ptr("super_block"), false},
		"i_mapping": {InMapping, ptr("address_space"), false}, "i_ino": {InIno, Base("long unsigned int"), false},
		"i_size": {InSize, Base("long long int"), false}, "i_sb_list": {InSBList, Struct("list_head"), false},
		"i_dentry": {InDentry, Struct("hlist_head"), false}, "i_data": {InData, Struct("address_space"), false},
		"i_link": {InLink, Ptr(Base("char")), false},
	}
	if o.Timespec {
		i.Struct("timespec64", 16, map[string]F{"tv_sec": {0, Base("long long int"), false}, "tv_nsec": {8, Base("long int"), false}})
		for n, name := range []string{"i_atime", "i_mtime", "i_ctime"} {
			inode[name] = F{InTimes + uint64(n)*16, Struct("timespec64"), false}
		}
	} else {
		for n, name := range []string{"atime", "mtime", "ctime"} {
			inode["i_"+name+"_sec"] = F{InTimes + uint64(n)*8, Base("long long int"), false}
			inode["i_"+name+"_nsec"] = F{InTimes + 0x18 + uint64(n)*4, Base("unsigned int"), false}
		}
	}
	i.Struct("inode", InodeSize, inode)
	i.Struct("qstr", 16, map[string]F{"len": {4, Base("unsigned int"), false}, "name": {8, Ptr(Base("unsigned char")), false}})
	i.Union("dentry_d_u", 16, map[string]F{"d_alias": {0, Struct("hlist_node"), false}})
	i.Struct("dentry", DSize, map[string]F{
		"d_parent": {DParent, ptr("dentry"), false}, "d_name": {DName, Struct("qstr"), false},
		"d_inode": {DInode, ptr("inode"), false}, "d_u": {DAlias, Union("dentry_d_u"), false},
	})
	i.Struct("vfsmount", 32, map[string]F{"mnt_root": {0, ptr("dentry"), false}, "mnt_sb": {8, ptr("super_block"), false}})
	i.Struct("mount", MntSize, map[string]F{
		"mnt_parent": {MntParent, ptr("mount"), false}, "mnt_mountpoint": {MntPoint, ptr("dentry"), false},
		"mnt": {MntRoot, Struct("vfsmount"), false}, "mnt_instance": {MntInstance, Struct("list_head"), false},
		"mnt_ns": {MntNS, ptr("mnt_namespace"), false},
	})
	i.Struct("mnt_namespace", 0x40, map[string]F{"root": {0x18, ptr("mount"), false}})
	i.Struct("nsproxy", 0x40, map[string]F{"mnt_ns": {8, ptr("mnt_namespace"), false}})
	i.Struct("task_struct", 0x100, map[string]F{"nsproxy": {0x10, ptr("nsproxy"), false}})
	page := map[string]F{
		"flags": {PgFlags, Base("long unsigned int"), false}, "compound_head": {PgHead, Base("long unsigned int"), false},
		"mapping": {PgMapping, ptr("address_space"), false},
	}
	if o.Folio {
		page["__folio_index"] = F{PgIndex, Base("long unsigned int"), false}
		i.Struct("folio", 4*PCPageSize, map[string]F{
			"flags": {PgFlags, Base("long unsigned int"), false}, "mapping": {PgMapping, ptr("address_space"), false},
			"index": {PgIndex, Base("long unsigned int"), false},
		})
	} else {
		page["index"] = F{PgIndex, Base("long unsigned int"), false}
	}
	i.Struct("page", PCPageSize, page)
	i.Enum("pageflags", 4, "unsigned int", map[string]int64{
		"PG_locked": 0, "PG_referenced": 2, "PG_uptodate": 3, "PG_lru": 5, "PG_head": 6,
		"PG_owner_priv_1": 10, "PG_checked": 10, "__NR_PAGEFLAGS": 25,
	})
}

func (f *PageCacheFixture) Alloc(n uint64) uint64 {
	at := f.heap
	f.heap += (n + 0x3f) &^ 0x3f
	f.Mem.Map(at, n)
	return at
}

// Link adds node at the tail of the list at head.
func (f *PageCacheFixture) Link(head, node uint64) {
	if f.read64(head) == 0 {
		f.Mem.U64(head, head)
		f.Mem.U64(head+8, head)
	}
	f.link(head, node)
}

func (f *PageCacheFixture) str(s string) uint64 {
	at := f.Alloc(uint64(len(s)) + 1)
	f.Mem.Str(at, s)
	return at
}

// AddSuperBlock adds a superblock with a root directory and gives the
// superblock and its root dentry.
func (f *PageCacheFixture) AddSuperBlock(fsType, id string, major, minor uint32) (uint64, uint64) {
	sb := f.Alloc(SBSize)
	fs := f.Alloc(0x48)
	f.Mem.U64(fs, f.str(fsType))
	f.Mem.U64(sb+SBType, fs)
	f.Mem.U32(sb+SBDev, major<<20|minor)
	f.Mem.Str(sb+SBID, id)
	f.Mem.U64(sb+SBInodes, sb+SBInodes)
	f.Mem.U64(sb+SBInodes+8, sb+SBInodes)
	f.Mem.U64(sb+SBMounts, sb+SBMounts)
	f.Mem.U64(sb+SBMounts+8, sb+SBMounts)
	f.link(PCSuperList, sb+SBList)
	root := f.Alloc(DSize)
	f.Mem.U64(root+DParent, root)
	f.Mem.U32(root+DName+4, 1)
	f.Mem.U64(root+DName+8, f.str("/"))
	f.Mem.U64(sb+SBRoot, root)
	f.sbRoots[sb] = root
	dir := f.AddInode(sb, InodeSpec{Mode: 0o040755, Ino: 2})
	f.Alias(dir, root)
	return sb, root
}

type InodeSpec struct {
	Mode, Ino    uint64
	Size         int64
	UID, GID     uint32
	Times        [3][2]int64
	Link         string
	NoMapping    bool
	ForeignSuper uint64
}

func (f *PageCacheFixture) AddInode(sb uint64, s InodeSpec) uint64 {
	in := f.Alloc(InodeSize)
	m := f.Mem
	m.U16(in+InMode, uint16(s.Mode))
	m.U32(in+InUID, s.UID)
	m.U32(in+InGID, s.GID)
	owner := sb
	if s.ForeignSuper != 0 {
		owner = s.ForeignSuper
	}
	m.U64(in+InSB, owner)
	m.U64(in+InIno, s.Ino)
	m.U64(in+InSize, uint64(s.Size))
	for n, t := range s.Times {
		if f.Opts.Timespec {
			m.U64(in+InTimes+uint64(n)*16, uint64(t[0]))
			m.U64(in+InTimes+uint64(n)*16+8, uint64(t[1]))
		} else {
			m.U64(in+InTimes+uint64(n)*8, uint64(t[0]))
			m.U32(in+InTimes+0x18+uint64(n)*4, uint32(t[1]))
		}
	}
	if !s.NoMapping {
		m.U64(in+InMapping, in+InData)
		m.U64(in+InData, in)
	}
	if s.Link != "" {
		m.U64(in+InLink, f.str(s.Link))
	}
	f.link(sb+SBInodes, in+InSBList)
	return in
}

// Name adds a dentry called name under parent for inode and gives it.
func (f *PageCacheFixture) Name(inode, parent uint64, name string) uint64 {
	d := f.Alloc(DSize)
	f.Mem.U64(d+DParent, parent)
	f.Mem.U32(d+DName+4, uint32(len(name)))
	f.Mem.U64(d+DName+8, f.str(name))
	if inode != 0 {
		f.Alias(inode, d)
	}
	return d
}

// Alias puts dentry d at the head of the inode's i_dentry list.
func (f *PageCacheFixture) Alias(inode, d uint64) {
	f.Mem.U64(d+DInode, inode)
	old := f.read64(inode + InDentry)
	f.Mem.U64(d+DAlias, old)
	f.Mem.U64(d+DAlias+8, inode+InDentry)
	if old != 0 {
		f.Mem.U64(old+8, d+DAlias)
	}
	f.Mem.U64(inode+InDentry, d+DAlias)
}

// Mount mounts sb at mountpoint under parent in namespace ns; a zero parent
// makes the mount its own parent, the root of its namespace.
func (f *PageCacheFixture) Mount(sb, parent, mountpoint, ns uint64) uint64 {
	mnt := f.Alloc(MntSize)
	if parent == 0 {
		parent, mountpoint = mnt, f.sbRoots[sb]
	}
	f.Mem.U64(mnt+MntParent, parent)
	f.Mem.U64(mnt+MntPoint, mountpoint)
	f.Mem.U64(mnt+MntRoot, f.sbRoots[sb])
	f.Mem.U64(mnt+MntRoot+8, sb)
	f.Mem.U64(mnt+MntNS, ns)
	f.link(sb+SBMounts, mnt+MntInstance)
	return mnt
}

func (f *PageCacheFixture) SuperOf(inode uint64) uint64 { return f.read64(inode + InSB) }

func (f *PageCacheFixture) PageAt(pfn uint64) uint64 { return PCPageArray + pfn*PCPageSize }

// Cache puts data at index of the inode's page cache, as one page of a new
// frame, and gives the struct page.
func (f *PageCacheFixture) Cache(inode, index uint64, data []byte) uint64 {
	return f.CacheFolio(inode, index, 0, data)
}

// CacheFolio puts a folio of 2^order pages at index, in consecutive frames.
func (f *PageCacheFixture) CacheFolio(inode, index uint64, order uint, data []byte) uint64 {
	mapping := inode + InData
	n := uint64(1) << order
	head := f.PageAt(f.pfn)
	for j := uint64(0); j < n; j++ {
		pfn := f.pfn + j
		page := f.PageAt(pfn)
		f.Mem.Map(page, PCPageSize)
		frame := make([]byte, PageSize)
		if lo := j * PageSize; lo < uint64(len(data)) {
			copy(frame, data[lo:])
		}
		f.Phys.Write(pfn*PageSize, frame)
		if !f.Opts.NoDirect {
			f.Mem.Write(PCDirectMap+pfn*PageSize, frame)
		}
		if j == 0 {
			f.Mem.U64(page+PgFlags, 1<<3|1<<5)
			f.Mem.U64(page+PgMapping, mapping)
			f.Mem.U64(page+PgIndex, index)
			if order > 0 {
				f.Mem.U64(page+PgFlags, 1<<3|1<<5|1<<6)
			}
		} else {
			f.Mem.U64(page+PgHead, head+1)
		}
	}
	f.pfn += n
	f.SetEntry(inode, index, head)
	if order > 0 {
		if f.folios[mapping] == nil {
			f.folios[mapping] = map[uint64]uint{}
		}
		f.folios[mapping][index] = order
	}
	f.Mem.U64(mapping+ASNrPages, f.read64(mapping+ASNrPages)+n)
	return head
}

// SetEntry stores a raw entry in the inode's page cache tree.
func (f *PageCacheFixture) SetEntry(inode, index, entry uint64) {
	mapping := inode + InData
	if f.trees[mapping] == nil {
		f.trees[mapping] = map[uint64]uint64{}
	}
	f.trees[mapping][index] = entry
}

// build writes every tree: one entry at index 0 sits in xa_head, anything
// else in a shift-0 node, or a shift-6 node over shift-0 nodes past 64.
func (f *PageCacheFixture) build() {
	for mapping, entries := range f.trees {
		root := mapping + ASPages
		if len(entries) == 1 && f.folios[mapping] == nil {
			if e, ok := entries[0]; ok {
				f.Mem.U64(root+8, e)
				continue
			}
		}
		top := uint64(0)
		for idx := range entries {
			top = max(top, idx)
		}
		if top < 64 {
			node := f.node(0, 0, 0, root)
			f.fill(node, mapping, entries, 0)
			f.Mem.U64(root+8, node|2)
			continue
		}
		parent := f.node(6, 0, 0, root)
		children := map[uint64]map[uint64]uint64{}
		for idx, e := range entries {
			hi := idx >> 6
			if children[hi] == nil {
				children[hi] = map[uint64]uint64{}
			}
			children[hi][idx] = e
		}
		his := make([]uint64, 0, len(children))
		for hi := range children {
			his = append(his, hi)
		}
		sort.Slice(his, func(a, b int) bool { return his[a] < his[b] })
		for _, hi := range his {
			child := f.node(0, hi, parent, root)
			f.fill(child, mapping, children[hi], hi<<6)
			f.Mem.U64(parent+XANodeSlots+hi*8, child|2)
		}
		f.Mem.U64(root+8, parent|2)
	}
}

func (f *PageCacheFixture) node(shift, offset, parent, array uint64) uint64 {
	n := f.Alloc(XANodeSize)
	f.Mem.U8(n, uint8(shift))
	f.Mem.U8(n+1, uint8(offset))
	f.Mem.U64(n+8, parent)
	f.Mem.U64(n+0x10, array)
	return n
}

func (f *PageCacheFixture) fill(node, mapping uint64, entries map[uint64]uint64, base uint64) {
	for idx, e := range entries {
		slot := idx - base
		f.Mem.U64(node+XANodeSlots+slot*8, e)
		if order, ok := f.folios[mapping][idx]; ok {
			for j := uint64(1); j < 1<<order && slot+j < 64; j++ {
				f.Mem.U64(node+XANodeSlots+(slot+j)*8, slot<<2|2)
			}
		}
	}
}

func (f *PageCacheFixture) Context(t testing.TB, opts map[string]any) (tools.Context, *[]string) {
	t.Helper()
	f.build()
	all := map[string]any{tools.OptionPhysicalMemory: f.Phys}
	if v, ok := opts[tools.OptionPhysicalMemory]; ok && v == nil {
		delete(all, tools.OptionPhysicalMemory)
	}
	for k, v := range opts {
		if k != tools.OptionPhysicalMemory || v != nil {
			all[k] = v
		}
	}
	return f.Fixture.Context(t, all)
}
