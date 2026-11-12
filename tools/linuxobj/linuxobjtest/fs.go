package linuxobjtest

import (
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

// File system layouts (S80 3.3). Fixed means the header sets the offset on
// x86-64 with no lock debugging; placed means declaration order over the
// declared members only.
const (
	FSTaskFS    = 0xf0
	FSTaskFiles = 0xf8

	// mm_struct, include/linux/mm_types.h v4.19: mmap fixed, the rest placed
	// after mm_rb and vmacache_seqnum; the size covers exe_file (S61b) and
	// the maple tree members the memoryranges test adds at 0xa0 to 0xb4.
	FSMMMmap       = 0x00
	FSMMPgd        = 0x18
	FSMMStartBrk   = 0x20
	FSMMBrk        = 0x28
	FSMMStartStack = 0x30
	FSMMContext    = 0x58
	FSMMArgStart   = 0x38
	FSMMArgEnd     = 0x40
	FSMMEnvStart   = 0x48
	FSMMEnvEnd     = 0x50
	FSMMSize       = 0xb8

	// vm_area_struct, include/linux/mm_types.h v4.19, fixed.
	FSVMAStart = 0x00
	FSVMAEnd   = 0x08
	FSVMAMM    = 0x40
	FSVMAFlags = 0x50
	FSVMAPgoff = 0x98
	FSVMAFile  = 0xa0
	FSVMANext  = 0x10
	FSVMASize  = 0xb0

	// struct file, include/linux/fs.h v6.17, fixed with CONFIG_SECURITY and
	// CONFIG_EPOLL.
	FSFileInode = 0x20
	FSFilePath  = 0x40
	FSFileSize  = 0xb8

	// fs_struct (v4.19 and v6.17), files_struct and fdtable (v4.19 and
	// v6.17), fixed; files_struct is sized to the end of fdtab.
	FSStructRoot = 0x18
	FSStructSize = 0x38

	FSFilesFdt  = 0x20
	FSFilesSize = 0x60
	FSFdtMaxFDs = 0x00
	FSFdtFD     = 0x08
	FSFdtSize   = 0x38

	// dentry, include/linux/dcache.h v4.19 to v6.17: fixed to d_inode,
	// d_op, d_fsdata, d_child and d_subdirs (v4.19 order) placed after it;
	// the linuxobj files test reads d_fsdata right after d_op.
	FSDentHash   = 0x08
	FSDentParent = 0x18
	FSDentName   = 0x20
	FSDentInode  = 0x30
	FSDentOp     = 0x38
	FSDentChild  = 0x48
	FSDentSubdir = 0x58
	FSDentSize   = 0x68
	FSQstrLen    = 0x04
	FSQstrName   = 0x08

	// inode, include/linux/fs.h v6.1: i_mode fixed, the rest placed after
	// i_flags; i_private, the last, sits where the linuxobj files test
	// writes it, 0x200.
	FSInodeMode    = 0x00
	FSInodeSB      = 0x10
	FSInodeMapping = 0x18
	FSInodeIno     = 0x20
	FSInodeNlink   = 0x28
	FSInodeSizeOff = 0x30
	FSInodeATime   = 0x38
	FSInodeMTime   = 0x48
	FSInodeCTime   = 0x58
	FSInodeLink    = 0x70
	FSInodeCount   = 0x68
	FSInodeSize    = 0x208

	// super_block, include/linux/fs.h v4.19 and v6.17: fixed to s_root,
	// s_uuid and s_subtype placed after it.
	FSSBDev     = 0x10
	FSSBFlags   = 0x50
	FSSBType    = 0x28
	FSSBRoot    = 0x68
	FSSBSubtype = 0x80
	FSSBUUID    = 0x70
	FSSBSize    = 0x88

	// vfsmount, include/linux/mount.h v6.17, fixed.
	FSVfsRoot  = 0x00
	FSVfsSB    = 0x08
	FSVfsFlags = 0x10
	FSVfsSize  = 0x20

	// mount, fs/mount.h v6.17: fixed to the mnt_node union, the rest placed.
	FSMntParent     = 0x10
	FSMntMountpoint = 0x18
	FSMntVfs        = 0x20
	FSMntDevname    = 0x58
	FSMntList       = 0x60
	FSMntID         = 0x90
	FSMntGroupID    = 0x94
	FSMntMaster     = 0x80
	FSMntNS         = 0x88
	FSMntShare      = 0x70
	FSMntNode       = 0x40
	FSMntSize       = 0x98

	// mnt_namespace: ns first (fs/mount.h v6.17), then list, the v4.19
	// member, placed; the size covers the seq the linuxobj files test adds
	// at 0x30. FSNSInum is ns.inum from the start of the namespace.
	FSNSInum = 0x10
	FSNSList = 0x18
	FSNSSize = 0x38

	// nsproxy, include/linux/nsproxy.h v6.17, fixed.
	FSNsproxyMntNS = 0x18

	// address_space.nrpages placed after i_pages; struct page,
	// include/linux/mm_types.h v4.19 and v6.17, fixed (64 bytes).
	FSAddrSpaceNrpages = 0x18
	FSPageFlags        = 0x00
	FSPageMapping      = 0x18
	FSPageIndex        = 0x20
	FSPageStructSize   = 0x40
)

const (
	fileOp           = 0x08
	dentFsdata       = 0x40
	dentOpsDname     = 0x48
	dentOpsSize      = 0x68
	inodePrivate     = 0x200
	nsCommonSize     = 0x18
	nsCommonInum     = 0x10
	mntNamespaceNS   = 0x00
	fsTypeSize       = 0x08
	pathSize         = 0x10
	timespecSize     = 0x10
	mmContextSize    = 0x08
	rbNodeSize       = 0x18
	fdtableSlotWidth = 8
)

// declareFileTypes declares the records AddFS and AddNetTypes share, at one
// layout, so either may come first.
func declareFileTypes(k *Kernel) {
	t := k.Table
	u64 := scalar("long long unsigned int")
	filep := ptr("file")
	t.AddStruct(symbols.StructType{Name: "path", Size: pathSize, Fields: []symbols.Field{
		field("mnt", 0, ptr("vfsmount")), field("dentry", 8, ptr("dentry")),
	}})
	t.AddStruct(symbols.StructType{Name: "file", Size: FSFileSize, Fields: []symbols.Field{
		field("f_op", fileOp, ptr("file_operations")), field("f_inode", FSFileInode, ptr("inode")),
		field("f_path", FSFilePath, scalar("path")),
	}})
	t.AddStruct(symbols.StructType{Name: "files_struct", Size: FSFilesSize, Fields: []symbols.Field{
		field("fdt", FSFilesFdt, ptr("fdtable")),
	}})
	t.AddStruct(symbols.StructType{Name: "fdtable", Size: FSFdtSize, Fields: []symbols.Field{
		field("max_fds", FSFdtMaxFDs, scalar("unsigned int")),
		field("fd", FSFdtFD, symbols.TypeRef{Name: "file", IsPointer: true, Element: &filep}),
	}})
	t.AddStruct(symbols.StructType{Name: "hlist_bl_node", Size: 0x10, Fields: []symbols.Field{
		field("next", 0, ptr("hlist_bl_node")), field("pprev", 8, ptr("hlist_bl_node")),
	}})
	t.AddStruct(symbols.StructType{Name: "qstr", Size: 0x10, Fields: []symbols.Field{
		field("hash", 0, scalar("unsigned int")), field("len", FSQstrLen, scalar("unsigned int")),
		field("name", FSQstrName, ptr("unsigned char")),
	}})
	t.AddStruct(symbols.StructType{Name: "dentry", Size: FSDentSize, Fields: []symbols.Field{
		field("d_hash", FSDentHash, scalar("hlist_bl_node")), field("d_parent", FSDentParent, ptr("dentry")),
		field("d_name", FSDentName, scalar("qstr")), field("d_inode", FSDentInode, ptr("inode")),
		field("d_op", FSDentOp, ptr("dentry_operations")), field("d_fsdata", dentFsdata, voidPtr()),
		field("d_child", FSDentChild, scalar("list_head")), field("d_subdirs", FSDentSubdir, scalar("list_head")),
	}})
	t.AddStruct(symbols.StructType{Name: "dentry_operations", Size: dentOpsSize, Fields: []symbols.Field{
		field("d_dname", dentOpsDname, voidPtr()),
	}})
	t.AddStruct(symbols.StructType{Name: "inode", Size: FSInodeSize, Fields: []symbols.Field{
		field("i_mode", FSInodeMode, scalar("unsigned short")), field("i_sb", FSInodeSB, ptr("super_block")),
		field("i_mapping", FSInodeMapping, ptr("address_space")), field("i_ino", FSInodeIno, u64),
		field("i_nlink", FSInodeNlink, scalar("unsigned int")), field("i_size", FSInodeSizeOff, scalar("long long int")),
		field("i_atime", FSInodeATime, scalar("timespec64")), field("i_mtime", FSInodeMTime, scalar("timespec64")),
		field("i_ctime", FSInodeCTime, scalar("timespec64")), field("i_count", FSInodeCount, scalar("atomic_t")),
		field("i_link", FSInodeLink, ptr("char")), field("i_private", inodePrivate, voidPtr()),
	}})
	t.AddStruct(symbols.StructType{Name: "timespec64", Size: timespecSize, Fields: []symbols.Field{
		field("tv_sec", 0, scalar("long long int")), field("tv_nsec", 8, scalar("long int")),
	}})
	t.AddStruct(symbols.StructType{Name: "atomic_t", Size: 4, Fields: []symbols.Field{field("counter", 0, scalar("int"))}})
	t.AddStruct(symbols.StructType{Name: "ns_common", Size: nsCommonSize, Fields: []symbols.Field{
		field("stashed", 0, ptr("dentry")), field("ops", 8, voidPtr()), field("inum", nsCommonInum, scalar("unsigned int")),
	}})
	k.addFields("task_struct", TaskSize, field("files", FSTaskFiles, ptr("files_struct")))
}

// AddFS declares the task, memory, file, dentry, inode, superblock and mount
// types of S39 and S46, and the PID types.
func AddFS(k *Kernel) {
	AddPIDTypes(k)
	declareFileTypes(k)
	t := k.Table
	u64 := scalar("long long unsigned int")
	k.addFields("task_struct", TaskSize, field("fs", FSTaskFS, ptr("fs_struct")))
	t.AddStruct(symbols.StructType{Name: "mm_struct", Size: FSMMSize, Fields: []symbols.Field{
		field("mmap", FSMMMmap, ptr("vm_area_struct")), field("pgd", FSMMPgd, ptr("pgd_t")),
		field("start_brk", FSMMStartBrk, u64), field("brk", FSMMBrk, u64), field("start_stack", FSMMStartStack, u64),
		field("arg_start", FSMMArgStart, u64), field("arg_end", FSMMArgEnd, u64),
		field("env_start", FSMMEnvStart, u64), field("env_end", FSMMEnvEnd, u64),
		field("context", FSMMContext, scalar("mm_context_t")),
	}})
	t.AddStruct(symbols.StructType{Name: "mm_context_t", Size: mmContextSize, Fields: []symbols.Field{field("vdso", 0, voidPtr())}})
	t.AddStruct(symbols.StructType{Name: "pgd_t", Size: 8})
	t.AddStruct(symbols.StructType{Name: "vm_area_struct", Size: FSVMASize, Fields: []symbols.Field{
		field("vm_start", FSVMAStart, u64), field("vm_end", FSVMAEnd, u64), field("vm_next", FSVMANext, ptr("vm_area_struct")),
		field("vm_mm", FSVMAMM, ptr("mm_struct")), field("vm_flags", FSVMAFlags, u64),
		field("vm_pgoff", FSVMAPgoff, u64), field("vm_file", FSVMAFile, ptr("file")),
	}})
	t.AddStruct(symbols.StructType{Name: "fs_struct", Size: FSStructSize, Fields: []symbols.Field{
		field("root", FSStructRoot, scalar("path")), field("pwd", FSStructRoot+pathSize, scalar("path")),
	}})
	t.AddStruct(symbols.StructType{Name: "super_block", Size: FSSBSize, Fields: []symbols.Field{
		field("s_dev", FSSBDev, scalar("unsigned int")), field("s_type", FSSBType, ptr("file_system_type")),
		field("s_flags", FSSBFlags, u64), field("s_root", FSSBRoot, ptr("dentry")),
		field("s_uuid", FSSBUUID, scalar("uuid_t")), field("s_subtype", FSSBSubtype, ptr("char")),
	}})
	t.AddStruct(symbols.StructType{Name: "uuid_t", Size: 0x10, Fields: []symbols.Field{field("b", 0, array("unsigned char", 16))}})
	t.AddStruct(symbols.StructType{Name: "file_system_type", Size: fsTypeSize, Fields: []symbols.Field{field("name", 0, ptr("char"))}})
	t.AddStruct(symbols.StructType{Name: "vfsmount", Size: FSVfsSize, Fields: []symbols.Field{
		field("mnt_root", FSVfsRoot, ptr("dentry")), field("mnt_sb", FSVfsSB, ptr("super_block")),
		field("mnt_flags", FSVfsFlags, scalar("int")),
	}})
	t.AddStruct(symbols.StructType{Name: "mount", Size: FSMntSize, Fields: []symbols.Field{
		field("mnt_parent", FSMntParent, ptr("mount")), field("mnt_mountpoint", FSMntMountpoint, ptr("dentry")),
		field("mnt", FSMntVfs, scalar("vfsmount")), field("mnt_node", FSMntNode, scalar("rb_node")),
		field("mnt_devname", FSMntDevname, ptr("char")), field("mnt_list", FSMntList, scalar("list_head")),
		field("mnt_share", FSMntShare, scalar("list_head")), field("mnt_master", FSMntMaster, ptr("mount")),
		field("mnt_ns", FSMntNS, ptr("mnt_namespace")), field("mnt_id", FSMntID, scalar("int")),
		field("mnt_group_id", FSMntGroupID, scalar("int")),
	}})
	t.AddStruct(symbols.StructType{Name: "rb_node", Size: rbNodeSize, Fields: []symbols.Field{
		field("__rb_parent_color", 0, u64), field("rb_right", 8, ptr("rb_node")), field("rb_left", 0x10, ptr("rb_node")),
	}})
	t.AddStruct(symbols.StructType{Name: "rb_root", Size: 8, Fields: []symbols.Field{field("rb_node", 0, ptr("rb_node"))}})
	t.AddStruct(symbols.StructType{Name: "mnt_namespace", Size: FSNSSize, Fields: []symbols.Field{
		field("ns", mntNamespaceNS, scalar("ns_common")), field("list", FSNSList, scalar("list_head")),
	}})
	k.addFields("nsproxy", nsproxySize, field("mnt_ns", FSNsproxyMntNS, ptr("mnt_namespace")))
	t.AddStruct(symbols.StructType{Name: "address_space", Size: addrSpaceSz, Fields: []symbols.Field{
		field("i_pages", AddrSpacePage, scalar("xarray")), field("nrpages", FSAddrSpaceNrpages, u64),
	}})
	t.AddStruct(symbols.StructType{Name: "page", Size: FSPageStructSize, Fields: []symbols.Field{
		field("flags", FSPageFlags, u64), field("mapping", FSPageMapping, ptr("address_space")), field("index", FSPageIndex, u64),
	}})
}

// Str writes s NUL-terminated on the heap.
func (k *Kernel) Str(s string) uint64 {
	a := k.Alloc(uint64(len(s)) + 1)
	k.Mem.Write(a, append([]byte(s), 0))
	return a
}

// AddDentry lays out a hashed dentry (d_hash.pprev set, which
// hlist_bl_unhashed reads as hashed) with empty child lists; parent 0 makes
// it its own parent, as a root is (IS_ROOT, dcache.h).
func (k *Kernel) AddDentry(name string, parent, inode uint64) uint64 {
	d := k.Alloc(FSDentSize)
	if parent == 0 {
		parent = d
	}
	k.Mem.U64(d+FSDentParent, parent)
	k.Mem.U64(d+FSDentHash+8, d+FSDentHash)
	k.Mem.U32(d+FSDentName+FSQstrLen, uint32(len(name)))
	k.Mem.U64(d+FSDentName+FSQstrName, k.Str(name))
	k.Mem.U64(d+FSDentInode, inode)
	k.Circle(d + FSDentSubdir)
	k.Circle(d + FSDentChild)
	return d
}

// LinkChildren puts the children on parent's d_subdirs through d_child.
func (k *Kernel) LinkChildren(parent uint64, children ...uint64) {
	heads := []uint64{parent + FSDentSubdir}
	for _, c := range children {
		heads = append(heads, c+FSDentChild)
	}
	k.Circle(heads...)
}

type Inode struct {
	Ino                 uint64
	Mode                uint16
	Size                int64
	Nlink               uint32
	SB                  uint64
	Mapping             uint64
	ATime, MTime, CTime [2]int64
	Link                uint64
	Count               int32
}

// AddInode lays out an inode; a zero Count is written as 1, an inode in use.
func (k *Kernel) AddInode(spec Inode) uint64 {
	a := k.Alloc(FSInodeSize)
	m := k.Mem
	m.u16(a+FSInodeMode, spec.Mode)
	m.U64(a+FSInodeSB, spec.SB)
	m.U64(a+FSInodeMapping, spec.Mapping)
	m.U64(a+FSInodeIno, spec.Ino)
	m.U32(a+FSInodeNlink, spec.Nlink)
	m.U64(a+FSInodeSizeOff, uint64(spec.Size))
	for off, ts := range map[uint64][2]int64{FSInodeATime: spec.ATime, FSInodeMTime: spec.MTime, FSInodeCTime: spec.CTime} {
		m.U64(a+off, uint64(ts[0]))
		m.U64(a+off+8, uint64(ts[1]))
	}
	m.U64(a+FSInodeLink, spec.Link)
	count := spec.Count
	if count == 0 {
		count = 1
	}
	m.U32(a+FSInodeCount, uint32(count))
	return a
}

type SuperBlock struct {
	Dev           uint32
	Flags         uint64
	Type, Subtype string
	UUID          [16]byte
	Root          uint64
}

// AddSuperBlock lays out a superblock; an empty Type leaves s_type null and
// an empty Subtype leaves s_subtype null.
func (k *Kernel) AddSuperBlock(spec SuperBlock) uint64 {
	a := k.Alloc(FSSBSize)
	m := k.Mem
	m.U32(a+FSSBDev, spec.Dev)
	m.U64(a+FSSBFlags, spec.Flags)
	if spec.Type != "" {
		fst := k.Alloc(fsTypeSize)
		m.U64(fst, k.Str(spec.Type))
		m.U64(a+FSSBType, fst)
	}
	if spec.Subtype != "" {
		m.U64(a+FSSBSubtype, k.Str(spec.Subtype))
	}
	m.Write(a+FSSBUUID, spec.UUID[:])
	m.U64(a+FSSBRoot, spec.Root)
	return a
}

type Mount struct {
	Parent, Mountpoint, Root, SB uint64
	Flags                        int32
	Devname                      string
	ID, GroupID                  int32
	Master, NS                   uint64
}

// AddMount lays out a mount; Parent 0 makes it its own parent, as a
// namespace root is (fs/namespace.c mnt_has_parent).
func (k *Kernel) AddMount(spec Mount) uint64 {
	a := k.Alloc(FSMntSize)
	m := k.Mem
	parent := spec.Parent
	if parent == 0 {
		parent = a
	}
	m.U64(a+FSMntParent, parent)
	m.U64(a+FSMntMountpoint, spec.Mountpoint)
	m.U64(a+FSMntVfs+FSVfsRoot, spec.Root)
	m.U64(a+FSMntVfs+FSVfsSB, spec.SB)
	m.U32(a+FSMntVfs+FSVfsFlags, uint32(spec.Flags))
	m.U64(a+FSMntDevname, k.Str(spec.Devname))
	m.U32(a+FSMntID, uint32(spec.ID))
	m.U32(a+FSMntGroupID, uint32(spec.GroupID))
	m.U64(a+FSMntMaster, spec.Master)
	m.U64(a+FSMntNS, spec.NS)
	k.Circle(a + FSMntShare)
	return a
}

// AddMountNamespace puts the mounts on a new namespace's list, in order, and
// points each at it.
func (k *Kernel) AddMountNamespace(inum uint32, mounts ...uint64) uint64 {
	ns := k.Alloc(FSNSSize)
	k.Mem.U32(ns+FSNSInum, inum)
	heads := []uint64{ns + FSNSList}
	for _, m := range mounts {
		heads = append(heads, m+FSMntList)
		k.Mem.U64(m+FSMntNS, ns)
	}
	k.Circle(heads...)
	return ns
}

// SetTaskFS gives the task an fs_struct rooted at the vfsmount and dentry,
// and its nsproxy the mount namespace.
func (k *Kernel) SetTaskFS(task, rootMnt, rootDentry, ns uint64) uint64 {
	fs := k.Alloc(FSStructSize)
	k.Mem.U64(fs+FSStructRoot, rootMnt)
	k.Mem.U64(fs+FSStructRoot+8, rootDentry)
	k.Mem.U64(task+FSTaskFS, fs)
	k.Mem.U64(k.Mem.read64(task+TaskNsproxy)+FSNsproxyMntNS, ns)
	return fs
}

func (k *Kernel) AddFile(dentry, vfsmnt, inode uint64) uint64 {
	f := k.Alloc(FSFileSize)
	k.Mem.U64(f+FSFileInode, inode)
	k.Mem.U64(f+FSFilePath, vfsmnt)
	k.Mem.U64(f+FSFilePath+8, dentry)
	return f
}

// SetTaskFiles gives the task a descriptor table of maxFDs slots holding
// files by descriptor number, and returns the slot array.
func (k *Kernel) SetTaskFiles(task uint64, maxFDs uint32, files map[uint64]uint64) (fdArray uint64) {
	fs := k.Alloc(FSFilesSize)
	fdt := k.Alloc(FSFdtSize)
	fdArray = k.Alloc(uint64(maxFDs) * fdtableSlotWidth)
	k.Mem.U32(fdt+FSFdtMaxFDs, maxFDs)
	k.Mem.U64(fdt+FSFdtFD, fdArray)
	for fd, f := range files {
		k.Mem.U64(fdArray+fd*fdtableSlotWidth, f)
	}
	k.Mem.U64(fs+FSFilesFdt, fdt)
	k.Mem.U64(task+FSTaskFiles, fs)
	return fdArray
}

type VMA struct {
	Start, End, Flags, Pgoff, File uint64
}

type MM struct {
	PGD                                uint64
	StartBrk, Brk, StartStack          uint64
	ArgStart, ArgEnd, EnvStart, EnvEnd uint64
	VMAs                               []VMA
}

// AddMM lays out an mm_struct whose areas chain through mmap and vm_next in
// the order given.
func (k *Kernel) AddMM(spec MM) uint64 {
	mm := k.Alloc(FSMMSize)
	m := k.Mem
	for off, v := range map[uint64]uint64{
		FSMMPgd: spec.PGD, FSMMStartBrk: spec.StartBrk, FSMMBrk: spec.Brk, FSMMStartStack: spec.StartStack,
		FSMMArgStart: spec.ArgStart, FSMMArgEnd: spec.ArgEnd, FSMMEnvStart: spec.EnvStart, FSMMEnvEnd: spec.EnvEnd,
	} {
		m.U64(mm+off, v)
	}
	link := mm + FSMMMmap
	for _, v := range spec.VMAs {
		a := k.Alloc(FSVMASize)
		m.U64(a+FSVMAStart, v.Start)
		m.U64(a+FSVMAEnd, v.End)
		m.U64(a+FSVMAMM, mm)
		m.U64(a+FSVMAFlags, v.Flags)
		m.U64(a+FSVMAPgoff, v.Pgoff)
		m.U64(a+FSVMAFile, v.File)
		m.U64(link, a)
		link = a + FSVMANext
	}
	return mm
}

// Translating is kernel memory whose page directories, listed in Tables,
// translate to the process roots a ProcessMemory hook resolves.
type Translating struct {
	*Memory
	Tables map[uint64]uint64
}

func (t *Translating) Translate(va uint64) (uint64, error) {
	if dtb, ok := t.Tables[va]; ok {
		return dtb, nil
	}
	return 0, fmt.Errorf("%#x: %w", va, memory.ErrUnmapped)
}

type Tree struct {
	K                                                                   *Kernel
	RootSB, RootMnt, RootDentry, Etc, Passwd, TmpDir                    uint64
	TmpSB, TmpMnt, TmpRoot, X                                           uint64
	RootInode, EtcInode, PasswdInode, TmpDirInode, TmpRootInode, XInode uint64
	NS, Task, PasswdFile, XFile                                         uint64
}

// Values of the S39 tree: device numbers are MKDEV (include/linux/kdev_t.h,
// MINORBITS 20), modes the POSIX S_IFDIR and S_IFREG types, the tmpfs mount
// MNT_NOSUID, MNT_NODEV and MNT_SHARED (include/linux/mount.h v4.19), and
// the namespace inode the first dynamic proc inode number
// (fs/proc/generic.c PROC_DYNAMIC_FIRST).
const (
	sdaOne      = 8<<20 | 1
	tmpfsDev    = 30
	modeDir     = 0o40755
	modeSticky  = 0o41777
	mntNosuid   = 0x01
	mntNodev    = 0x02
	mntShared   = 0x1000
	firstProcNS = 0xf0000000
)

// NewTree builds the S39 tree: ext4 on /dev/sda1 holding /etc/passwd and
// /tmp, a tmpfs mounted on /tmp holding x, both in one mount namespace, and
// task 1 with passwd on descriptor 0 and x on descriptor 1.
func NewTree() *Tree {
	k := NewKernel(1700000000, 0)
	AddFS(k)
	t := &Tree{K: k}
	mapping := func() uint64 { return k.Alloc(addrSpaceSz) }
	ts := func(sec int64) [2]int64 { return [2]int64{sec, 0} }
	t.RootSB = k.AddSuperBlock(SuperBlock{Dev: sdaOne, Type: "ext4",
		UUID: [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}})
	t.TmpSB = k.AddSuperBlock(SuperBlock{Dev: tmpfsDev, Type: "tmpfs",
		UUID: [16]byte{0x11, 0x22, 0x33, 0x44, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}})
	t.RootInode = k.AddInode(Inode{Ino: 2, Mode: modeDir, Size: 4096, Nlink: 3, SB: t.RootSB, Mapping: mapping(),
		ATime: ts(1700000100), MTime: ts(1700000200), CTime: ts(1700000300)})
	t.EtcInode = k.AddInode(Inode{Ino: 11, Mode: modeDir, Size: 4096, Nlink: 2, SB: t.RootSB, Mapping: mapping()})
	t.PasswdInode = k.AddInode(Inode{Ino: 12, Mode: 0o100644, Size: 0x1800, Nlink: 1, SB: t.RootSB, Mapping: mapping(),
		ATime: ts(1700001000), MTime: ts(1700002000), CTime: ts(1700003000)})
	t.TmpDirInode = k.AddInode(Inode{Ino: 13, Mode: modeSticky, Size: 4096, Nlink: 2, SB: t.RootSB, Mapping: mapping()})
	t.TmpRootInode = k.AddInode(Inode{Ino: 1, Mode: modeSticky, Size: 60, Nlink: 2, SB: t.TmpSB, Mapping: mapping()})
	t.XInode = k.AddInode(Inode{Ino: 5, Mode: 0o100600, Size: 10, Nlink: 1, SB: t.TmpSB, Mapping: mapping()})
	t.RootDentry = k.AddDentry("/", 0, t.RootInode)
	t.Etc = k.AddDentry("etc", t.RootDentry, t.EtcInode)
	t.Passwd = k.AddDentry("passwd", t.Etc, t.PasswdInode)
	t.TmpDir = k.AddDentry("tmp", t.RootDentry, t.TmpDirInode)
	t.TmpRoot = k.AddDentry("/", 0, t.TmpRootInode)
	t.X = k.AddDentry("x", t.TmpRoot, t.XInode)
	k.LinkChildren(t.RootDentry, t.Etc, t.TmpDir)
	k.LinkChildren(t.Etc, t.Passwd)
	k.LinkChildren(t.TmpRoot, t.X)
	k.Mem.U64(t.RootSB+FSSBRoot, t.RootDentry)
	k.Mem.U64(t.TmpSB+FSSBRoot, t.TmpRoot)
	t.RootMnt = k.AddMount(Mount{Root: t.RootDentry, SB: t.RootSB, Devname: "/dev/sda1", ID: 1})
	t.TmpMnt = k.AddMount(Mount{Parent: t.RootMnt, Mountpoint: t.TmpDir, Root: t.TmpRoot, SB: t.TmpSB,
		Flags: mntNosuid | mntNodev | mntShared, Devname: "tmpfs", ID: 2, GroupID: 1})
	t.NS = k.AddMountNamespace(firstProcNS, t.RootMnt, t.TmpMnt)
	t.Task = k.AddTask(Task{PID: 1, TGID: 1, Comm: "init"})
	k.LinkTasks(t.Task)
	k.SetTaskFS(t.Task, t.RootMnt+FSMntVfs, t.RootDentry, t.NS)
	t.PasswdFile = k.AddFile(t.Passwd, t.RootMnt+FSMntVfs, t.PasswdInode)
	t.XFile = k.AddFile(t.X, t.TmpMnt+FSMntVfs, t.XInode)
	k.SetTaskFiles(t.Task, 4, map[uint64]uint64{0: t.PasswdFile, 1: t.XFile})
	return t
}
