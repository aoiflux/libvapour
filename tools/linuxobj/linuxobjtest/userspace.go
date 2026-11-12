package linuxobjtest

import (
	"strings"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

// RootFS is one ext4 root mount in its own namespace; File adds regular
// files under it, creating the directories on the way.
type RootFS struct {
	k                 *Kernel
	SB, Mnt, Root, NS uint64
	dentries          map[string]uint64
	ino               uint64
}

const firstFileIno = 100

func (k *Kernel) NewRootFS() *RootFS {
	r := &RootFS{k: k, dentries: map[string]uint64{}, ino: firstFileIno}
	r.SB = k.AddSuperBlock(SuperBlock{Dev: sdaOne, Type: "ext4"})
	inode := k.AddInode(Inode{Ino: 2, Mode: modeDir, Nlink: 3, SB: r.SB})
	r.Root = k.AddDentry("/", 0, inode)
	r.Mnt = k.AddMount(Mount{Root: r.Root, SB: r.SB, Devname: "/dev/sda1", ID: 1})
	r.NS = k.AddMountNamespace(firstProcNS, r.Mnt)
	return r
}

// Enter makes the root the task's root and mount namespace.
func (r *RootFS) Enter(task uint64) { r.k.SetTaskFS(task, r.Mnt+FSMntVfs, r.Root, r.NS) }

// File adds an executable regular file at path and returns an open struct
// file for it. nlink 0 also unhashes its dentry, as an unlinked file's is.
func (r *RootFS) File(path string, nlink uint32, size int64) uint64 {
	k := r.k
	parts := strings.Split(strings.Trim(path, "/"), "/")
	parent, dir := r.Root, ""
	for _, name := range parts[:len(parts)-1] {
		dir += "/" + name
		d, ok := r.dentries[dir]
		if !ok {
			r.ino++
			d = k.AddDentry(name, parent, k.AddInode(Inode{Ino: r.ino, Mode: 0o40755, Nlink: 2, SB: r.SB}))
			r.dentries[dir] = d
		}
		parent = d
	}
	r.ino++
	inode := k.AddInode(Inode{Ino: r.ino, Mode: 0o100755, Size: size, Nlink: nlink, SB: r.SB})
	d := k.AddDentry(parts[len(parts)-1], parent, inode)
	if nlink == 0 {
		k.Mem.U64(d+FSDentHash+8, 0)
	}
	return k.AddFile(d, r.Mnt+FSMntVfs, inode)
}

// UserSpaces gives each process real x86-64 page tables over one physical
// memory, and the kernel a pgd for each that translates to its table root.
type UserSpaces struct {
	k      *Kernel
	PM     *testsupport.PagedMemory
	Kernel *Translating
}

func (k *Kernel) NewUserSpaces(size int) *UserSpaces {
	return &UserSpaces{k: k, PM: testsupport.NewPagedMemory(size),
		Kernel: &Translating{Memory: k.Mem, Tables: map[uint64]uint64{}}}
}

// New returns a kernel pgd and the address space it stands for.
func (u *UserSpaces) New() (pgd uint64, as *testsupport.AddressSpace) {
	pgd = u.k.Alloc(pageSize)
	as = u.PM.NewAddressSpace()
	u.Kernel.Tables[pgd] = as.DTB
	return pgd, as
}

// Context reads process memory through 4-level paging from each task's
// table root.
func (u *UserSpaces) Context(options map[string]any) (tools.Context, *[]string) {
	if options == nil {
		options = map[string]any{}
	}
	options[tools.OptionPhysicalMemory] = u.PM
	ctx, diags := u.k.Context(options)
	ctx.Memory = u.Kernel
	ctx.ProcessMemory = func(dtb uint64) (memory.MemoryReader, error) {
		tr := &layers.IntelTranslator{Physical: u.PM, CR3: dtb, Mode: layers.LinuxMode(layers.ModeX64, 0, 0)}
		return layers.NewVirtualMemoryLayer(u.PM, tr), nil
	}
	return ctx, diags
}
