package linuxobj

import (
	"fmt"
	"strings"
	"time"
)

type FDTable struct {
	Array uint64
	Count uint64
}

// A table over MaxTableEntries is refused rather than cut: nr_open can be
// raised far above its default (S39 F2), so no kernel bound applies.
func (k *Kernel) TaskFDs(t Task) (FDTable, bool, error) {
	if !k.Has("task_struct", "files") {
		return FDTable{}, false, fmt.Errorf("%w: task_struct has no files", ErrUnsupported)
	}
	files, err := k.Pointer(k.in(t), t.Addr, "task_struct", "files")
	if err != nil || files == 0 {
		return FDTable{}, false, nil
	}
	fdt, err := k.Pointer(k.mem, files, "files_struct", "fdt")
	if err != nil || fdt == 0 {
		return FDTable{}, false, nil
	}
	count, err := k.Uint(k.mem, fdt, "fdtable", "max_fds")
	if err != nil {
		return FDTable{}, false, nil
	}
	array, err := k.Pointer(k.mem, fdt, "fdtable", "fd")
	if err != nil || array == 0 {
		return FDTable{}, false, nil
	}
	if count > uint64(k.ctx.Bounds().MaxTableEntries) {
		return FDTable{}, false, nil
	}
	return FDTable{Array: array, Count: count}, true, nil
}

type OpenFile struct {
	FD   uint64
	File uint64
}

func (k *Kernel) OpenFiles(tab FDTable) ([]OpenFile, error) {
	var out []OpenFile
	width := k.PointerSize()
	for fd := range tab.Count {
		file, err := k.PointerAt(k.mem, tab.Array+fd*width)
		if err != nil {
			return out, fmt.Errorf("linuxobj: fd %d: %w", fd, err)
		}
		if file != 0 {
			out = append(out, OpenFile{FD: fd, File: file})
		}
	}
	return out, nil
}

func (k *Kernel) FileInode(file uint64) (uint64, bool, error) {
	inode, ok, err := k.Deref(k.mem, file, "file", "f_inode")
	if err != nil || !ok {
		return 0, false, err
	}
	return inode, true, nil
}

// PathPoint is a (mount, dentry) pair; Mount is the struct mount, not the
// vfsmount embedded in it.
type PathPoint struct {
	Mount  uint64
	Dentry uint64
}

func (k *Kernel) pathAt(at uint64) (PathPoint, error) {
	vfs, err := k.Pointer(k.mem, at, "path", "mnt")
	if err != nil {
		return PathPoint{}, err
	}
	dentry, err := k.Pointer(k.mem, at, "path", "dentry")
	if err != nil {
		return PathPoint{}, err
	}
	mnt, err := k.mountOf(vfs)
	if err != nil {
		return PathPoint{}, err
	}
	return PathPoint{Mount: mnt, Dentry: dentry}, nil
}

func (k *Kernel) FileLocation(file uint64) (PathPoint, error) {
	f, err := k.Member("file", "f_path")
	if err != nil {
		return PathPoint{}, fmt.Errorf("%w: file has no f_path", ErrUnsupported)
	}
	return k.pathAt(file + f.Offset)
}

const fmodeBacking = 1 << 24

// The maps file shows a stacked filesystem's file by the path the user
// opened, kept beside the backing file (S39 F5).
func (k *Kernel) MappedFileLocation(file uint64) (PathPoint, error) {
	user, err := k.Member("backing_file", "user_path")
	if err != nil || !k.Has("file", "f_mode") {
		return k.FileLocation(file)
	}
	mode, err := k.Uint(k.mem, file, "file", "f_mode")
	if err != nil {
		return PathPoint{}, err
	}
	if mode&fmodeBacking == 0 {
		return k.FileLocation(file)
	}
	return k.pathAt(file + user.Offset)
}

func (k *Kernel) MappedFileInode(file uint64) (uint64, bool, error) {
	if _, err := k.Member("backing_file", "user_path"); err == nil && k.Has("file", "f_mode") {
		mode, err := k.Uint(k.mem, file, "file", "f_mode")
		if err != nil {
			return 0, false, err
		}
		if mode&fmodeBacking != 0 {
			at, err := k.MappedFileLocation(file)
			if err != nil {
				return 0, false, err
			}
			return k.Deref(k.mem, at.Dentry, "dentry", "d_inode")
		}
	}
	return k.FileInode(file)
}

const (
	modeTypeMask = 0o170000
	modeSetUID   = 0o4000
	modeSetGID   = 0o2000
	modeSticky   = 0o1000
)

var modeTypes = []struct {
	bits      uint64
	name      string
	character byte
}{
	{0o100000, "REG", '-'},
	{0o040000, "DIR", 'd'},
	{0o120000, "LNK", 'l'},
	{0o020000, "CHR", 'c'},
	{0o060000, "BLK", 'b'},
	{0o010000, "FIFO", 'p'},
	{0o140000, "SOCK", 's'},
}

func InodeType(mode uint64) (string, bool) {
	for _, t := range modeTypes {
		if mode&modeTypeMask == t.bits {
			return t.name, true
		}
	}
	return "", false
}

func FileMode(mode uint64) string {
	b := []byte("?---------")
	for _, t := range modeTypes {
		if mode&modeTypeMask == t.bits {
			b[0] = t.character
		}
	}
	for i, c := range "rwxrwxrwx" {
		if mode&(1<<(8-i)) != 0 {
			b[1+i] = byte(c)
		}
	}
	special := func(bit uint64, at int, set, unset byte) {
		if mode&bit == 0 {
			return
		}
		if b[at] == 'x' {
			b[at] = set
		} else {
			b[at] = unset
		}
	}
	special(modeSetUID, 3, 's', 'S')
	special(modeSetGID, 6, 's', 'S')
	special(modeSticky, 9, 't', 'T')
	return string(b)
}

func (k *Kernel) InodeMode(inode uint64) (uint64, error) {
	return k.Uint(k.mem, inode, "inode", "i_mode")
}

type InodeTimes struct {
	Changed, Modified, Accessed       time.Time
	ChangedOK, ModifiedOK, AccessedOK bool
}

const (
	ctimeQueried   = 1 << 31
	nsecPerSecond  = 1_000_000_000
	inodeTimeSplit = "i_ctime_sec"
)

func (k *Kernel) InodeTimes(inode uint64) (InodeTimes, error) {
	var out InodeTimes
	for _, t := range []struct {
		letter string
		at     *time.Time
		ok     *bool
	}{{"c", &out.Changed, &out.ChangedOK}, {"m", &out.Modified, &out.ModifiedOK}, {"a", &out.Accessed, &out.AccessedOK}} {
		sec, nsec, present, err := k.inodeTime(inode, t.letter)
		if err != nil {
			return out, err
		}
		if present && nsec < nsecPerSecond {
			*t.at, *t.ok = time.Unix(sec, int64(nsec)).UTC(), true
		}
	}
	return out, nil
}

func (k *Kernel) inodeTime(inode uint64, letter string) (sec int64, nsec uint64, present bool, err error) {
	if k.Has("inode", inodeTimeSplit) {
		if sec, err = k.Int(k.mem, inode, "inode", "i_"+letter+"time_sec"); err != nil {
			return 0, 0, false, err
		}
		if nsec, err = k.Uint(k.mem, inode, "inode", "i_"+letter+"time_nsec"); err != nil {
			return 0, 0, false, err
		}
		if letter == "c" {
			nsec &^= ctimeQueried
		}
		return sec, nsec, true, nil
	}
	f, ferr := k.Member("inode", "i_"+letter+"time")
	if ferr != nil {
		return 0, 0, false, nil
	}
	at := inode + f.Offset
	if sec, err = k.Int(k.mem, at, f.Type.Name, "tv_sec"); err != nil {
		return 0, 0, false, err
	}
	n, err := k.Int(k.mem, at, f.Type.Name, "tv_nsec")
	if err != nil {
		return 0, 0, false, err
	}
	if n < 0 {
		return sec, nsecPerSecond, true, nil
	}
	return sec, uint64(n), true, nil
}

const minorBits = 20

func (k *Kernel) SuperBlockDeviceString(sb uint64) (string, error) {
	dev, err := k.Uint(k.mem, sb, "super_block", "s_dev")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", dev>>minorBits, dev&(1<<minorBits-1)), nil
}

const sbReadOnly = 1

var superBlockOptions = []struct {
	bit  uint64
	name string
}{{1 << 4, "sync"}, {1 << 7, "dirsync"}, {1 << 6, "mand"}, {1 << 25, "lazytime"}}

func (k *Kernel) SuperBlockFlags(sb uint64) (string, []string, error) {
	flags, err := k.Uint(k.mem, sb, "super_block", "s_flags")
	if err != nil {
		return "", nil, err
	}
	access := "rw"
	if flags&sbReadOnly != 0 {
		access = "ro"
	}
	var opts []string
	for _, o := range superBlockOptions {
		if flags&o.bit != 0 {
			opts = append(opts, o.name)
		}
	}
	return access, opts, nil
}

const pathMax = 4096

func (k *Kernel) SuperBlockType(sb uint64) (string, bool, error) {
	fsType, err := k.Pointer(k.mem, sb, "super_block", "s_type")
	if err != nil || fsType == 0 {
		return "", false, err
	}
	namePtr, err := k.Pointer(k.mem, fsType, "file_system_type", "name")
	if err != nil || namePtr == 0 {
		return "", false, err
	}
	name, err := k.StringAt(namePtr, pathMax)
	if err != nil || name == "" {
		return "", false, nil
	}
	if !k.Has("super_block", "s_subtype") {
		return name, true, nil
	}
	subPtr, err := k.Pointer(k.mem, sb, "super_block", "s_subtype")
	if err != nil {
		return "", false, err
	}
	if subPtr == 0 {
		return name, true, nil
	}
	sub, err := k.StringAt(subPtr, pathMax)
	if err != nil {
		return "", false, nil
	}
	return strings.Join([]string{name, sub}, "."), true, nil
}
