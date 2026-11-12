# S39: Linux file identity, path reconstruction and the process memory-area walk

Version 1, 2026-11-12.

## 1. Purpose

A Linux process reaches files through descriptors, through its executable and through the memory areas it maps. An examiner wants, for each of them, the name the kernel itself would print: the target of `/proc/<pid>/fd/<n>` and `/proc/<pid>/exe`, the last column of `/proc/<pid>/maps`, and the mount point column of `/proc/<pid>/mountinfo`. The kernel builds these names on demand by walking from a dentry up through its parents and across the mounts it sits on, and some pseudo files name themselves through a dentry operation instead. This specification defines that walk, the names of pseudo files, the descriptor table and inode facts each open file carries, the mount tree of a namespace, and the walk of a process's memory areas (the VMA list before 6.1, the maple tree from 6.1). It is the source for `linux.file.list_open`, `linux.mount.list`, `any.memory.list` on Linux, and the path and memory-area helpers that `linux.process.check_identity`, `linux.library.list`, `linux.memory.list_elf_files`, `linux.memory.find_pattern`, `linux.shell.read_history` and `any.memory.find_code` use.

The task walk is S01 and the list walk S01's `List`. Module lookup is not used.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxobj.Kernel` | Kernel-space memory, the symbol table, the address form and the effective Limits. |
| Tasks | S01 task walk, or the `any.process.list` rows on Linux | The task whose root a path is built from, and whose `mm` is walked. |
| Symbols | symbol table | The types of section 3; the function symbols `pipefs_dname`, `sockfs_dname`, `anon_inodefs_dname`, `ns_dname`, `simple_dname`, `dmabuffs_dname`, `pidfs_dname` and `special_mapping_name`. |
| Options | tool options | Unchanged: `linux.file.list_open.files_only`, `linux.mount.list.mntns`, `linux.mount.list.mount_format`, `any.memory.list.address`, the session PID set. |
| Limits | effective `limits.Limits` | Section 8. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17 unless a row names fewer. The supported captures run 6.17 (Ubuntu 24, mem3) and 6.14 (Fedora 40, mem4). Paths are under the kernel tree.

### Descriptors and files

| # | Fact | Source |
|---|---|---|
| F1 | `task_struct.files` points at a `files_struct`; `files_struct.fdt` points at `struct fdtable { unsigned int max_fds; struct file __rcu **fd; ... }`. A slot holds a `struct file *` or NULL. | `include/linux/fdtable.h`, every tag. |
| F2 | `sysctl_nr_open` defaults to 1024*1024 and bounds `max_fds`; the administrator can raise it to `sysctl_nr_open_max`. | `fs/file.c`, v4.19, v6.17. |
| F3 | `struct file` holds `struct path f_path`, `struct inode *f_inode`, `f_op`, `fmode_t f_mode` and `private_data`. `struct path` is `{ struct vfsmount *mnt; struct dentry *dentry; }`. | `include/linux/fs.h`, `include/linux/path.h`, v4.19, v6.17. |
| F4 | `/proc/<pid>/fd/<n>` resolves to the open file's `f_path` (`proc_fd_link`) and `/proc/<pid>/exe` to the `f_path` of `mm->exe_file` (`proc_exe_link`); `do_proc_readlink` prints it with `d_path` into a `PATH_MAX` buffer at v6.17 and a `PAGE_SIZE` page at v4.19. | `fs/proc/fd.c`, `fs/proc/base.c`, v4.19, v6.17. |
| F5 | A backing file (`f_mode & FMODE_BACKING`, `1 << 24`) is the first member of `struct backing_file { struct file file; union { struct path user_path; ... }; }`. `/proc/<pid>/maps` prints `file_user_path(file)` and the device and inode of `file_user_inode(file)`, which are the user path and its dentry's inode for a backing file and `f_path` and `f_inode` otherwise. The flag and the type exist at v6.14 and v6.17, not at v4.19 to v6.4. | `include/linux/fs.h`, `fs/file_table.c`, v6.14, v6.17; absent at v6.4. |
| F6 | `struct fs_struct` holds `struct path root, pwd`. | `include/linux/fs_struct.h`, v4.19, v6.17. |

### Inodes and superblocks

| # | Fact | Source |
|---|---|---|
| I1 | `struct inode` has `umode_t i_mode`, `struct super_block *i_sb`, `unsigned long i_ino`, `loff_t i_size` and `void *i_private`. The times are `struct timespec64 i_atime, i_mtime, i_ctime` at v4.19, v6.1 and v6.4, and `time64_t i_{a,m,c}time_sec` with `u32 i_{a,m,c}time_nsec` at v6.14 and v6.17. | `include/linux/fs.h`. |
| I2 | At v6.14 and v6.17 `I_CTIME_QUERIED` is `BIT(31)` of `i_ctime_nsec`, and `inode_get_ctime_nsec` masks it off. | `include/linux/fs.h`, v6.14, v6.17. |
| I3 | `S_IFMT` is 0170000 and the types are `S_IFSOCK` 0140000, `S_IFLNK` 0120000, `S_IFREG` 0100000, `S_IFBLK` 0060000, `S_IFDIR` 0040000, `S_IFCHR` 0020000, `S_IFIFO` 0010000; `S_ISUID` 04000, `S_ISGID` 02000, `S_ISVTX` 01000. | `include/uapi/linux/stat.h`, every tag. |
| I4 | The long format of `ls` writes the type character (`d`, `b`, `c`, `l`, `p`, `s` or `-`) then three `rwx` triplets; the set-user-ID and set-group-ID bits show as `s` in the execute place when it is set and `S` when not, and the sticky bit as `t` or `T`. | POSIX.1-2017, XCU `ls`, "STDOUT". |
| I5 | `dev_t` splits with `MINORBITS` 20: `MAJOR(dev) = dev >> 20`, `MINOR(dev) = dev & ((1 << 20) - 1)`. | `include/linux/kdev_t.h`, every tag. |
| I6 | `super_block` has `dev_t s_dev`, `unsigned long s_flags`, `struct file_system_type *s_type` (whose `name` is a `const char *`) and `const char *s_subtype`. `SB_RDONLY` is bit 0, `SB_SYNCHRONOUS` 4, `SB_MANDLOCK` 6, `SB_DIRSYNC` 7, `SB_LAZYTIME` 25. | `include/linux/fs.h`, every tag. |
| I7 | `/proc/<pid>/mountinfo` prints the type as `s_type->name`, then `.` and `s_subtype` when `s_subtype` is not NULL; the superblock options as `ro` or `rw` by `SB_RDONLY`, then `sync`, `dirsync`, `mand` and `lazytime` for their bits. | `fs/proc_namespace.c` `show_type`, `show_sb_opts`, `show_mountinfo`, every tag. |

### Dentries

| # | Fact | Source |
|---|---|---|
| D1 | `struct dentry` has `unsigned int d_flags`, `struct hlist_bl_node d_hash`, `struct dentry *d_parent`, `struct qstr d_name`, `struct inode *d_inode`, `const struct dentry_operations *d_op`, `struct super_block *d_sb` and `void *d_fsdata`. `qstr` is `{ union { struct { u32 hash; u32 len; }; u64 hash_len; }; const unsigned char *name; }`. | `include/linux/dcache.h`, every tag. |
| D2 | `IS_ROOT(x)` is `x == x->d_parent`. `d_unhashed(d)` is `hlist_bl_unhashed(&d->d_hash)`, which is `!d_hash.pprev`; `d_unlinked(d)` is `d_unhashed(d) && !IS_ROOT(d)`. | `include/linux/dcache.h`, `include/linux/list_bl.h`, v4.19, v6.17. |
| D3 | `NAME_MAX` is 255 and `PATH_MAX` 4096 including the NUL. | `include/uapi/linux/limits.h`, v4.19, v6.17. |
| D4 | `dentry_path_raw` walks `d_parent` until `IS_ROOT`, prepending `/` and each `d_name`; with nothing prepended the result is `/`. | `fs/d_path.c` `__dentry_path`, v6.17; `__dentry_path`, v4.19. |

### Paths across mounts

| # | Fact | Source |
|---|---|---|
| P1 | `struct mount` embeds `struct vfsmount mnt` (`mnt_root`, `mnt_sb`, `int mnt_flags`) and has `struct mount *mnt_parent`, `struct dentry *mnt_mountpoint` and `struct mnt_namespace *mnt_ns`; `real_mount(v)` is `container_of(v, struct mount, mnt)`. A mount is its namespace's root when `mnt_parent` is itself (`mnt_has_parent`). | `fs/mount.h`, every tag. |
| P2 | `prepend_path` walks from `(dentry, mount)` until both equal the root's. At a mount's `mnt_root` it moves to `(mnt_mountpoint, mnt_parent)` unless the mount is its own parent; there it ends with 1 when `mnt_ns` is neither NULL, an error pointer nor anonymous, and with 2 otherwise. A dentry that is its own parent before a mount root is reached ends the walk with 3 ("Escaped?"), and the output is dropped. Otherwise each `d_name` is prepended with `/` and the walk moves to `d_parent`. When nothing was prepended the result is `/`. | `fs/d_path.c` `__prepend_path`, `prepend_path`, v6.1 to v6.17 identical; `prepend_path`, v4.19 (same outcomes, the escape tested as `IS_ROOT` before the mount root). |
| P3 | `d_path` uses the reader's `fs->root`; it prints the walk's text for every outcome and appends ` (deleted)` when `d_unlinked(dentry)`. `__d_path` returns NULL for every outcome other than reaching the root. | `fs/d_path.c`, every tag. |
| P4 | `d_path` calls `d_op->d_dname` instead of walking when the dentry has one, unless the dentry is `IS_ROOT` and is its mount's `mnt_root` ("some pseudo inodes are mountable"). | `fs/d_path.c` `d_path`, every tag. |
| P5 | `is_anon_ns(ns)` is `ns->seq == 0`; every namespace from `alloc_mnt_ns` takes a sequence number from 1 up. `MNT_NS_INTERNAL` is `ERR_PTR(-EINVAL)`. | `fs/mount.h`, v6.1, v6.17; `fs/namespace.c` `alloc_mnt_ns`, v4.19, v6.17. |

### Pseudo names

| # | Fact | Source |
|---|---|---|
| Q1 | `dynamic_dname` formats into a 64-byte buffer and fails with `ENAMETOOLONG` when the text and its NUL do not fit. | `fs/d_path.c`, every tag. |
| Q2 | `pipefs_dname` prints `pipe:[<i_ino>]`, `sockfs_dname` `socket:[<i_ino>]` and `anon_inodefs_dname` `anon_inode:<d_name>`. | `fs/pipe.c`, `net/socket.c`, `fs/anon_inodes.c`, every tag. |
| Q3 | `ns_dname` prints `<ops->name>:[<i_ino>]`. `ns_get_path` sets `inode->i_private` to the `ns_common` at every tag, and `ns_common.ops` is the `proc_ns_operations` whose first member is `const char *name`; v4.19 to v6.4 also copy `ns->ops` to `d_fsdata`. | `fs/nsfs.c`; `include/linux/ns_common.h`; `include/linux/proc_ns.h`; every tag. |
| Q4 | `simple_dname` prints `/<d_name> (deleted)`. It is the `d_dname` of dentries from `alloc_file_pseudo` on filesystems without their own dentry operations (`fs/file_table.c` at v4.19 to v6.4, `d_alloc_pseudo` in `fs/dcache.c` at v6.14 and v6.17). | `fs/d_path.c`, `fs/file_table.c`, `fs/dcache.c`. |
| Q5 | `dmabuffs_dname` prints `/<d_name>:<name>` with `name` the `dma_buf.name` reached by `d_fsdata`, at most `DMA_BUF_NAME_LEN` 32 bytes with its NUL, or empty. | `drivers/dma-buf/dma-buf.c`, `include/uapi/linux/dma-buf.h`, v6.17. |
| Q6 | `pidfs_dname` prints `anon_inode:[pidfd]`. `fs/pidfs.c` exists at v6.14 and v6.17, not at v4.19 to v6.4. | `fs/pidfs.c`. |

### Mount namespaces

| # | Fact | Source |
|---|---|---|
| N1 | `mnt_namespace` has `struct ns_common ns` (with `unsigned int inum`), `struct mount *root` and `u64 seq`. Its mounts are on `struct list_head list` through `mount.mnt_list` at v4.19, v6.1 and v6.4, and in `struct rb_root mounts` through `mount.mnt_node` at v6.14 and v6.17, ordered by `mnt_id_unique` (`mnt_add_to_ns`). | `fs/mount.h`, `fs/namespace.c`. |
| N2 | `rb_node` is `{ unsigned long __rb_parent_color; struct rb_node *rb_right; struct rb_node *rb_left; }`, the parent being `__rb_parent_color & ~3`. | `include/linux/rbtree_types.h`, `include/linux/rbtree.h`, v6.17; `include/linux/rbtree.h`, v4.19. |
| N3 | `mount` has `int mnt_id`, `int mnt_group_id`, `struct mount *mnt_master`, `struct list_head mnt_share` and `const char *mnt_devname`. The devname is copied with `strndup_user(..., PAGE_SIZE)` at v4.19 and `PATH_MAX` at v6.17. | `fs/mount.h`; `fs/namespace.c` `copy_mount_string`. |
| N4 | `MNT_NOSUID` 0x01, `MNT_NODEV` 0x02, `MNT_NOEXEC` 0x04, `MNT_NOATIME` 0x08, `MNT_NODIRATIME` 0x10, `MNT_RELATIME` 0x20, `MNT_READONLY` 0x40, `MNT_NOSYMFOLLOW` 0x80 (from v6.1). `MNT_SHARED` 0x1000 and `MNT_UNBINDABLE` 0x2000 are `mnt_flags` bits to v6.14; at v6.17 they are `T_SHARED` 1 and `T_UNBINDABLE` 2 of `mount.mnt_t_flags`. | `include/linux/mount.h`; `fs/mount.h`, `fs/pnode.h`. |
| N5 | `/proc/<pid>/mountinfo` prints the mount options as `ro` or `rw` by `MNT_READONLY`, then `nosuid`, `nodev`, `noexec`, `noatime`, `nodiratime`, `relatime` and `nosymfollow`; the mount point with `seq_path_root`, which skips the mount when `__d_path` gives NULL; the root with the dentry path. A slave prints `master:<mnt_master->mnt_group_id>` and `propagate_from:<id>` when `get_dominating_id` is non-zero and differs. | `fs/proc_namespace.c`, every tag. |
| N6 | `get_dominating_id` follows `mnt_master` and, for each master, its peers around `mnt_share`, returning the `mnt_group_id` of the first peer in the slave's namespace whose root is reachable from the reader's root: `is_path_reachable` climbs `mnt_mountpoint`/`mnt_parent` to the root's mount and then needs the dentry to descend from the root's dentry (`is_subdir`). | `fs/pnode.c`, `fs/namespace.c`, `fs/dcache.c`, v4.19, v6.17. |

### Memory areas

| # | Fact | Source |
|---|---|---|
| A1 | `vm_area_struct` has `unsigned long vm_start`, `vm_end` (the first byte after), `struct mm_struct *vm_mm`, `vm_flags`, `vm_ops`, `unsigned long vm_pgoff` (in pages), `struct file *vm_file` and `void *vm_private_data`. At v4.19 it also has `vm_next` and `vm_prev`, "linked list of VM areas per task, sorted by address", and `mm_struct.mmap` is the first. | `include/linux/mm_types.h`. |
| A2 | `mm_struct.map_count` is the number of areas; the debug check `validate_mm` requires it to equal the count of a walk of the list (v4.19) or of the maple tree (v6.17). | `include/linux/mm_types.h`; `mm/mmap.c` v4.19, `mm/vma.c` v6.17. |
| A3 | From v6.1 `mm_struct.mm_mt` is a maple tree and there is no `mmap` member or `vm_next`. Each area is stored over the range `[vm_start, vm_end - 1]`, and `validate_mm` checks that the stored range equals the area's. | `include/linux/mm_types.h`; `mm/mmap.c` v6.1, `mm/vma.h` v6.14, v6.17. |
| A4 | `VM_READ` 0x1, `VM_WRITE` 0x2, `VM_EXEC` 0x4, `VM_MAYSHARE` 0x80. `/proc/<pid>/maps` prints `r`, `w`, `x` by the first three, the offset as `vm_pgoff << PAGE_SHIFT`, and the device and inode of the file (F5). | `include/linux/mm.h`; `fs/proc/task_mmu.c` `show_vma_header_prefix`, `show_map_vma`. |

### The maple tree

| # | Fact | Source |
|---|---|---|
| T1 | `struct maple_tree { ...; unsigned int ma_flags; void *ma_root; }`. The height is `(ma_flags & 0x7C) >> 2`, at most `MAPLE_HEIGHT_MAX` 31. | `include/linux/maple_tree.h`, v6.1 to v6.17. |
| T2 | An entry is internal when its low two bits are `10` (`xa_is_internal`) and a node when it is also above 4096 (`xa_is_node`). The root entry is an encoded node with `MAPLE_ROOT_NODE` 0x02 added (`mte_mk_root`). An encoded node is the 256-byte-aligned node address (`& ~MAPLE_NODE_MASK`, 255) with its type at bits 3 to 6 (`MAPLE_NODE_TYPE_SHIFT` 3, `MAPLE_NODE_TYPE_MASK` 0x0F) and `MAPLE_ENODE_NULL` 0x04 set (`mt_mk_node`); inner slots hold such entries. A non-node, non-NULL root is a single entry for index 0. | `include/linux/xarray.h`; `lib/maple_tree.c` `mte_node_type`, `mte_to_node`, `mt_mk_node`, `mte_mk_root`, `mas_start`; `include/linux/maple_tree.h`; v6.1 to v6.17. |
| T3 | `enum maple_type { maple_dense, maple_leaf_64, maple_range_64, maple_arange_64 }`; a type below `maple_range_64` is a leaf. On 64-bit, `maple_range_64` has 15 pivots and 16 slots with `maple_metadata` over the last slot; `maple_arange_64` has 9 pivots, 10 slots, 10 gaps and its own `meta`; a dense node has 31 slots and no pivots. `maple_metadata` is `{ unsigned char end; unsigned char gap; }`. | `include/linux/maple_tree.h`; `lib/maple_tree.c` `mt_slots`, `mt_pivots`, `ma_is_leaf`. |
| T4 | Slot `i` of a node over `[min, max]` covers `[pivot[i-1] + 1, pivot[i]]`, the first from `min`; a pivot past the pivot array is `max` (`mas_safe_pivot`), and a zero pivot after slot 0 is `max` (`mas_logical_pivot`, v6.1). | `lib/maple_tree.c`. |
| T5 | `ma_data_end`: an `arange_64` node ends at `meta.end`; otherwise, when the last pivot is 0 the end is `meta.end`, when it is `max` the end is the last pivot's slot, and else the last slot. | `lib/maple_tree.c`, v6.1 to v6.17 identical. |
| T6 | A node's first word, `parent`, is written by `mte_set_parent` (v6.1) and `mas_set_parent` (v6.17) as the parent node's address with the slot number at bits 3 and up (`MAPLE_PARENT_SLOT_SHIFT` 3, mask 0xF8) and `MAPLE_PARENT_RANGE64` 0x06 for a range parent. A node replaced under RCU is marked dead by pointing `parent` at itself (`mte_set_node_dead`, `ma_dead_node`); its other words then hold the `rcu_head`. | `lib/maple_tree.c`, v6.1, v6.14, v6.17. |

### Area names

| # | Fact | Source |
|---|---|---|
| R1 | `/proc/<pid>/maps` names an area, in order: a file area by its path (F5), or at v6.4 onwards by `[anon_shmem:<name>]` when it has an `anon_name`; then `vm_ops->name(vma)` when the operation exists and returns a name; then `arch_vma_name`; `[vdso]` when `vm_mm` is NULL; `[heap]`; `[stack]`; `[anon:<name>]` from `anon_name`. | `fs/proc/task_mmu.c` `show_map_vma` (v4.19, v6.1, v6.4), `get_vma_name` (v6.14, v6.17). |
| R2 | `[heap]` is `vm_start < brk && vm_end > start_brk` at v6.14 and v6.17 (`vma_is_initial_heap`), and `vm_start <= brk && vm_end >= start_brk` at v4.19, v6.1 and v6.4. `[stack]` is `vm_start <= start_stack && vm_end >= start_stack` at every tag. | `include/linux/mm.h`, `fs/proc/task_mmu.c`. |
| R3 | A special mapping's `vm_ops` is `special_mapping_vmops`, whose `name` is `special_mapping_name`, returning `((struct vm_special_mapping *)vm_private_data)->name`; x86 names its vDSO mappings `[vdso]`, `[vvar]` and (v6.14, v6.17) `[vvar_vclock]`. | `mm/mmap.c`; `arch/x86/entry/vdso/vma.c`. |
| R4 | `anon_vma_name.name` is a flexible `char[]` copied with `strndup_user(..., ANON_VMA_NAME_MAX_LEN)`, 80. At v6.1 `anon_name` shares a union with `shared` and is valid only when `vm_file` is NULL (`anon_vma_name` returns NULL for files); from v6.4 it is a member of its own. | `include/linux/mm_types.h`; `mm/madvise.c` v6.1, v6.4, v6.14, v6.17; `kernel/sys.c` v6.1, v6.4, v6.14; `mm/madvise.c` v6.17. |
| R5 | `arch_vma_name` is a weak function returning NULL; x86 does not override it (its gate area is not in the process's tree). | `kernel/signal.c`; `arch/x86/entry/vsyscall/vsyscall_64.c`; v4.19, v6.17. |

### Measurements

| # | Measurement | Data |
|---|---|---|
| X1 | Both tables type every member above that their kernel has, with anonymous unions and structs flattened into the containing type (`vm_area_struct.vm_flags`, `mnt_namespace.mounts`, `mount.mnt_node`, `qstr.len`). mem3 (6.17) has `mount.mnt_t_flags` and `vm_area_struct.anon_name`; mem4 (6.14) has neither. Both have `backing_file.user_path` at 0xb8, `maple_range_64` (pivots at 0x8, slots at 0x80, `meta` at 0xf8), `maple_arange_64` (pivots 0x8, slots 0x50, `meta` 0xf0), and a 256-byte `maple_node`. All eight function symbols of section 2 resolve on both. | `pathfacts -types`, 2026-11-12. |
| X2 | Counts in section 9. Every walk that loses areas does so at a dead node (T6). | `pathfacts`, 2026-11-12. |

## 4. Algorithm

### 4.1 Descriptor tables and files

1. `TaskFDs`: read `task_struct.files`; NULL gives no table. Read `fdt`, then `max_fds` and `fd` (F1). A table that does not read, or whose `max_fds` is over `MaxTableEntries`, gives no table (F2 allows any size the administrator sets).
2. `OpenFiles`: read the `max_fds` slots in order; a NULL slot is not a file. A slot that does not read ends the table with what was read and an error.
3. `FileInode`: `f_inode`; NULL, or a pointer to memory that does not read, gives none.
4. `FileLocation`: `(real_mount(f_path.mnt), f_path.dentry)` (F3, P1). `MappedFileLocation` is `FileLocation` of the backing file's `user_path` when the table has `backing_file` and `f_mode` holds `FMODE_BACKING` (F5).
5. `InodeType` names `i_mode & S_IFMT` by I3 (`REG`, `DIR`, `LNK`, `CHR`, `BLK`, `FIFO`, `SOCK`). `FileMode` renders I4, with `?` for an unknown type.
6. `InodeTimes`: the I1 form the table has; the change time's nanoseconds are masked with I2 when the second form is used. A time is valid when its nanoseconds are below 10^9.
7. Superblocks: device `MAJOR:MINOR` (I5); flags and type by I6 and I7.

### 4.2 Dentry names

1. `DentryName`: read `d_name.len` and `d_name.name`, then `len` bytes. `len` must be at most `MaxNameBytes`, then 1 to `NAME_MAX` (D3).
2. `DentryPath`: D4, the path of a dentry inside its own filesystem.

### 4.3 The path walk

`WalkPath(at, root)`, with `at` and `root` each a `(mount, dentry)` pair, follows P2 in the author's own form:

1. While `at` is not `root`:
   1. Count a step; more than `MaxPathSteps` steps fails.
   2. When the dentry is the mount's `mnt.mnt_root`: if `mnt_parent` is another mount, move to `(mnt_parent, mnt_mountpoint)` and continue. Otherwise the walk ends at a namespace root: **outside the root** when `mnt_ns` is not NULL, not an error pointer (top 4095 values) and not anonymous (`seq` is 0, P5; with no `seq` member every namespace counts as attached), **detached** otherwise.
   3. When `d_parent` is the dentry itself, the walk has **escaped**: its text is dropped.
   4. Otherwise prepend `/` and the dentry's name (4.2), and move to `d_parent`.
2. Reaching `root` ends the walk **at the root**. The text is the prepended names, or `/` when there are none.
3. The text with its NUL must fit `PATH_MAX` (D3, F4).
4. The result keeps the mount it ended in and that mount's `mnt_ns`.

### 4.4 Shown paths

`ShowPath(at, root)` is `d_path` (P3, P4):

1. Read the dentry's `d_op`; when it and its `d_dname` are not NULL, and the dentry is not both `IS_ROOT` and the mount's `mnt_root`, the name is the pseudo name (4.5).
2. Otherwise the text is `WalkPath`'s text, with ` (deleted)` appended when `d_hash.pprev` is NULL and the dentry is not its own parent (D2). The suffix counts toward `PATH_MAX`.

### 4.5 Pseudo names

The `d_dname` pointer is matched against the addresses of the function symbols of section 2:

| `d_dname` | Name | Source |
|---|---|---|
| `pipefs_dname` | `pipe:[<i_ino>]` | Q2 |
| `sockfs_dname` | `socket:[<i_ino>]` | Q2 |
| `anon_inodefs_dname` | `anon_inode:<d_name>` | Q2 |
| `ns_dname` | `<name>:[<i_ino>]`, `name` from `d_inode.i_private` as `ns_common`, its `ops`, and `proc_ns_operations.name` | Q3 |
| `simple_dname` | `/<d_name> (deleted)` | Q4 |
| `dmabuffs_dname` | `/<d_name>:<dma_buf.name>` from `d_fsdata` | Q5 |
| `pidfs_dname` | `anon_inode:[pidfd]` | Q6 |

`i_ino` is that of `d_inode`. All but `simple_dname` fail when the text and its NUL pass 64 bytes (Q1). Any other `d_dname` is not run: the name is unknown.

### 4.6 Mount trees

1. `MountPoints(ns)`: with `mnt_namespace.mounts`, walk the red-black tree in order from `mounts.rb_node` (N1, N2); each node is `mount.mnt_node`. A child whose parent link is not the node, a node already visited, a link that does not read, or more than `MaxListEntries` nodes ends the walk, which is reported. Without `mounts`, walk `list` through `mnt_list` with the S01 list walk.
2. `MountNamespaceInode`: `ns.inum`.
3. The mount accessors read `mnt.mnt_root`, `mnt.mnt_sb`, `mnt.mnt_flags`, `mnt_id`, `mnt_group_id`, `mnt_parent`, `mnt_master` and `mnt_devname` (at most `PATH_MAX` bytes, N3).
4. `MountFlagStrings`: N5's options. `MountPropagation`: N4, from `mnt_t_flags` when the table has it, else from `mnt_flags`.
5. `TaskFSRoot`: `task_struct.fs`, then `fs.root` as `(real_mount(root.mnt), root.dentry)` (F6). A NULL `fs` is `ErrNoRoot`. The walk only compares the root, but a root whose mount or dentry does not read would make every comparison meaningless, so it must read.
6. `DominatingID(mnt, root)`: N6. The master chain and each peer ring are bounded by `MaxListEntries`; the descent test by `MaxPathSteps`.

### 4.7 Memory areas

1. **Shape.** `task_struct.mm`; `vm_area_struct.vm_start`, `vm_end`, `vm_flags`, `vm_pgoff` and `vm_file`; and either `mm_struct.mm_mt` with the maple types of T3, or `mm_struct.mmap` with `vm_area_struct.vm_next`. Otherwise the walker fails.
2. **Tree.** From `mm_mt.ma_root` (T2) visit nodes depth first over `[0, ULONG_MAX]`. For each node: the type must be one of T3's; the node must read; it must not be dead, and below the root its `parent` must name the parent node and the slot it was reached from (T6); for each slot from 0 to the data end (T5) the slot's range is T4's, and it must lie inside the node's range and not be empty. In a leaf a non-NULL, non-internal slot is a candidate area with its range; an internal entry is counted. In an inner node a slot must be an encoded node (T2: `MAPLE_ENODE_NULL` set, a valid type, a non-zero address), visited with the slot's range one level deeper. A node visited twice, a depth over `MAPLE_HEIGHT_MAX`, or more than `MaxListEntries` nodes stops that branch and is counted.
3. **List.** From `mm_struct.mmap` follow `vm_next` until NULL. A link that does not read, a link that leads back, or more than `MaxListEntries` areas ends the list and is counted.
4. **Areas.** Each candidate must read, have `vm_start < vm_end`, both 4096-aligned, and, with `vm_mm` in the table, `vm_mm == mm`. In the tree the stored range must be `[vm_start, vm_end - 1]` (A3); in the list each area must start at or above the previous area's end (A1). A candidate that fails is dropped and counted by rule.
5. **Count.** The number of areas kept is compared with `map_count` (A2); a difference is reported, not an error, since the capture was taken while the process ran.
6. **Names** (R1 to R4), for an area that has been kept:
   1. A file area with an `anon_name` that is its own member (not at the offset of `shared`, R4) and not NULL: `[anon_shmem:<name>]`.
   2. A file area otherwise: `ShowPath(MappedFileLocation(vm_file), the task's root)`.
   3. `vm_ops` and its `name` not NULL: `special_mapping_name` gives `vm_private_data`'s `vm_special_mapping.name`; any other function is not run and the name is unknown.
   4. `arch_vma_name` gives nothing on x86 (R5). `vm_mm` NULL: `[vdso]`.
   5. `[heap]` by the v6.14 rule of R2; `[stack]` by R2.
   6. `anon_name` not NULL: `[anon:<name>]`, the name at most 80 bytes with its NUL (R4).
   7. Otherwise the area has no name.
7. **Rows** (`any.memory.list` on Linux): one per area in address order, process by process in `any.process.list` order.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A name has 1 to `NAME_MAX` bytes | D3 | `ErrName`; the path is not built |
| A path with its NUL fits `PATH_MAX` | D3, F4 | `ErrPathLength` |
| A dentry, its name or a mount on the way does not read | | `ErrPathUnread` |
| More than `MaxPathSteps` steps, or a name over `MaxNameBytes` | Limits | `ErrWalkBound` |
| A pseudo name over 64 bytes | Q1 | `ErrPathLength` |
| An unknown `d_dname` | P4 | `ErrPseudoUnknown`; the name is not given |
| A maple slot range outside its node's range, or empty | T4 | That node's remaining slots are dropped; counted |
| An inner slot that is not an encoded node | T2 | Dropped; counted |
| A dead node | T6 | Dropped with what lies below it; counted |
| A node whose `parent` does not name its parent and slot | T6 | Dropped with what lies below it; counted |
| The task's root mount or dentry does not read | 4.6 step 5 | `ErrPathUnread`; no path is built from that root |
| A leaf slot holding an internal entry | T2 | Not an area; counted |
| An area that does not read, has `vm_start >= vm_end` or unaligned bounds | A1 | Dropped; counted |
| `vm_mm` is not the walked `mm` | A1 | Dropped; counted |
| The stored range is not `[vm_start, vm_end - 1]` | A3 | Dropped; counted |
| A list area starting below the previous area's end | A1 | Dropped; counted |
| A rb-tree child whose parent link is not its parent | N2 | The mount walk ends; reported |

## 6. Failure modes

| Case | Result |
|---|---|
| `task_struct.mm`, the area members or both area containers missing | `memoryranges.ErrLinuxShape` wrapping the member; the tool fails |
| `struct mount` or `mount.mnt` missing | `linuxobj.ErrUnsupported` |
| `mm` NULL | No areas (kernel thread) |
| `mm_struct` does not read | The process is listed with no areas and a diagnostic; strict mode makes it an error of the tool |
| Counted area losses (4.7 steps 2 to 4) | One `AreaLosses` error per process with counts per rule; rows that were kept are returned; strict mode makes it an error of the tool |
| `map_count` differs from the walk | Part of the same report |
| A path that is not built | `memoryranges.IsPathUnresolved(err)`; the row's path is empty and flagged, and the tool counts it |
| Strict mode | `any.memory.list`: any area loss is an error; names that are not built stay diagnostics. `linux.file.list_open`: a path that is not built is an error. |

Diagnostics take the form `<tool>: pid <n> (<comm>): <what failed>: <detail>`. `any.memory.list` adds one summary for names that were not built: `<tool>: <n> memory areas whose name was not built, Path left empty; first in pid <n> (<comm>)`.

## 7. Result schema

`any.memory.list` on Linux, `memoryranges.Mapping`:

| Field | Meaning |
|---|---|
| `PID`, `Process` | From `any.process.list` |
| `Start`, `End` | `vm_start` and `vm_end - 1` (inclusive end, as on Windows) |
| `Protection` | `r`, `w`, `x` or `-` for each of A4's bits |
| `Type` | `file` when `vm_file` is set, else `anonymous` |
| `VadAddress` | The `vm_area_struct` address |
| `PageOffset` | `vm_pgoff << 12` for a file area, else 0 |
| `Inode`, `Major`, `Minor` | F5's inode number and its superblock device (I5) for a file area |
| `Path` | 4.7 step 6's name; empty when there is none |
| `PathUnreadable` | The name could not be built (sections 5, 6) |

`linux.file.list_open` and `linux.mount.list` keep their rows. Their `Path` and `MountPoint` come from 4.4 (`files_only` keeps walked paths only and gives an empty path for a pseudo file) and from `__d_path` (4.3, only an at-the-root walk is shown).

## 8. Limits

- `MaxPathSteps`: steps of a path walk and of the descent test in 4.6 step 6.
- `MaxNameBytes`: one dentry name.
- `MaxListEntries`: maple-tree nodes per process, list areas per process, rb-tree nodes per namespace, the master chain and each peer ring.
- `MaxTableEntries`: descriptor slots per table.

`PATH_MAX`, `NAME_MAX`, the 64-byte `dynamic_dname` buffer, `DMA_BUF_NAME_LEN` and `ANON_VMA_NAME_MAX_LEN` are kernel limits (D3, Q1, Q5, R4) and are not configurable.

## 9. Acceptance

- Synthetic fixtures (`tools/linuxobj` and `tools/any/memoryranges` tests): a path across two mounts; a path from a chroot root; a path whose mount chain ends in another namespace, in an anonymous namespace and in no namespace; an escaped dentry; a deleted file; every pseudo name of 4.5 and an unknown one; a mounted pseudo root; the step, name and `PATH_MAX` limits; rb-tree and list namespaces, a broken rb-tree parent link; propagation from both flag forms and a dominating peer; both inode time forms with `I_CTIME_QUERIED`; a maple tree of two levels with `arange_64` and `leaf_64` nodes, metadata ends, a full node, an internal entry, a slot past its node's range, a stored range that is not the area's, a dead node, a wrong parent link, an inner slot that is not a node, the node cap and a node read twice; a VMA list out of order and one that loops; each area name of 4.7 step 6.
- Fuzz targets: `FuzzMapleTree` (arbitrary node bytes always end, within `MaxListEntries`), `FuzzPathWalk` (arbitrary dentry and mount bytes always end, within `MaxPathSteps`), `FuzzFileMode` (I4 rendering is ten characters for any mode).
- On both captures, measured with `pathfacts`, 2026-11-12: see the table below.

| | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| Task leaders; address spaces | 203; 115 | 242; 123 |
| Areas; file-backed | 29509; 25203 | 31605; 26069 |
| Areas per address space | 6 to 1417, median 156 | 14 to 1510, median 162 |
| Maple nodes read; deepest leaf | 2745; level 4 | 2955; level 4 |
| Trees whose depth differs from the `ma_flags` height | 0 | 0 |
| Walk count equal to `map_count` | 114 of 115 | 122 of 123 |
| Areas lost | 1 dead node in the process that was taking the capture: 6 of its 15 areas kept | 1 dead node in `gnome-shell`: 1510 of 1517 kept |
| Other loss rules (range, parent, internal entry, bounds, owner, stored range) | 0 | 0 |
| Anonymous area names | `[heap]` 115, `[stack]` 115, `[vdso]` 114, `[vvar]` 114, `[vvar_vclock]` 114, `[anon:...]` 69 (all `containerd`), none 3665 | `[heap]` 127, `[stack]` 123, `[vdso]` 123, `[vvar]` 123, `[vvar_vclock]` 123, `[anon:...]` 0 (no `anon_name` member), none 4917 |
| File area paths | at the root 25015 (2 ` (deleted)`), outside the root 145 (all `avahi-daemon`, which runs chrooted), in another namespace 1, `simple_dname` 40 (`/memfd:... (deleted)`) | 25899 (4 deleted), 122 (`avahi-daemon`), 2, 42 |
| Descriptor tables; open files | 116; 2147 | 124; 2721 |
| Open file names | `sockfs_dname` 1013, `anon_inodefs_dname` 545, `pidfs_dname` 186, `pipefs_dname` 48, `simple_dname` 28, `ns_dname` 3; walked at the root 286 (2 deleted), outside the root 1, in another namespace 35 (`/dev/dri/card1` and `/dev/input/event*` held by `systemd`) | 1082, 554, 381, 33, 28, 2; 596 (3 deleted), 1, 41 |
| Paths not built; dentries that do not read | 0; 0 | 0; 0 |
| Unknown `d_dname` or `vm_ops->name` functions | 0 | 0 |
| Mount namespaces | 17, all red-black trees, none cut; 2 to 460 mounts | 23, all trees, none cut; 2 to 57 mounts |
| Mount points shown from the first task of each namespace | all but one (the namespace's own root mount, above the task's root) in 16; 3 of 52 in one whose first task is chrooted | all but one in 22; 3 of 34 in one |
| `any.memory.list`; rows without a name | 29509; 0 | 31605; 0 |
| `linux.file.list_open` rows (every thread); with no path | 8530; 0 | 8865; 0 |
| `linux.mount.list` rows | 1348 | 888 |

Both dead nodes have their `parent` pointing at themselves and a kernel address in the first pivot, which T6 explains: the `rcu_head` overlays the pivots once a node is retired. The walk count equals `map_count` in every other address space on both captures.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision: paths are built from the task's own root, as the process itself would read `/proc/self/fd`. A path that ends outside that root (in another namespace, or above a chroot) keeps the text the kernel prints for it (P3) and is counted. Building from the initial task's root would give the host's view instead. | Owner choice |
| O2 | Owner decision: `[heap]` uses the v6.14 and v6.17 rule of R2 on every kernel; on v4.19 to v6.4 an area that only touches the heap's bounds is named `[heap]` by the kernel and not here. | A version source, or an owner choice |
| O3 | Owner decision: `linux.file.list_open.files_only` gives an empty path for a pseudo file instead of the walk of its unmounted dentry. | Owner choice |
| O4 | `vm_ops->name` functions other than `special_mapping_name`, and `d_dname` functions other than those of 4.5, are not run; such names are reported as unknown. | A capture that holds one |
| O5 | The VMA list (v4.19) and the v4.19 `prepend_path` are checked by fixtures only; no capture runs a kernel before 6.1. | A v4.19 capture (Q7) |
| O6 | Owner decision: `Mapping.Type` keeps `file` and `anonymous`, and `Protection` keeps the three `rwx` characters without the `s`/`p` column of A4. | Owner choice at the final stage |
| O7 | Owner decision: an anonymous area the kernel does not name has an empty name. `any.memory.find_code` therefore shows such areas as `N/A`, and `linux.memory.list_elf_files` gives an anonymous ELF mapping no path, where both printed `<anonymous>` before. | Owner choice |
| O8 | Owner decision: a dentry or mount that does not read leaves that one path empty and counted; `linux.file.list_open` no longer cuts the task's table there, and strict mode fails on it instead. | Owner choice |
| O9 | Owner decision: a deleted file is shown as `<path> (deleted)` from the dentry's hash link (D2), not from `i_nlink`; `linux.process.check_identity` sees the same text. An inode number of 0 no longer marks an open file's inode as unusable. | Owner choice |
| O10 | Pseudo names are matched by the addresses of the function symbols of section 2; a table without them reports every pseudo file as unknown. The tables of both captures have them (X1). | A capture without the symbols |
| O11 | The dead nodes of X2 lose the areas below them; the kernel's own reader retries from the root, which a capture cannot do. | None; a property of live acquisition |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Task's own root |
| O2 | Use the later rule everywhere |
| O3 | Empty path |
| O4 | Do not run; report unknown |
| O5 | Defer; fixtures only |
| O6 | Keep as is |
| O7 | Empty name |
| O8 | Empty and counted; table continues |
| O9 | Use the dentry hash link |
| O10 | Defer; both captures have them |
| O11 | Accept the loss |

## 11. Provenance

Written from the kernel sources at the tags in section 3, POSIX.1-2017 and the project's measurements. The sources were fetched from `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12. Every rule rests on the sources and measurements above.
