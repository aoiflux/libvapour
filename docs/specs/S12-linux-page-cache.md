# S12: Linux page cache: inode enumeration, page walk, file recovery and archive output

Version 1, 2026-11-12.

## 1. Purpose

The Linux kernel keeps recently read and written file data in memory, in the page cache of each file's inode, and it keeps the inodes themselves on per-superblock lists. An examiner wants three things from a memory image: which files the kernel held, with their paths, owners and times; which pages of one file were cached and where they sit in physical memory; and the cached content itself, as files that can be opened. This specification defines how the superblocks, inodes, names and mount points are found, how an inode's cached pages are walked and checked, how file content is rebuilt from them, and how the result is written as a POSIX tar archive.

The xarray and radix-tree walk is S02, the list walk is S01, and artefact names are S00.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel reader | `linuxwalk.Reader` from the session (S01, S02) | Kernel memory in the 48-bit address form, the symbol table, Limits. |
| Physical layer | `memory.MemoryReader`, optional | The session's physical memory, for page frames. |
| Paging mode | session option | `la57` selects the 5-level struct page array base when `vmemmap_base` is missing (F18). |
| Symbol table | symbols | `super_blocks`, `vmemmap_base`, `page_offset_base`, `init_task`, the enum `pageflags`, and the types of section 3. |
| Limits | effective `limits.Limits` | Section 8. |
| Options | tool options | Section 7. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17, from git.kernel.org, accessed 2026-11-12. A fact cites the tags where it was read; "all tags" means all five.

### Superblocks, inodes and names

| # | Fact | Source |
|---|---|---|
| F1 | `super_blocks` is a `static LIST_HEAD` in `fs/super.c`. Every superblock is added with `list_add_tail(&s->s_list, &super_blocks)` when it is created, and removed with `list_del_init(&s->s_list)` in `__put_super`. | `fs/super.c`, all tags. |
| F2 | The kernel's own superblock iterators skip a superblock whose `s_root` is null or that is not `SB_BORN` (v6.17 also skips `SB_DYING`). | `fs/super.c` `iterate_supers` and siblings, v4.19, v6.17. |
| F3 | `struct super_block` has `struct list_head s_list` (first member), `dev_t s_dev`, `struct file_system_type *s_type`, `struct dentry *s_root`, `struct list_head s_mounts`, `char s_id[32]`, `uuid_t s_uuid` and `struct list_head s_inodes`. `file_system_type.name` is a `const char *`. | `include/linux/fs.h`, all tags. |
| F4 | `struct inode` has `umode_t i_mode`, `kuid_t i_uid`, `kgid_t i_gid`, `struct super_block *i_sb`, `struct address_space *i_mapping`, `unsigned long i_ino`, `loff_t i_size`, `struct list_head i_sb_list`, `struct hlist_head i_dentry` (in a union), `struct address_space i_data` and `char *i_link` (in a union with `i_pipe`, `i_cdev` and `i_dir_seq`). The times are `struct timespec64 i_atime, i_mtime, i_ctime` at v4.19, v6.1 and v6.4, and `time64_t i_atime_sec, i_mtime_sec, i_ctime_sec` with `u32 i_atime_nsec, i_mtime_nsec, i_ctime_nsec` at v6.14 and v6.17. At v6.14 and v6.17 `I_CTIME_QUERIED` is `BIT(31)` of `i_ctime_nsec`, and `inode_get_ctime_nsec` masks it off. | `include/linux/fs.h`, all tags. |
| F5 | `inode_sb_list_add` links an inode onto its superblock with `list_add(&inode->i_sb_list, &sb->s_inodes)`. `inode_init_always` sets `mapping->host = inode` and `inode->i_mapping = &inode->i_data`. | `fs/inode.c`, v4.19, v6.17. |
| F6 | `struct dentry` has `struct dentry *d_parent`, `struct qstr d_name` (`len` and `const unsigned char *name`) and a union `d_u` holding `struct hlist_node d_alias`. `IS_ROOT(x)` is `((x) == (x)->d_parent)`. `__d_alloc` sets `d_parent` to the dentry itself and NUL-terminates the name at `len`. | `include/linux/dcache.h`, all tags; `fs/dcache.c` `__d_alloc`, v4.19, v6.17. |
| F7 | When a symlink is followed, the kernel uses `inode->i_link` first and calls the filesystem's `get_link` only when it is null. | `fs/namei.c` (`res = inode->i_link`, v4.19; `READ_ONCE(inode->i_link)`, v6.17). |
| F8 | `page_get_link`, for symlinks kept in the page cache, reads page 0 of the mapping and terminates it with `nd_terminate_link(kaddr, inode->i_size, PAGE_SIZE - 1)`, which writes a NUL at `min(i_size, PAGE_SIZE - 1)`. | `fs/namei.c`, v4.19, v6.17; `include/linux/namei.h`, v6.17. |
| F9 | A dentry is attached to its inode with `hlist_add_head(&dentry->d_u.d_alias, &inode->i_dentry)`. | `fs/dcache.c` `__d_instantiate`, v4.19, v6.17. |
| F10 | `struct mount` has `struct mount *mnt_parent`, `struct dentry *mnt_mountpoint`, `struct vfsmount mnt` (with `struct dentry *mnt_root`), `struct list_head mnt_instance` ("mount instance on sb->s_mounts") and `struct mnt_namespace *mnt_ns`. Mounts are added with `list_add_tail(&mnt->mnt_instance, &sb->s_mounts)`. Internal mounts get `mnt_ns = MNT_NS_INTERNAL`, defined as `ERR_PTR(-EINVAL)`. | `fs/mount.h`, `fs/namespace.c`, all tags. |
| F11 | `init_mount_tree` sets `init_task.nsproxy->mnt_ns` to the initial mount namespace. | `fs/namespace.c`, all tags. |
| F12 | A path is built by walking up from a dentry: at a mount's `mnt_root`, the walk moves to `mnt_mountpoint` in `mnt_parent`, unless the mount is its own parent (the namespace root); otherwise each dentry's name is prepended with `/` and the walk moves to `d_parent`. A dentry that is its own parent before a mount root is reached has escaped. | `fs/d_path.c` `__prepend_path`, v6.17, and `prepend_path`, v4.19. |
| F13 | `kuid_t` is a structure whose one member `val` is a `uid_t`; `kgid_t` is the same with `gid_t`. | `include/linux/uidgid.h`, v4.19; `include/linux/uidgid_types.h`, v6.17. |
| F14 | The devtmpfs kernel thread first unshares its mount namespace, then mounts devtmpfs at `/` in that namespace; the devtmpfs mount at `dev` is made separately. | `drivers/base/devtmpfs.c`, v6.1, v6.14, v6.17. |

### Page cache

| # | Fact | Source |
|---|---|---|
| P1 | `struct address_space` has `struct inode *host`, the tree of cached pages `i_pages` and `unsigned long nrpages`. `i_pages` is a `struct radix_tree_root` at v4.19 and a `struct xarray` from v6.1. The v6.17 comment calls `i_pages` "Cached pages" and `nrpages` the "Number of page entries". | `include/linux/fs.h`, all tags. |
| P2 | v4.19 adds a page with `page->mapping = mapping; page->index = offset;` and one radix entry. Shmem adds a transparent huge page as `HPAGE_PMD_NR` entries, `page + i` at `index + i`, with only the head given `mapping` and `index`. | `mm/filemap.c` `__add_to_page_cache_locked`, `mm/shmem.c` `shmem_add_to_page_cache`, v4.19. |
| P3 | From v6.1 a folio is added as one multi-index entry: `xas_set_order(&xas, index, folio_order(folio))`, `folio->mapping = mapping`, `folio->index = xas.xa_index`, then `xas_store(&xas, folio)`, and `nrpages` grows by the folio's page count. | `mm/filemap.c` `__filemap_add_folio`, v6.1, v6.4, v6.14, v6.17; `mm/shmem.c`, v6.17. |
| P4 | `struct page` has `unsigned long flags`, `struct address_space *mapping`, `unsigned long compound_head` ("Bit zero is set") and `pgoff_t index`; at v6.17 the index member is `__folio_index`. `struct folio` exists from v6.1 and overlays the head page with `flags`, `mapping` and `index`. | `include/linux/mm_types.h`, all tags. |
| P5 | `set_compound_head` stores `head + 1` in a tail page's `compound_head`, and `compound_head()` gives `head - 1` when bit 0 is set. | `include/linux/page-flags.h`, all tags. |
| P6 | `enum pageflags` ends with `__NR_PAGEFLAGS`; several names alias one bit (for example `PG_checked = PG_owner_priv_1`). The bits of `page->flags` above the flags hold the section, node, zone and other fields. | `include/linux/page-flags.h`, all tags; `include/linux/page-flags-layout.h`, v6.1, v6.4, v6.17 ("page->flags layout"); `include/linux/mm.h`, v4.19. |
| P7 | With `CONFIG_SPARSEMEM_VMEMMAP`, `__pfn_to_page(pfn)` is `vmemmap + (pfn)` and `__page_to_pfn(page)` is `page - vmemmap`. | `include/asm-generic/memory_model.h`, all tags. |
| P8 | On x86-64 `VMEMMAP_START` is `vmemmap_base` (v4.19: under `CONFIG_DYNAMIC_MEMORY_LAYOUT`, else `__VMEMMAP_BASE_L4`). `__VMEMMAP_BASE_L4` is 0xffffea0000000000 and `__VMEMMAP_BASE_L5` 0xffd4000000000000. `vmemmap_base` and `page_offset_base` are `unsigned long` variables. | `arch/x86/include/asm/pgtable_64_types.h`, all tags; `arch/x86/kernel/head64.c`, v4.19, v6.17. |
| P9 | The x86-64 memory map gives the virtual memory map (`vmemmap_base`) 1 TB from 0xffffea0000000000 with 4-level tables and 0.5 PB from 0xffd4000000000000 with 5-level tables, and the direct mapping of all physical memory at `page_offset_base`. With `CONFIG_RANDOMIZE_MEMORY` these bases are randomised at boot. | `Documentation/x86/x86_64/mm.txt` v4.19, `Documentation/x86/x86_64/mm.rst` v6.1, `Documentation/arch/x86/x86_64/mm.rst` v6.4, v6.14, v6.17. |
| P10 | `MAX_XAS_ORDER` is `XA_CHUNK_SHIFT * 2 - 1` and `MAX_PAGECACHE_ORDER` is at most it (v6.14, v6.17). At v6.1 and v6.4 `MAX_PAGECACHE_ORDER` is `HPAGE_PMD_ORDER` or 8. | `include/linux/pagemap.h`, v6.14, v6.17; `mm/readahead.c`, v6.1, v6.4. |

### Values and formats

| # | Fact | Source |
|---|---|---|
| V1 | `S_IFMT` 0170000; `S_IFSOCK` 0140000, `S_IFLNK` 0120000, `S_IFREG` 0100000, `S_IFBLK` 0060000, `S_IFDIR` 0040000, `S_IFCHR` 0020000, `S_IFIFO` 0010000; `S_ISUID` 04000, `S_ISGID` 02000, `S_ISVTX` 01000. | `include/uapi/linux/stat.h`, v4.19, v6.17. |
| V2 | `MINORBITS` is 20; `MAJOR(dev)` is `dev >> MINORBITS`, `MINOR(dev)` `dev & MINORMASK`. | `include/linux/kdev_t.h`, v4.19, v6.17. |
| V3 | The ls long format's mode field: one entry-type character (`d`, `b`, `c`, `l`, `p`, `-`; others implementation-defined), then three `rwx` triplets; `s`/`S` mark set-user-ID or set-group-ID with or without execute, `t`/`T` the sticky bit on a directory. | IEEE Std 1003.1-2017, XCU `ls`, STDOUT. |
| V4 | ustar headers are 512-byte blocks with `magic` "ustar\0" at offset 257 and `version` "00" at 263; `name` is 100 bytes and `prefix` 155; typeflag `0` regular, `2` symbolic link, `5` directory. A pax extended header (typeflag `x`) carries `path`, `linkpath`, `size`, `uid`, `gid`, `mtime`, `atime` and `ctime` records that the ustar fields cannot hold. | IEEE Std 1003.1-2017, XCU `pax`, "ustar Interchange Format" and "pax Interchange Format". |
| V5 | gzip member format. | RFC 1952. |
| V6 | A path component is at most 255 bytes (`NAME_MAX`). | S00 C6. |

### Measurements

Measured with `pagecachefacts`, 2026-11-12, on mem3_ubuntu24 (kernel 6.17) and mem4_fedora40 (kernel 6.14).

| # | Measurement | Data |
|---|---|---|
| M1 | Both symbol tables type every F3, F4 (split time form), F6, F10, F13 and P1 member named above; `address_space.i_pages` is an `xarray`; `xa_node.slots` has 64 elements; `struct page` is 64 bytes. mem3 has `page.__folio_index` and `folio.index`; mem4 has `page.index` and `folio.index`. Both have `page.compound_head`, the symbols `super_blocks`, `vmemmap_base`, `page_offset_base` and `init_task`, and the enum `pageflags` with `__NR_PAGEFLAGS` 25 (43 and 42 names). | `-shapes` output. |
| M2 | `d_u` is typed as an anonymous union (`unnamed_dentry::d_u`), reached by member name. | Same. |
| M3 | Both captures were taken by a module writing the image to a file on the captured system (`/home/mew/Downloads/ubuntu24.lime`, `/home/mew/Downloads/fedora40.lime` are in the cache). Inode lists and page trees changed during acquisition: section 9 shows lists that break and tree entries whose pages now belong to other mappings or are free (`mapping` 0, `lru` holding the list poison). | Section 9. |

## 4. Algorithm

### 4.1 Superblocks

1. Walk `super_blocks` with the S01 list walk, container `super_block`, member `s_list` (F1). When the forward walk does not close, also walk backward from the head and append, in list order, the entries the forward walk did not reach (M3: a list caught while it changed can break in one direction only). The break is a diagnostic in both cases.
2. Read each superblock. One with a null `s_root` is skipped and counted (F2).
3. The filesystem type is the string at `s_type->name`; the device is `MAJOR(s_dev):MINOR(s_dev)` (V2); the ID is `s_id` up to its first NUL.

### 4.2 Mounts and mount points

1. Walk `s_mounts` (container `mount`, member `mnt_instance`) as in 4.1 step 1 (F10).
2. Skip a mount whose `mnt_ns` is null or `MNT_NS_INTERNAL` (F10).
3. The mount's root is the path of its `mnt.mnt_root` from the superblock's root (4.3). Its point is the F12 walk from `(mnt_root, mount)` up to the mount that is its own parent. A walk that escapes, does not read, or passes `MaxPathSteps` drops the mount.
4. A superblock's views are its mounts with distinct roots: those whose `mnt_ns` is the initial namespace (`init_task.nsproxy->mnt_ns`, F11) first, then, within each group, the deepest root first. Where mounts share a root, the view is the first of them in the initial namespace, else the first in list order (F14: a devtmpfs superblock also has a mount at `/` in its kernel thread's own namespace).

### 4.3 Names

1. An inode's name is its first alias: `i_dentry.first`, minus the offset of `d_u.d_alias` in `dentry` (F9).
2. The path from the superblock's root: walk `d_parent` until a dentry is its own parent (F6), prepending `/` and each `d_name`. The path is `/` for the root itself. Paths of dentries already walked are kept and reused.
3. A name must be 1 to 255 bytes (V6), must not hold `/` or NUL, and must not be `.` or `..`; otherwise `ErrName`. A chain that ends at a dentry other than the superblock's `s_root` is `ErrDetached`. More than `MaxPathSteps` dentries is `ErrPathSteps`. In these cases the inode is listed with an empty path. A dentry on the chain that does not read, or a name that does not read, is `ErrUnread`: the inode is skipped and counted as an unread inode, not listed (O15). The per-superblock diagnostic counts `ErrName` and `ErrPathSteps` inodes together and labels them all `ErrName` (O13).
4. The full path uses the first view (4.2 step 4) whose root is the path or a component-wise prefix of it: the view's point joined with the rest of the path. The row's mount point is that view's point. With no such view, the full path is the path from the superblock's root and the mount point is empty.

### 4.4 Inodes

1. Walk `s_inodes` (container `inode`, member `i_sb_list`, F5) as in 4.1 step 1.
2. Read each inode. One whose `i_sb` is not this superblock is `ErrForeign`: skipped and counted.
3. Read `i_mode`, `i_uid.val`, `i_gid.val`, `i_ino`, `i_size` (signed), `i_mapping`, and `i_link` for a symlink (F4, F13). The type is the V1 `S_IFMT` value, named by its `S_IF` suffix (`REG`, `DIR`, `LNK`, `CHR`, `BLK`, `FIFO`, `SOCK`), or empty for any other value.
4. Times: the split form when `i_atime_sec` exists, else the `timespec64` form (F4). `ctime`'s nanoseconds lose bit 31 (F4). A time whose nanoseconds are 10^9 or more is absent.
5. `CachedPages` is `i_mapping->nrpages` (P1); `Pages` is `ceil(i_size / 4096)` for a positive size, else 0.

### 4.5 The cached pages of a mapping

1. **Layout.** The page owner type is `folio` when it has `flags`, `mapping` and `index`, else `page` (P4). The struct page array base is the value of `vmemmap_base`, or `__VMEMMAP_BASE_L4` (`__VMEMMAP_BASE_L5` with `la57`) when the symbol is missing (P8). The array spans 1 TB, or 0.5 PB with `la57` (P9).
2. **Walk.** Walk `address_space.i_pages` with S02, using the member's type to choose the layout. Value entries (shadow and swap entries) are counted, not pages.
3. **Check.** For an entry *e* at index *i*:
   1. *e* must lie in the array (`ErrPageOutside`) at a multiple of `sizeof(struct page)` from its base (`ErrPageMisaligned`), and its `struct page` must read (`ErrPageUnread`).
   2. If bit 0 of its `compound_head` is set, *e* is a tail page (P2, P5): its owner is `compound_head − 1`, which must pass step 1, and its offset is `(e − owner) / sizeof(struct page)`. Otherwise the owner is *e* and the offset 0.
   3. The owner's `mapping` must be this mapping (`ErrPageMapping`), and the owner's `index` plus the offset must be *i* (`ErrPageIndex`). A tail below its owner is also `ErrPageIndex`.
4. **Folio pages.** An accepted head *e* stands for its tail pages too (P3): pages *e* + *j* × `sizeof(struct page)`, *j* = 1, 2, …, at index *i* + *j*, while the page reads and its `compound_head` is *e* + 1. The count is bounded by 2^11 (P10, with the 64-slot nodes of M1), by the next entry's index, and, for the last entry, by the file's page count (at least 1). Tails share the head's flags.
5. **Frame.** A page's frame number is `(page − base) / sizeof(struct page)` (P7); its physical address is that times 4096. Its bytes come from the physical layer, or, without one, from `page_offset_base + physical` (P9). With neither, `ErrNoFrameReader`.
6. **Flags.** The names of bit *b* of the owner's flags, for *b* below `__NR_PAGEFLAGS`, are every enum name of value *b* that does not start with `__`, in table order (P6).
7. Pages are listed in index order.

### 4.6 Content

A file of size *s* is rebuilt as exactly *s* bytes: each accepted page at offset `index × 4096`, cut at *s*, and zeros wherever no page is cached or a frame does not read.

### 4.7 Symlink targets

The target is the NUL-terminated string at `i_link` (F7), read up to `MaxNameBytes`. With a null `i_link`, it is the frame of page 0, cut at `min(i_size, 4095)` and at its first NUL (F8). An empty or unavailable target is `ErrNoLinkTarget`.

### 4.8 Archive

1. One gzip member (V5) holding a tar stream whose headers are ustar, with pax extended headers where a field does not fit (V4).
2. Each superblock gets a top directory `<fstype>.<major>.<minor>`, with the type mapped by the S00 label rule (`unknown` when the label is empty); a name already used gets `.0x<superblock address, 16 digits>` added.
3. For every named inode (4.3) of type `DIR`, `REG` or `LNK`, in 4.4 order, one member at the top directory joined with the path from the superblock's root (`/` maps to the top directory itself):
   - `DIR`: a directory member, its name ending in `/`.
   - `LNK`: a symbolic link member with the 4.7 target; skipped without one.
   - `REG`: a regular member with the 4.6 content; skipped when no accepted page lies inside the size (`ErrNotCached`), when the size is above the dump limit (`ErrTooLarge`), or when the size is above what the archive limit leaves after the regular members already written (`ErrArchiveFull`). The archive's total is the sum of its regular members' sizes; headers are not counted. A later, smaller file that still fits is written.
4. Header fields: mode `i_mode & 0777`, uid and gid, mtime (the Unix epoch when absent), and atime and ctime when present. The set-user-ID, set-group-ID and sticky bits are dropped, so that extraction cannot carry them onto the examiner's host.
5. A member name already written gets `.0x<inode address, 16 digits>` added.
6. A member with a symlink member as a proper prefix, and a symlink whose name is a prefix of a member already written, are refused with `ErrThroughLink`, so that no extractor writes through a link.
7. `tmpfs_only` keeps the superblocks whose type is `tmpfs`; the top directory names are chosen over all superblocks first.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A superblock has a root | F2 | Skipped, counted in one diagnostic |
| An inode names its superblock | F5 | `ErrForeign`: skipped, counted |
| Names are 1 to 255 bytes with no `/` or NUL, not `.` or `..` | F6, V6 | `ErrName`: listed without a path |
| A name chain ends at the superblock's root | F6, F12 | `ErrDetached`: listed without a path |
| A name chain has at most `MaxPathSteps` dentries | Limits | `ErrPathSteps`: listed without a path; counted under the `ErrName` text (O13) |
| Every dentry and name on the chain reads | F6 | `ErrUnread`: the inode is skipped and counted as unread (O15) |
| A page entry lies on the struct page array | P7, P8, P9 | `ErrPageOutside`, `ErrPageMisaligned` |
| The owner's mapping and index match the tree | P2, P3 | `ErrPageMapping`, `ErrPageIndex` |
| A time's nanoseconds are below 10^9 | F4 | Time absent |
| Only flag bits below `__NR_PAGEFLAGS` are named | P6 | Higher bits ignored |
| Archive members never pass through a symlink member | V4; extraction safety | `ErrThroughLink` |

## 6. Failure modes

| Case | Result |
|---|---|
| `super_blocks` missing | `ErrNoSuperBlocks` |
| A required member missing, or pointers not 8 bytes | Error wrapping `linuxwalk.ErrUnsupported` |
| A list walk that does not close | Diagnostic with the end and place (`ErrWalk`), then the backward walk's addition |
| Structures that do not read, foreign or unnamed inodes | Counted, one diagnostic per superblock and reason: `<tool>: super_block at 0x<addr>: <n> inodes: <reason>`. An inode whose dentry or name does not read counts as unread (O15); `ErrPathSteps` inodes count under the `ErrName` reason (O13) |
| Rejected page entries, unread or inconsistent tree nodes, a capped walk | One diagnostic per mapping with each count. Pages cut by the `MaxTableEntries` cap are not counted, so a capped walk with no rejected entry adds 0 to the strict-mode count (O14) |
| Frames that do not read | Zeros in the content; one diagnostic per file |
| `list_pages` with neither or both targets | `ErrNoTarget`, `ErrTwoTargets` |
| `list_pages.inode` not an inode of a listed superblock | `ErrNotInode` (or `ErrUnread`, `ErrForeign`) |
| A dump without `output_dir` | `ErrNoOutputDir` |
| `compression_format` other than empty or `gz` | `ErrCompression` |
| A file over the dump limit | `ErrTooLarge`, skipped; one diagnostic with the count |
| A file over what the archive limit leaves of the archive | `ErrArchiveFull`, skipped; one diagnostic with the count |
| The archive file exists | `extract.ErrArtifactExists` |
| Strict mode | `ErrStrict` when any list broke, a superblock or inode did not read, an inode was foreign or had no usable path, a mapping's pages or tree nodes were rejected or did not read (a walk cut only by the `MaxTableEntries` cap does not count, O14), a frame did not read, or a file was too large, did not fit in the archive, or was refused; uncached files and symlinks without a target do not count |

## 7. Result schema

`linux.pagecache.list_files`, one row per inode, in superblock list order then inode list order:

| Field | Meaning |
|---|---|
| `SuperBlockAddress`, `InodeAddress` | Addresses in the 48-bit form |
| `FSType`, `Device` | 4.1 step 3 |
| `MountPoint` | 4.3 step 4; empty when no view shows the inode |
| `InodeNumber` | `i_ino` |
| `Type` | `REG`, `DIR`, `LNK`, `CHR`, `BLK`, `FIFO`, `SOCK`, or empty |
| `Mode` | V3 string; `?` as the type character for an unknown type, `s` for a socket |
| `UID`, `GID` | `i_uid.val`, `i_gid.val` |
| `Size` | `i_size`, bytes, signed |
| `Pages`, `CachedPages` | 4.4 step 5 |
| `Accessed`, `Modified`, `Changed` | UTC times, each with an `…OK` flag that is false when absent |
| `Path` | 4.3 step 4; empty when unnamed |

`linux.pagecache.list_pages`, one row per accepted page in index order: `InodeAddress`, `MappingAddress`, `PageAddress` (the `struct page`), `Physical`, `Index`, `Offset` (index × 4096), `Flags` (4.5 step 6, joined by `,`), `File` (the S00 `inode` artefact name when dumped, else empty).

`linux.pagecache.dump_files`, one row per archive member: the list_files fields, `Member` (the name in the archive), `MemberSize` (bytes of a regular member) and `RecoveredBytes` (of them, bytes from cached frames).

Options (keys unchanged): `linux.pagecache.list_files.type` (list of type names, case-insensitive), `linux.pagecache.list_files.find` (exact full path); `linux.pagecache.list_pages.inode` (inode address), `.find` (full path; every inode with it), `.dump` (bool); `linux.pagecache.dump_files.tmpfs_only` (bool), `.compression_format` (empty or `gz`).

The archive is written to `output_dir` as `pagecache.kernel.tar.gz`, the S00 kind `pagecache` with scope `kernel` and extension `tar.gz` (O5).

## 8. Limits

- `MaxListEntries`: each list walk, in each direction.
- `MaxTableEntries`: tree entries and nodes (S02), and accepted pages per mapping.
- `MaxPathSteps`: dentries per name, and steps of a mount point walk.
- `MaxNameBytes`: symlink targets at `i_link`.
- The dump limit (`max_dump_size` when set and below `MaxArtifactBytes`, else `MaxArtifactBytes`): bytes of one `list_pages` dump file and of one regular archive member.
- The archive limit (`MaxArchiveBytes`, default 16 GiB): bytes of all regular archive members together (O8, D4). Most of a member's bytes can be the zeros of uncached holes (4.6), so a bound equal to the member bound dropped small files once a few large ones were written: with 1 GiB, 186 of 1302 files on mem3 and 313 of 868 on mem4, `/etc/passwd` among them. The default is above both captures' totals (4.44 and 2.35 GB, section 9). `max_dump_size` does not change it.

## 9. Acceptance

- Synthetic fixtures (`tools/linuxkern/kerntest/s12_fixture.go`): a root filesystem and a tmpfs mounted on it; a regular file with a hole, fast and page symlinks, a set-user-ID file, an uncached file and an unnamed inode; both time layouts with `I_CTIME_QUERIED` and an out-of-range nanosecond value; a detached dentry and a foreign inode; an inode list broken forward; entries failing each 4.5 step 3 rule; a folio of order 2 with sibling slots; a v4.19-style tail entry; frames from the physical layer, the direct map, and neither; the array base with and without `vmemmap_base`; the `MaxTableEntries` cap; an archive checked for the ustar magic, member types, content, link targets and dropped special bits; a member under a symlink and a duplicate name; the dump limit hit by one member and the archive limit by the total, each with its diagnostic and strict failure, and a default archive limit above the member limit.
- Fuzz targets: `FuzzPages` (tree slots and struct pages, `tools/linuxobj`) and `FuzzFiles` (inode, dentry and mount bytes through all three tools, `tools/linux/pagecache`), 30 s each.
- No host ground truth exists for either capture: the counts below are what this specification reads, and the content checks are structural only.

| Figure | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| Superblocks with a root | 89 | 75 |
| Of them shown by a namespace mount; in the initial namespace | 73; 49 | 60; 29 |
| `s_inodes` lists that broke forward; entries the backward walk added | 3; 876, 5478, 43 | 1; 2041 |
| Inodes listed | 24231 | 23753 |
| Named; under a view | 22297; 19950 | 21715; 21699 |
| Types REG / DIR / LNK / CHR / BLK / FIFO / SOCK / other | 12833 / 5987 / 5062 / 219 / 56 / 14 / 57 / 3 | 16021 / 3872 / 3466 / 256 / 31 / 17 / 86 / 4 |
| Inodes with `nrpages` > 0; sum of `nrpages` | 1706; 192008 | 1109; 150066 |
| Tree entries; value entries | 130668; 129725 | 112388; 451998 |
| Entries rejected: outside / misaligned / unread / other mapping / wrong index | 300 / 0 / 0 / 44378 / 611 | 609 / 0 / 0 / 10193 / 6012 |
| Unread or inconsistent tree nodes | 104 | 92 |
| Pages accepted (with folio tail pages) | 99586 | 95574 |
| Frames that read | 99584 of 99586 | 95573 of 95574 |
| Archive members: directories / regular / links | 5519 / 1302 / 2404 | 3711 / 868 / 739 |
| Regular files skipped as not cached; links without a target; files over the dump limit; files that did not fit in the archive | 10285; 2468; 1; 0 | 13584; 2438; 0; 0 |
| Regular data written; of it from cached frames | 4441142279; 309607125 bytes | 2351110371; 323213389 bytes |
| ELF check: files under `/usr/bin`, `/usr/sbin`, and `/usr/lib*` `.so` files, 64 bytes or more, first page not all zero, not `#!` | 433 of 437 have a valid `e_ident` | 372 of 373 |
| Text check: `/etc/passwd`, `group`, `os-release`, `hostname`, `fstab` with a cached first page, lines well formed | none cached on mem3 (the `/etc/passwd` entry points at an anonymous page and is rejected) | 2 of 2 (`/etc/group`, `/etc/passwd`) |

The archive figures are with the default limits, taken 2026-11-12 after D4: a 1 GiB dump limit per member (`MaxArtifactBytes`) and a 16 GiB archive limit (`MaxArchiveBytes`). Every file under the member limit fits, as before O8. With O8's single 1 GiB bound for both, the archive held 1116 and 555 regular members, 1073741808 and 1073741723 bytes, of them 272176921 and 169573101 from cached frames: 88% (mem3) and 52% (mem4) of the cached bytes, and mem4 lost `/etc/passwd`. Most of the bytes are the zeros of uncached holes. An examiner who wants a smaller archive lowers `MaxArchiveBytes`; `max_dump_size` lowers the member limit only.

On mem3 accepted pages exceed accepted entries by 14207 (99586 against 85379): v6.17 caches ext4 files in large folios, expanded by 4.5 step 4. On mem4 they are equal. The rejected entries concentrate in large, busy mappings (`libLLVM.so.20.1`: 11863 entries of other mappings on mem3; the Fedora capture file: 5672 wrong index), consistent with M3. The ELF headers that fail (four `.so` files on mem3, `wpa_supplicant` on mem4) have a cached, accepted first page whose bytes are not an ELF header; without ground truth the cause cannot be told apart from acquisition smear. Symlinks without a target are mostly procfs, sysfs and apparmorfs links, whose targets are computed by `get_link` (F7) and are not in memory.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Only the first alias names an inode; other hard-link names are not listed. | Owner decision: list one row per alias, or keep one row per inode |
| O2 | Inode times named `__i_atime` and similar (kernels between v6.4 and v6.14) are not read; such a table makes the tools fail with `ErrUnsupported`. No checked tag has them. | A capture of such a kernel (Q7) |
| O3 | hugetlbfs mappings index in huge-page units on some kernels; their offsets are not converted. No checked tag was read for this. | A capture with hugetlbfs files in use |
| O4 | `CHR`, `BLK`, `FIFO` and `SOCK` inodes are not archived, so that extraction cannot create device nodes. | Owner decision |
| O5 | S00 has no archive kind. The archive is named `pagecache.kernel.tar.gz`; the earlier name was `recovered_fs.tar.gz`. Owner decision 2026-11-12: add a kind to S00. Done: S00 4.1 lists kind `pagecache` with extension `tar.gz`; `extract.KindPageCache` and `extract.ExtTarGzip` added; `pagecache.ArchiveName` is built from them (same name, now a variable); files `docs/specs/S00-artifact-names.md`, `extract/artifactname.go`, `tools/linux/pagecache/pagecache_dump_files.go`. | Owner decision: add a kind to S00 |
| O6 | Uncached regular files are left out of the archive and listed only by `list_files`; a partly cached file has zeros in its holes, and the row's `RecoveredBytes` says how much came from the cache. pax sparse files are not written. | Owner decision |
| O7 | Aliased flag bits list every alias name. | Owner decision: one name per bit |
| O8 | The dump limit applies per member, not to the whole archive. Owner decision 2026-11-12: both each member and the archive. Done: one dump limit bounds each regular member (`ErrTooLarge`) and the sum of regular member sizes (`ErrArchiveFull`), each counted in one diagnostic and failing strict mode (4.8 step 3, sections 6 and 8); no new `Limits` field (section 8); section 9 figures re-measured; files `tools/linux/pagecache/pagecache_dump_files.go`, `pagecache_test.go`. Owner decision 2026-11-12 (follow-up D4): a separate archive limit in `Limits` with a larger default. Done: `limits.Limits.MaxArchiveBytes` (default 16 GiB, ceiling 2^52) bounds the sum of regular members; the dump limit bounds each member only (4.8 step 3, sections 6 and 8); `ErrArchiveFull` reads "file does not fit in what the archive limit leaves of the archive"; tests `TestTheDumpLimitBoundsEachMemberAndTheArchiveLimitTheirSum`, `TestTheDefaultArchiveLimitExceedsTheMemberLimit`; section 9 re-measured; files `limits/limits.go`, `limits/limits_test.go`, `tools/linux/pagecache/pagecache_dump_files.go`, `pagecache_test.go`, S74 section 8. | Owner decision |
| O9 | 4-byte pointers, the v4.19 radix layout and a kernel without `CONFIG_SPARSEMEM_VMEMMAP` are written from the sources only (or refused: 4-byte pointers). | A capture that has them (Q7) |
| O10 | Deleted-but-open files are not marked. | A later rule from `d_unhashed`, if wanted |
| O11 | `list_files` lists every inode of every superblock, not only the named files under a namespace mount. Rows come also from superblocks no namespace mount shows (apparmorfs; the one-root internal filesystems such as pipefs, sockfs, pidfs, bdev; 4.1, 4.3 step 4), from inodes with no usable name (4.3 step 3), and from named inodes on lists that close or on the proc lists that broke (4.4 step 1). Owner decision 2026-11-12 (follow-up PU3): re-measure these rows. Done: `pagecachefacts -inodes` read the named ones live: `i_state` without `I_NEW`, `I_WILL_FREE`, `I_FREEING` or `I_CLEAR` on all but 3, `i_count` above 0, an alias attached. An inode with no alias (`i_dentry.first` null) has no name (4.3 step 1). A symlink row's `Path` is the link's own path, with no target appended (4.3 step 4). Owner decision 2026-11-12 (follow-up N1): a row shows its inode through one view only, the first whose root is a prefix of its path (4.2 step 4, 4.3 step 4). Done: no library change. On mem3 one nsfs inode (0x8d7e014c1148) is bind-mounted at `/run/snapd/ns/snapd-desktop-integration.mnt`; its mount's root dentry does not walk to the superblock's `s_root`, so 4.2 step 3 drops the mount and the row has no view. | Ground truth for the broken lists; a probe of nsfs bind mounts |
| O12 | The content and names of mem4's archive members were probed. Owner decision 2026-11-12 (follow-up PU4): probe. Done: not a bug. A regular member is `i_size` bytes, with zeros in uncached holes (4.6, O6). A symlink member holds the target as the kernel stores it (read at `i_link` with `pagecachefacts -inodes`: `/dev/initctl` holds `/run/initctl`, an absolute path). The archive also holds the roots of superblocks no namespace mount shows, and proc and binfmt_misc directories (4.8 step 3). `MemberSize` is set only for regular members (section 7). Owner decision 2026-11-12 (follow-up N1): the dump rows use the views of 4.2 step 4 and 4.3 step 4, as `list_files` does. Done: no library change. | Owner decision |
| O13 | The per-superblock inode diagnostic in `files` (`tools/linux/pagecache/pagecache.go`) puts every path error other than `ErrUnread`, `ErrForeign` and `ErrDetached` in one count and labels it with the `ErrName` text, so inodes cut by `ErrPathSteps` are reported as bad names. Owner decision 2026-11-12: kept for v0.1.0; a count and label of their own for `ErrPathSteps` in v0.2.0. | v0.2.0 |
| O14 | `pages` (`tools/linux/pagecache/pagecache_list_pages.go`) reports a walk cut by the `MaxTableEntries` cap, but adds only the rejected and unread entries to the losses; the pages the cap cut add 0, so they do not fail strict mode. Owner decision 2026-11-12: kept for v0.1.0; a capped walk counts as a loss in v0.2.0. | v0.2.0 |
| O15 | `inode` (`tools/linux/pagecache/pagecache.go`) returns `ErrUnread` when a dentry or name on the inode's chain does not read, and `files` then skips the inode as an unread inode; it is not listed with an empty path. Owner decision 2026-11-12: kept for v0.1.0; list such an inode with an empty path in v0.2.0. | v0.2.0 |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | One row per inode |
| O2 | Refuse with ErrUnsupported |
| O3 | Leave unconverted |
| O4 | Do not archive them |
| O5 | Add a kind to S00 |
| O6 | Omit uncached, zero-fill holes, report bytes |
| O7 | List every alias |
| O8 | Both each member and the archive |
| O9 | Ship as written, mark untested |
| O10 | Defer to v0.2.0 |

## 11. Provenance

Written from the Linux kernel sources at v4.19, v6.1, v6.4, v6.14 and v6.17 (git.kernel.org, accessed 2026-11-12), IEEE Std 1003.1-2017, RFC 1952, and the project's measurements on mem3_ubuntu24 and mem4_fedora40. Every rule rests on the sources and measurements above. Author: the project.
