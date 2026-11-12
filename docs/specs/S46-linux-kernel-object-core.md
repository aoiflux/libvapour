# S46: Linux kernel object core: member reads, boot time, capabilities, ptrace and page tables

Version 1, 2026-11-12.

## 1. Purpose

Every Linux reader in `tools/linuxobj` and 28 tool packages read kernel objects through one `linuxobj.Kernel`: a member of a structure at its declared width and sign, a pointer, a fixed or NUL-terminated string, a symbol, the size of a type, and the address forms of the running paging mode. On top of that core an examiner needs four facts the kernel keeps in its own words: when the system booted, in wall-clock time and in each time namespace, and when each task started; which capabilities each task holds and what the full set of the running kernel is; which tasks trace which under ptrace, with the tracer's options; and, for a process, which physical page backs a virtual address and whether the page was written. This specification defines that core and those four readers, and the tool `linux.boot.read_time`, which reports the boot time per time namespace.

The list, task and tree walks are S01 and S02 (`tools/linuxwalk`), the module model is S06 (`tools/linuxmodule`), the task identity and a task's page-table root are S14 (`taskidentity.go`, `taskspace.go`). They are used here, not re-derived.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Context | `tools.Context` | Kernel-space memory, the symbol table, options and Limits. |
| Paging mode | option `paging_mode` | The session's mode name, `linux-x64`, `linux-la57`, `linux-x86pae` or `linux-x86`. |
| Physical memory | option `physical_memory` | The physical layer page tables are read from. |
| Symbols | symbol table | `tk_core`, `timekeeper_data`, `cap_last_cap`, `init_cred`, `physical_mask`; the types in section 3. |
| Limits | effective `limits.Limits` | Section 8. |

`linux.boot.read_time` takes no options beyond the shared `strict` and `diagnostics`.

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17 unless a row names fewer, fetched from `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12. Paths are under the kernel tree. The Intel SDM is Volume 3A, order number 253668-093US, September 2026 (paging is its chapter 5 in that edition, canonical addressing section 4.5). The supported captures run 6.17 (Ubuntu 24) and 6.14 (Fedora 40).

### Core reads

| # | Fact | Source |
|---|---|---|
| K1 | The session's tables give member types by their C base names after typedefs (`int` for `pid_t`, `long long int` for `ktime_t`, `long long unsigned int` for `u64`), a width per member, and no declared type on symbols. | M1 |
| K2 | 4-level paging translates 48-bit linear addresses and 5-level paging 57-bit ones; 32-bit and PAE paging translate 32-bit addresses. | SDM 4.5, 5.3, 5.4, 5.5 |
| K3 | A linear address is canonical for 4-level paging when bits 63:47 are identical, and for 5-level paging when bits 63:56 are identical. | SDM 4.5 |
| K4 | x86 stores integers little-endian (S01 X1). | S01 |
| K5 | `char` is 1 byte, `short` 2, `int` 4 and `long long` 8 (`__s16`, `__s32`, `__s64`); `long` is `BITS_PER_LONG` wide, 64 on a 64-bit kernel and 32 otherwise, the width of a pointer. | `include/uapi/asm-generic/int-ll64.h`, `include/asm-generic/bitsperlong.h`, v6.17 |
| K6 | A member typed `unsigned …`, `u8`–`u64`, `__u8`–`__u64`, `__le*`, `__be*`, `size_t`, `phys_addr_t` or `bool` holds no sign. | `include/uapi/asm-generic/int-ll64.h`, `include/linux/types.h`, v6.17 |

### Boot clock and time namespaces

| # | Fact | Source |
|---|---|---|
| C1 | The core timekeeper is the member `timekeeper` of the static `tk_core` up to v6.14; at v6.17 `tk_core` is a macro for `timekeeper_data[TIMEKEEPER_CORE]`, with `TIMEKEEPER_CORE` 0 in `enum timekeeper_ids`, so the core timekeeper is element 0 of the symbol `timekeeper_data`. | `kernel/time/timekeeping.c`, every tag; `include/linux/timekeeper_internal.h`, v6.17 |
| C2 | At v6.14 and v6.17 the container is `struct tk_data` { `seqcount_raw_spinlock_t seq`; `struct timekeeper timekeeper`; … }. | `kernel/time/timekeeping.c`, v6.14, v6.17 |
| C3 | At v4.19, v6.1 and v6.4 the container is an unnamed `struct` { `seq`; `struct timekeeper timekeeper`; }, with `seq` a `seqcount_t` at v4.19 and a `seqcount_raw_spinlock_t` at v6.1 and v6.4. The timekeeper follows the counter at the next multiple of its alignment; `struct timekeeper` holds `u64` members. Both captures place it at +0x8 after a 4-byte counter. | `kernel/time/timekeeping.c`, `include/linux/timekeeper_internal.h`, those tags; M1 |
| C4 | `seqcount_t` begins with `unsigned sequence` and a `seqcount_raw_spinlock_t` begins with its `seqcount_t`; a writer increments `sequence` before and after an update, and a reader retries while it is odd. | `include/linux/seqlock.h`, v4.19, v6.1, v6.17 |
| C5 | `struct timekeeper` has `u64 xtime_sec` (CLOCK_REALTIME seconds), `struct timespec64 wall_to_monotonic`, `ktime_t offs_real` (monotonic to realtime) and `ktime_t offs_boot` (monotonic to boottime) at every tag, and `struct timespec64 monotonic_to_boot` from v6.1. `getboottime64` returns `ktime_sub(tk->offs_real, tk->offs_boot)`. `tk_set_wall_to_mono` keeps `offs_real` equal to the negated `wall_to_monotonic` (it warns when they differ) and `tk_update_sleep_time` keeps `monotonic_to_boot` equal to `offs_boot`. | `include/linux/timekeeper_internal.h`, `kernel/time/timekeeping.c`, every tag (`monotonic_to_boot` absent at v4.19) |
| C6 | `/proc/stat` `btime` is `getboottime64`, and at v6.1 to v6.17 less the reader's `nsproxy->time_ns->offsets.boottime` (`timens_sub_boottime`). `struct nsproxy` has `struct time_namespace *time_ns`; `struct time_namespace` has `struct ns_common ns` and `struct timens_offsets offsets`; `struct timens_offsets` has `struct timespec64 monotonic, boottime`. `init_time_ns` has `ns.inum` `PROC_TIME_INIT_INO`, 0xEFFFFFFA. No time namespace exists at v4.19. | `fs/proc/stat.c`, every tag; `include/linux/time_namespace.h`, `include/linux/nsproxy.h`, `kernel/time/namespace.c`, `include/linux/proc_ns.h`, v6.1 to v6.17; `include/uapi/linux/nsfs.h`, v6.17 |
| C7 | `struct timespec64` is `time64_t tv_sec; long tv_nsec`. `KTIME_MAX` is the largest `s64` and `KTIME_SEC_MAX` is `KTIME_MAX / NSEC_PER_SEC`. An offset written to `/proc/<pid>/timens_offsets` is refused when `tv_nsec` is `NSEC_PER_SEC` or more or `tv_sec` is beyond `±KTIME_SEC_MAX`. | `include/linux/time64.h`, every tag; `fs/proc/base.c`, `kernel/time/namespace.c`, v6.1 to v6.17 |
| C8 | A task's start is `ktime_get_boottime_ns()` in `u64 start_boottime` at v6.1 to v6.17 and in `u64 real_start_time` at v4.19: host CLOCK_BOOTTIME nanoseconds. `/proc/<pid>/stat` reports it plus the reader's namespace offset, so its wall-clock time is the host boot time plus the stored value whatever the namespace. | `kernel/fork.c`, `include/linux/sched.h`, `fs/proc/array.c`, every tag |
| C9 | The Hyper-V time synchronisation driver sets the clock with `do_settimeofday64` on a host sync, which moves `wall_to_monotonic` and `offs_real` and so the boot time read later. | `drivers/hv/hv_util.c`, `kernel/time/timekeeping.c`, v6.14, v6.17 |

### Capabilities

| # | Fact | Source |
|---|---|---|
| P1 | `CAP_*` by number: 0 `CHOWN`, 1 `DAC_OVERRIDE`, 2 `DAC_READ_SEARCH`, 3 `FOWNER`, 4 `FSETID`, 5 `KILL`, 6 `SETGID`, 7 `SETUID`, 8 `SETPCAP`, 9 `LINUX_IMMUTABLE`, 10 `NET_BIND_SERVICE`, 11 `NET_BROADCAST`, 12 `NET_ADMIN`, 13 `NET_RAW`, 14 `IPC_LOCK`, 15 `IPC_OWNER`, 16 `SYS_MODULE`, 17 `SYS_RAWIO`, 18 `SYS_CHROOT`, 19 `SYS_PTRACE`, 20 `SYS_PACCT`, 21 `SYS_ADMIN`, 22 `SYS_BOOT`, 23 `SYS_NICE`, 24 `SYS_RESOURCE`, 25 `SYS_TIME`, 26 `SYS_TTY_CONFIG`, 27 `MKNOD`, 28 `LEASE`, 29 `AUDIT_WRITE`, 30 `AUDIT_CONTROL`, 31 `SETFCAP`, 32 `MAC_OVERRIDE`, 33 `MAC_ADMIN`, 34 `SYSLOG`, 35 `WAKE_ALARM`, 36 `BLOCK_SUSPEND`, 37 `AUDIT_READ`, 38 `PERFMON`, 39 `BPF` and 40 `CHECKPOINT_RESTORE`; 38 to 40 are absent at v4.19. `CAP_LAST_CAP` is 37 at v4.19 and 40 at v6.1 to v6.17. | `include/uapi/linux/capability.h`, every tag |
| P2 | `kernel_cap_t` is `struct { __u32 cap[2]; }` at v4.19 and v6.1, with capability n in bit n mod 32 of `cap[n >> 5]`, and `struct { u64 val; }` from v6.4. `struct cred` has `cap_inheritable`, `cap_permitted`, `cap_effective`, `cap_bset` and `cap_ambient` of that type. | `include/linux/capability.h`, `include/uapi/linux/capability.h`, `include/linux/cred.h`, every tag |
| P3 | The sysctl `kernel.cap_last_cap` reads the `static const int cap_last_cap = CAP_LAST_CAP`. | `kernel/sysctl.c`, every tag |
| P4 | `CAP_FULL_SET` is every bit up to `CAP_LAST_CAP` (`CAP_VALID_MASK` from v6.4; `{ ~0, CAP_LAST_U32_VALID_MASK }` before), and `init_cred` is built with `cap_bset = CAP_FULL_SET`. | `include/linux/capability.h`, `kernel/cred.c`, every tag |
| P5 | `/proc/<pid>/status` prints each set as hexadecimal; `cap_ambient_invariant_ok` requires the ambient set within permitted and inheritable. | `fs/proc/array.c`, `include/linux/cred.h`, every tag |

### Ptrace

| # | Fact | Source |
|---|---|---|
| R1 | `PT_PTRACED` is 0x1, `PT_SEIZED` 0x10000 and `PT_OPT_FLAG_SHIFT` 3; `PT_EVENT_FLAG(e)` is `1 << (3 + e)`, giving `PT_TRACESYSGOOD` (e 0) and `PT_TRACE_FORK`, `VFORK`, `CLONE`, `EXEC`, `VFORK_DONE`, `EXIT`, `SECCOMP` (e 1 to 7); `PT_EXITKILL` and `PT_SUSPEND_SECCOMP` are `PTRACE_O_EXITKILL` (1 << 20) and `PTRACE_O_SUSPEND_SECCOMP` (1 << 21) shifted by 3. At v4.19 only, `PT_DTRACE` is 0x2, `PT_BLOCKSTEP` bit 30 and `PT_SINGLESTEP` bit 31. | `include/linux/ptrace.h`, `include/uapi/linux/ptrace.h`, every tag |
| R2 | `ptrace_attach` sets `task->ptrace` to `PT_PTRACED`, with `PT_SEIZED` and the options shifted by 3 for a seize; `ptrace_setoptions` replaces the option bits; `PTRACE_TRACEME` sets `PT_PTRACED`. | `kernel/ptrace.c`, every tag |
| R3 | `__ptrace_unlink` sets `child->parent = child->real_parent`, removes `ptrace_entry` and sets `child->ptrace = 0`. | `kernel/ptrace.c`, every tag |
| R4 | `__ptrace_link` adds `child->ptrace_entry` to `new_parent->ptraced` with `list_add` and sets `child->parent = new_parent`. `struct task_struct` has `unsigned int ptrace`, `parent`, `real_parent`, `struct list_head ptraced` and `ptrace_entry`. | `kernel/ptrace.c`, `include/linux/sched.h`, every tag |

### Page tables

| # | Fact | Source |
|---|---|---|
| G1 | In every paging-structure entry bit 0 is P; in an entry that may map a page, bit 7 is PS; in an entry that maps a page, bit 6 is D. Bit 7 of a PML5E or PML4E, and of a PAE PDPTE, is reserved. In a 4 KiB PTE bit 7 is PAT and bit 12 an address bit; in a 2 MiB or 1 GiB entry bit 12 is PAT. The kernel names the same bits `_PAGE_BIT_PRESENT` 0, `_PAGE_BIT_DIRTY` 6, `_PAGE_BIT_PSE` 7, `_PAGE_BIT_PAT` 7 and `_PAGE_BIT_PAT_LARGE` 12, with bits 52 to 63 software, protection-key or NX bits. | SDM Tables 5-15 to 5-20, 5.4; `arch/x86/include/asm/pgtable_types.h`, v6.17 |
| G2 | 4-level paging: CR3 bits 51:12 locate the PML4; the PML4E, PDPTE, PDE and PTE are indexed by linear-address bits 47:39, 38:30, 29:21 and 20:12; a PDPTE with PS maps 1 GiB and a PDE with PS maps 2 MiB. 5-level paging adds a PML5 indexed by bits 56:48. PAE paging: CR3 bits 31:5 locate four 8-byte PDPTEs indexed by bits 31:30, then a PDE (bits 29:21, PS maps 2 MiB) and a PTE (bits 20:12). 32-bit paging: CR3 bits 31:12 locate a directory of 4-byte entries indexed by bits 31:22 (PS maps 4 MiB) and a table indexed by bits 21:12. CR3 bits 11:0 are flags or a PCID. | SDM 5.3, 5.4, 5.5.2, 5.5.4, Tables 5-12, 5-13 |
| G3 | An entry's frame is `entry & PTE_PFN_MASK`, `PAGE_MASK & __PHYSICAL_MASK`. `__PHYSICAL_MASK_SHIFT` is 52 on a 64-bit or PAE kernel and 32 on a 2-level one; with `CONFIG_DYNAMIC_PHYSICAL_MASK` `__PHYSICAL_MASK` is the variable `physical_mask`, initialised to `(1 << __PHYSICAL_MASK_SHIFT) - 1`, from which AMD memory encryption clears `sme_me_mask`. | `arch/x86/include/asm/page_types.h`, `pgtable_types.h`, `page_64_types.h`, `page_32_types.h`, `arch/x86/mm/pgtable.c`, every tag; `arch/x86/mm/mem_encrypt_identity.c`, v4.19 to v6.14; `arch/x86/boot/startup/sme.c`, v6.17 |
| G4 | The kernel stores swap entries and inverted frames in entries with P clear (`__pte_needs_invert` is true for any non-zero entry without `_PAGE_PRESENT`), and `pte_present` also counts `_PAGE_PROTNONE` entries, whose frame is inverted. | `arch/x86/include/asm/pgtable-invert.h`, `pgtable.h`, v6.17 |
| G5 | `pgd_alloc` takes an order-1 (8 KiB) block when page-table isolation is in use and order 0 otherwise: by configuration up to v6.14, by the running feature at v6.17. A PGD is therefore 4 KiB aligned, and 8 KiB aligned only with isolation. | `arch/x86/include/asm/pgalloc.h`, `arch/x86/mm/pgtable.c`, every tag |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Both tables: `tk_data` (size 576; `seq` +0x0 `seqcount_raw_spinlock_t` of 4 bytes, `timekeeper` +0x8), `timekeeper` (280; `xtime_sec` +0x38, `wall_to_monotonic` +0x48, `offs_real` +0x58, `offs_boot` +0x60 as `long long int`, `monotonic_to_boot` +0xc0), `timespec64` (`tv_sec` `long long int`, `tv_nsec` `long int`, 8 bytes each), `time_namespace` (`ns` +0x10, `offsets` +0x28), `timens_offsets.boottime` +0x10, `nsproxy.time_ns` +0x30, `ns_common.inum` +0x10, `kernel_cap_t` (8; `val` `long long unsigned int`), `cred` caps +0x30 to +0x50, `mm_struct.pgd` +0x78, `task_struct.ptrace` +0x30 `unsigned int`, `pid` `int`, `start_boottime` present. Every symbol has an empty type. mem3 has `timekeeper_data` and no `tk_core`; mem4 has `tk_core`. Both have `init_time_ns`, `cap_last_cap`, `init_cred`, `physical_mask` and `sme_me_mask`. | `corefacts -types`, 2026-11-12 |
| M2 to M9 | Clock, evidence, tasks, namespaces, capabilities, ptrace, page tables, tool rows. | Section 9 |

## 4. Algorithm

### 4.1 Core reads

1. **Address form.** The width is 32 bits with 4-byte pointers, 57 with a paging mode ending `la57`, and 48 otherwise (K2). `Masked` keeps the low width bits; `Canonical` also copies the top kept bit into every bit above it, except at 32 bits (K3). The S01 walker gets `Canonical` as its address form.
2. **Integer members.** The width is that of the member's C base type under K5 when its type name is one, else the table's member width, else the type's size; a pointer member is a pointer wide. A member that is an array or more than 8 bytes wide is not an integer. Bitfields take their bits from that word (`symbols.IntField`). `Uint` returns the bits; `Int` sign-extends them from the member's top bit unless the type is unsigned by K6. Resolved members are cached per `Kernel`.
3. **Pointers.** `Pointer` reads a pointer-wide little-endian word at the member (K4), as stored. `Deref` also says whether the pointer is set and the whole pointee (its type's size, or one byte when untyped) reads.
4. **Sizes.** `SizeOf` is the structure's size, else the K5 width of a base-type name, else the table's own size.
5. **Strings.** `CharArray` reads the whole array member and cuts at the first NUL. `StringAt` reads at most `count` bytes a page at a time and stops at the first NUL; it fails only when a page it still needs does not read.
6. **Readable** reads every byte of the range, a page at a time; a size of 0 means one byte, and a range that wraps does not read.
7. Symbols, members and types are answered by the session table; `SymbolsAt` by its address index; `SymbolNames` lists the table's names when it can. `Modules` builds the S06 model once per `Kernel`.

### 4.2 Boot clock

1. Find `tk_core`, else `timekeeper_data` (C1). Neither: `ErrNoTimekeeper`.
2. Place the timekeeper in the container: at the `timekeeper` member of the symbol's declared type if the table gives one; else of `tk_data` (C2); else after the container's sequence counter, whose type is `seqcount_raw_spinlock_t` if the table has it and `seqcount_t` otherwise, rounded up to a pointer width (C3). None of these: `ErrTimekeeperAt`.
3. Read `offs_real` and `offs_boot` (signed nanoseconds) and take the boot time as `offs_real − offs_boot` in UTC (C5). A difference outside `int64` is `ErrTimeRange`.
4. Read the container's first word as `seqcount_t.sequence` (C4); `Updating` is an odd value.
5. Read `xtime_sec` as the time of the last update, whole seconds.
6. Check, where the members exist: `wall_to_monotonic` in nanoseconds equals `−offs_real`, and `monotonic_to_boot` equals `offs_boot` (C5). A check that cannot read is left unchecked.
7. The result is cached per `Kernel`.

### 4.3 Task start and time namespaces

1. **Creation time** is the boot time plus `start_boottime`, or `real_start_time` when that member is the one the table has (C8). A value beyond `int64` is `ErrTimeRange`.
2. **A task's time namespace** is `task->nsproxy->time_ns` (C6). A null `nsproxy` means the task holds none (an exiting task); a null `time_ns` is an error. Without `nsproxy.time_ns` the kernel has no time namespaces (`ErrNoTimeNSProxy`).
3. **A namespace** gives `ns.inum` and `offsets.boottime` (C6, C7). Its boot time is the host boot time less that offset.

### 4.4 Capabilities

1. **A set** is the 8 bytes at its address read as one little-endian value: both layouts of P2 put capability n at bit n on x86 (K4). A type whose size is not 8 is `ErrUnsupported`.
2. **The full set** of the running kernel is bits 0 to `cap_last_cap` (P3, P4); else, when `init_cred.cap_bset` is a run of low bits, that set (P4); else bits 0 to 40, the named ones (P1). The source is recorded.
3. **Text:** the full set is `CAP_FULL_SET` (P4), the empty set is empty text, and any other set lists its P1 names in bit order joined by `, `, followed by the unnamed bits as one hexadecimal value.

### 4.5 Ptrace

1. A task is traced when `PT_PTRACED` is set in `ptrace` (R1, R2, R3).
2. Its tracer is `parent` while it is traced (R4); a null `parent` names none.
3. A task traces others when its `ptraced` list is not empty; the tracees are the S01 walk of `ptraced` over `task_struct.ptrace_entry`, forwards, each giving its `pid` (R4).
4. Flag text is the R1 names of the set bits in bit order joined by `|`; bits without a name are returned apart.

### 4.6 Page tables

1. The shape comes from the paging mode with the `linux-` prefix dropped; with no mode recorded and 8-byte pointers it is 4-level. Each shape lists its levels' index bits and whether PS may map a page there (G2).
2. The root is the CR3 value less its flag bits (bits 11:0, or 4:0 for PAE) (G2).
3. The frame mask is `physical_mask` when the shape has 8-byte entries and the symbol reads as a value above one page, else the G3 default for the shape, less the page offset (G3).
4. At each level read the whole table from physical memory and take the indexed entry. P clear is a page fault for the span that entry covers (G4: the frame bits of such an entry are not a frame). PS set where no page can be mapped is a fault marked reserved (G1). PS set where allowed, or the last level, maps a page of that level's span: physical = frame bits above the span | the address bits below it. Otherwise the entry's frame is the next table.
5. `Dirty` is D in a present leaf (G1). `ReadAt` translates each page and fails on any fault; `ReadPadded` fills a page that does not translate or read with zeros and counts those bytes.
6. `Translator` returns the shared `layers.IntelTranslator` for the same root, mode and frame mask, for callers that need a `layers` translator.

### 4.7 Tool `linux.boot.read_time`

1. Read the boot clock (4.2); failure is the tool's error. An odd sequence or a failed check is a diagnostic, an error in strict mode.
2. Without time namespaces return one row with the host boot time.
3. Otherwise walk every task, threads included (S01; a thread can enter a namespace of its own), group them by namespace address, and give one row per namespace with its task count and boot time (4.3). Tasks with a null `nsproxy` are in no row. A task whose namespace does not read is counted in one diagnostic, an error in strict mode.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| `offs_real − offs_boot` fits `int64` | C5: both are `ktime_t` | `ErrTimeRange` |
| `wall_to_monotonic` = `−offs_real`; `monotonic_to_boot` = `offs_boot` | C5 | Flag; diagnostic in the tool, error in strict mode |
| The sequence is even | C4 | Flag; as above |
| `0 ≤ tv_nsec < 10^9` and `|tv_sec| ≤ KTIME_SEC_MAX` | C7 | `ErrTimeRange` |
| A start time fits `int64` nanoseconds | C8 | `ErrTimeRange` |
| A namespace's inode number is not 0 | C6; S40 N6 | Error |
| A capability set is 8 bytes | P2 | `ErrUnsupported` |
| `cap_last_cap` is 0 to 63 | P1, P3: a set holds 64 bits | Next source of 4.4 step 2 |
| `init_cred.cap_bset` is a run of low bits | P4 | Next source |
| `physical_mask` is above one page | G3 | G3 default |
| PS clear in a PML5E, PML4E or PAE PDPTE | G1 | Reserved fault |
| A table reads in full | G2 | `ErrTableUnread` |

Bits outside the running kernel's full set are reported, not refused: M6 found none, and refusing them would hide what the kernel holds.

## 6. Failure modes

| Case | Result |
|---|---|
| A member, type or symbol is missing | The table's error, wrapped; `TableGap` is true for it |
| A member read fails | `linuxobj: <type>.<member> at 0x<addr>: <cause>` |
| Not an integer, not an array, no size | `ErrNotInteger`, `ErrNotArray`, `ErrNoSize` |
| No timekeeper, unknown placement, value out of range | `ErrNoTimekeeper`, `ErrTimekeeperAt`, `ErrTimeRange` |
| No start member, no time namespaces | `ErrNoStartTime`, `ErrNoTimeNSProxy` |
| No physical layer, unknown paging mode | `ErrNoPhysicalLayer`, `ErrPagingMode` |
| A page does not translate | `*PageFault` with the level, entry, span and whether it was reserved |
| A table or a read is too large or unreadable | `ErrTableUnread`, `ErrReadTooLarge` |
| Tool: clock check failed | `linux.boot.read_time: timekeeper at 0x<addr>: <check>` (diagnostic, or error in strict mode) |
| Tool: namespaces unread | `linux.boot.read_time: <n> tasks without a readable time namespace, first: <task>` |

## 7. Result schema

`linuxobj.BootClock`: `Timekeeper` (address), `Sequence`, `SequenceRead`, `RealOffset`, `BootOffset` (durations), `Boot` (UTC time), `Updated` (UTC time, whole seconds; zero when not read), `WallChecked`, `WallAgrees`, `SleepChecked`, `SleepAgrees`; methods `Updating()` and `Consistent()`.

`linuxobj.TimeNamespace`: `Address`, `Inode`, `BootOffset`; method `BootTime(host)`.

`linuxobj.CapFull`: `Last`, `Mask`, `Source` (`cap_last_cap`, `init_cred.cap_bset` or `named capabilities`); method `Holds`.

`linuxobj.PageFault`: `Virtual`, `Level` (0 is the root table), `Entry`, `Reserved`; method `Span()`.

`linux.boot.read_time` row, sorted by `Namespace` then `NamespaceAddress`:

| Field | Type | Meaning |
|---|---|---|
| `Namespace` | uint | `ns.inum`; 0 when the kernel has no time namespaces |
| `NamespaceAddress` | uint | `struct time_namespace` address; 0 as above |
| `BootOffset` | duration | `offsets.boottime` |
| `Tasks` | int | Tasks walked in the namespace |
| `BootTime` | time | UTC; never absent in a row |

Changes users see (section 10, O1 to O3):

- `linux.boot.read_time`: rows replace `TimeNS`, `TimeNSAvailable`, `TimeNSPresent`, `BootTime`, `BootTimeValid` with the fields above. Before this specification the tool failed on both captures; it now gives one row on each.
- `linux.process.list_capabilities`: sets are written with the kernel names (`CAP_NET_RAW`), the full set as `CAP_FULL_SET` instead of `all`, and unnamed bits in hexadecimal.
- `linux.process.list_tracing`: flag text is the kernel's `PT_*` names joined by `|`; neither capture holds a traced task, so neither gives a flag row.

## 8. Limits

- `MaxListEntries`: the ptraced list and the task walk (S01).
- `PTECacheEntries`: page tables are cached whole, so a `PageTables` holds at most `PTECacheEntries / 512` tables, at least one, the oldest dropped first; `Translator` passes the value to the shared translator when the physical layer is an immutable snapshot.
- `MaxBufferBytes`: the largest `ReadAt`; `ReadPadded` returns at most that many bytes.

Strings are bounded by their callers' counts; the boot clock, a namespace and a capability set are fixed-size reads.

## 9. Acceptance

- Synthetic fixtures (`tools/linuxobj/*_s46_test.go`, `tools/linux/boottime/boottime_test.go`, fixture `linuxobjtest/s46_fixture.go`): address forms for each mode; integer widths, signs and bitfields; base-type sizes for 64-bit and 32-bit; pointer, `Deref` of a readable, partly unmapped and null pointee; `Readable`; strings ending at NUL, at the count and at an unmapped page; table queries; the module model built once; the boot time from `tk_core`, the checks agreeing and failing by 1 ns and 1 s, an odd sequence, each container shape (v4.19, v6.1, v6.14, v6.17), no placement, no symbol and a value out of range; creation time from both start members and out of range; time namespaces with an offset, a null `nsproxy`, a null `time_ns`, a bad `tv_nsec` and an inode of 0; the capability table, both set layouts, a 12-byte type, each full-set source and the text form; ptrace flags, tracer, tracees and a null parent; every paging shape, each page size, faults and their spans, a reserved PS, an unreadable table, agreement with `Translator`, the encryption bit, cross-page and padded reads, the read cap, missing inputs; the tool with two namespaces, without namespaces, with an inconsistent clock and with an unreadable namespace.
- Fuzz targets: `FuzzPageTableWalk` (any physical content in any mode: a mapping keeps the page offset and has a page size of that mode, a fault spans a power of two of at least 4 KiB, a padded read is always its length), `FuzzCapabilityText` (every set bit is a name or in the hexadecimal rest; the full set is its name), `FuzzPtraceFlagNames` (names and rest account for every bit), `FuzzTimespecNanoseconds` and `FuzzOffsetArithmetic` (against exact arithmetic).
- On both captures, measured with `corefacts`, 2026-11-12:

| | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| M2 Timekeeper | `timekeeper_data` + 0x8; sequence 67420 (even) | `tk_core` + 0x8; sequence 200080 (even) |
| M2 Offsets | `offs_real` 1787405196396665099 ns, `offs_boot` 0 | 1787406664114798359 ns, 0 |
| M2 Checks | `wall_to_monotonic` and `monotonic_to_boot` agree | agree |
| M2 Boot time | 2026-08-22T13:26:36.396665099Z | 2026-08-22T13:51:04.114798359Z |
| M2 `xtime_sec`, uptime | 13:28:13Z, 96.6 s | 13:59:46Z, 521.9 s |
| M3 Kernel log RTC line | at 0.235413399 s, clock set to 1787405194: boot in [13:26:33.765, 13:26:34.765); the reader is 1.63 s after that interval | at 0.544005647 s, 1787406664: boot in [13:51:03.456, 13:51:04.456); the reader is inside it |
| M3 Last log record before uptime | 50.5 s of 96.6 s | 236.9 s of 521.9 s |
| M3 Image file written | 14 min 27 s after `xtime_sec` | 2 min 6 s after |
| M4 Tasks walked, threads too | 557 | 573 |
| M4 Creation times | pid 1 at boot + 49.5 ms; none before boot or after `xtime_sec`; 0 unread | pid 1 at boot + 60.6 ms; same |
| M5 Time namespaces | 1: `init_time_ns`, 4026531834, offset 0, 556 tasks; 1 task with a null `nsproxy` | 1: 4026531834, offset 0, 572 tasks; 1 null |
| M6 Full set | `cap_last_cap` 40, mask 0x1ffffffffff; `init_cred.cap_bset` equal | same |
| M6 Credentials | 556 read, 1 unread (null `real_cred`) | 572, 1 |
| M6 Sets full/empty/other | inheritable 0/532/24, permitted 151/367/38, effective 151/367/38, bounding 508/4/44, ambient 0/547/9 | 0/543/29, 160/358/54, 160/358/54, 502/4/66, 0/569/3 |
| M6 Invariants | no bit outside the full set; ambient within permitted ∩ inheritable and effective within permitted for every task | same |
| M7 Ptrace | 0 tasks with a non-zero `ptrace`, 0 tracers | same |
| M8 Masks | `physical_mask` 0xfffffffffffff (52 bits), `sme_me_mask` 0 | same |
| M8 Roots | 468 user tasks, 115 distinct roots, all 4 KiB aligned, 54 also 8 KiB aligned | 454, 123, all, 49 |
| M8 Walk over every area | 29509 areas: 520973 pages mapped (all 4 KiB), 1014537 faults, 0 reserved, 0 unread tables | 31605: 491188, 1655518, 0, 0 |
| M8 Against the session's process layer | 1535510 of 1535510 answers agree | 2146706 of 2146706 |
| M8 Against `Translator` | 520973 of 520973 agree | 491188 of 491188 |
| M9 Tool rows | `read_time` 1, `list_capabilities` 203, `list_tracing` 0 | 1, 241, 0 |

The reader's boot time is the kernel's own `getboottime64`. On mem4 it falls inside the interval the RTC line gives. On mem3 it is 1.63 s later: the Hyper-V time driver set the clock after the RTC did (C9; `hv_utils: TimeSync IC` is logged at 0.598 s), which moves `offs_real`, and `/proc/stat` would show the same later value. Half of the roots are not 8 KiB aligned, so the kernels run without page-table isolation (G5), and the root rule stays 4 KiB. Neither capture holds a ptrace link, a time namespace other than the initial one, a large user page or an encrypted mapping; those paths are checked by fixtures only.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision: `linux.boot.read_time` row fields are renamed (`Namespace`, `NamespaceAddress`, `BootOffset`, `Tasks`, `BootTime`; the validity flags are gone because a row always holds a time). The timeline was changed to match. | Owner choice at the final stage |
| O2 | Owner decision: capability sets use the kernel's macro names and `CAP_FULL_SET` (P1, P4) instead of lower-case names and `all`. | Owner choice |
| O3 | Owner decision: ptrace flags use the kernel's `PT_*` names joined by `|`. | Owner choice |
| O4 | The v4.19 and v6.1 to v6.4 container shapes (C3), the v4.19 capability layout (P2), `real_start_time` (C8) and the 32-bit and 5-level walks (G2) are fixtures only. | A capture of those versions or modes (Q7) |
| O5 | 32-bit paging ignores the PSE-36 bits of a 4 MiB entry (SDM 5.3); no 32-bit capture exists. | A 32-bit capture |
| O6 | `PROT_NONE` and swap entries are not read (G4); a reader that needs a `PROT_NONE` page's frame would have to undo the inversion. | A spec revision if an examiner needs it |
| O7 | The boot time after a host time sync differs from the RTC's (M3, C9). The tool reports the kernel's value; whether to also report the RTC line's is not specified. | Owner choice |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept the new names |
| O2 | Use the kernel's names |
| O3 | Use PT_* names joined by \| |
| O4 | Defer; fixtures only |
| O5 | Keep ignoring them |
| O6 | Leave unread |
| O7 | Kernel's value only |

## 11. Provenance

Written from the kernel sources at the tags in section 3, the Intel SDM Volume 3A (253668-093US), and the project's measurements. The kernel sources were fetched from `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12. The replaced files were read for their exported names and callers only. Every rule rests on the sources and measurements above.
