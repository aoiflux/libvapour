# S80: Linux test fixtures: synthetic kernel layouts for the Linux tool tests

Version 1, 2026-11-12.

## 1. Purpose

The Linux tools are tested without a memory image. Three fixture packages lay out synthetic kernel objects in a sparse address space and declare a symbol table that describes them: `tools/linuxkern/kerntest` (modules, module parameters, taints, section attributes), `tools/linuxobj/linuxobjtest` (tasks, credentials, clocks, PIDs, files, mounts, network objects, module kallsyms and exports) and `tools/linuxtrace/linuxtracetest` (modules with core layouts, tasks with perf event lists, IDR trees). The tools read every offset from the symbol table, so a fixture is correct when its table and its bytes agree and when each layout is one a kernel could have. This specification fixes where each offset comes from, the rules every declared record keeps, and the behaviour of the helpers that the tool tests call.

The list, task, xarray and IDR walks the fixtures feed are S01 and S02. The page cache fixture (`s12_fixture.go`) is S12; the S38, S39, S46 and S61b fixture files are their own specifications and are kept.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel headers | `include/linux/*.h`, `include/net/*.h`, `fs/mount.h`, `net/netlink/af_netlink.h`, `net/packet/internal.h`, `kernel/module/internal.h`, `kernel/module/sysfs.c`, `kernel/trace/ftrace.c`, `kernel/kallsyms.c`, `kernel/panic.c`, `kernel/params.c`, `kernel/time/timekeeping.c`, `arch/x86/include/asm/page_64_types.h` and `pgtable_64_types.h`, at v4.19, v6.1, v6.4, v6.14 and v6.17. |
| ELF gABI | `Elf64_Sym` layout, `SHN_ABS`, `STB_GLOBAL`, `STT_FUNC`. |
| x86-64 psABI | LP64 scalar widths and natural alignment (Figure 3.1). |
| Dependent tests | The offsets that tests outside the fixture packages write or add on their own (section 3.4). |
| Captures | mem3_ubuntu24 (6.17) and mem4_fedora40 (6.14), through their own symbol tables, for section 9. |

No Limits field applies. No option is read.

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17, from git.kernel.org, accessed 2026-11-12. "Fixed" means the header sets the offset on x86-64 with no lock debugging (`CONFIG_DEBUG_LOCK_ALLOC`, `CONFIG_DEBUG_SPINLOCK` off), with `CONFIG_SMP`, `CONFIG_IPV6`, `CONFIG_NET_NS`, `CONFIG_SECURITY`, `CONFIG_EPOLL` and `CONFIG_DYNAMIC_FTRACE` on, as on both captures. "Placed" means rule A2 (section 4).

### 3.1 Addresses and data

| # | Fact | Source |
|---|---|---|
| A-F1 | `__START_KERNEL_map` is 0xffffffff80000000; `KERNEL_IMAGE_SIZE` is 1 GiB with `CONFIG_RANDOMIZE_BASE`; `MODULES_VADDR` is `__START_KERNEL_map + KERNEL_IMAGE_SIZE`, 0xffffffffc0000000. The kerntest table moves a symbol by the KASLR shift only inside that 1 GiB. | `arch/x86/include/asm/page_64_types.h`, `pgtable_64_types.h`, v4.19, v6.17. |
| A-F2 | `__PAGE_OFFSET_BASE_L4` is 0xffff888000000000 at v6.17 (0xffff880000000000 at v4.19). The linuxobjtest and linuxtracetest heaps start one MiB into it. | `page_64_types.h`, v4.19, v6.17. |
| A-F3 | `Text` is `__START_KERNEL_map` plus the default `CONFIG_PHYSICAL_START` of 16 MiB. | `page_64_types.h` `__START_KERNEL`, v6.17. |
| A-F4 | `taint_flags[]` is, in bit order, P/G, F, S, R, M, B, U, D, A, W, C, I, O, E, L, K, X, T, N, J, with the module flag set for P, F, C, O, E, K, X, T, N and J. | `kernel/panic.c`, v6.17. |
| A-F5 | `kernel_param_ops` objects `param_ops_byte`, `short`, `ushort`, `int`, `uint`, `long`, `ulong`, `ullong`, `hexint`, `charp`, `bool`, `invbool`, `string` and `param_array_ops` are defined by `kernel/params.c`. | `kernel/params.c`, v6.17. |
| A-F6 | `kallsyms_expand_symbol` reads a one-byte length, or two bytes when the first has bit 7 set (`(len & 0x7f) | (next << 7)`), then that many token indexes. With base-relative absolute-percpu offsets `kallsyms_sym_address` returns a non-negative offset as the address and a negative one as `kallsyms_relative_base - 1 - offset`. | `kernel/kallsyms.c`, v6.1, v6.17. |
| A-F7 | At v4.19 `add_kallsyms` stores each module symbol's type letter in `st_info`; from v6.1 it is in `mod_kallsyms.typetab`. | `kernel/module.c` v4.19; `kernel/module/kallsyms.c` v6.17. |
| A-F8 | A module section attribute's address is `bin_attribute.private` (`sattr->private = (void *)sec->sh_addr`). | `kernel/module/sysfs.c`, v6.17. |
| A-F9 | `MKDEV(ma, mi)` is `ma << 20 | mi`; `MNT_NOSUID` 0x01, `MNT_NODEV` 0x02, `MNT_SHARED` 0x1000; the first dynamic proc inode number is `PROC_DYNAMIC_FIRST`, 0xf0000000; a dentry is unhashed when `d_hash.pprev` is null. | `include/linux/kdev_t.h` v6.17; `include/linux/mount.h` v4.19; `fs/proc/generic.c` v4.19, v6.17; `include/linux/list_bl.h`, `dcache.h` v6.17. |
| A-F10 | An internal xarray entry is tagged 2 (`xa_mk_node`); `XA_CHUNK_SHIFT` is 6; an `xa_node` has three mark words after its 64 slots. | `include/linux/xarray.h`, v4.19 to v6.17. |
| A-F11 | Enumerations: `enum mod_mem_type` (v6.4, v6.17), `enum module_state` (all tags), `rt_scope_t` (uapi `rtnetlink.h`), `netdev_state_t` (`netdevice.h`), the `IFF_` bits (uapi `if.h`), `bpf_prog_type` (uapi `bpf.h`), the `xdp_sock` state (`xdp_sock.h`), `pid_type` (`pid_types.h` v6.17), all v6.17 unless named. | As listed. |

### 3.2 kerntest records

| # | Record | Members and offsets | Class | Source |
|---|---|---|---|---|
| K1 | `struct module` | state 0, list 8, name 24 (56 bytes), mkobj 80 | fixed | `module.h`, all tags (no `CONFIG_STACKTRACE_BUILD_ID`) |
| K2 | `struct module` | kp 176, num_kp 184, mem 320 (7 × 72, cache-line aligned, `__module_memory_align`), taints 824, kallsyms 832, sect_attrs 840, size 896 | placed, v6.17 order; mem clear of the bytes the moduledump test writes at 0x100 to 0x110 | `module.h` v6.17 |
| K3 | `module_memory` | base 0, is_rox 8, size 12, 72 bytes with `mtn` | fixed | `module.h` v6.17 |
| K4 | `kobject`, `module_kobject`, `kset` | name 0, entry 8, parent 24, kset 32, kref 56, 64 bytes; mod 64, 96 bytes; list 0, kobj 24, 96 bytes | fixed | `kobject.h`, `module.h`, v4.19, v6.17 |
| K5 | `mod_kallsyms`, `mod_tree_root`, `latch_tree_root` | symtab 0, num_symtab 8, strtab 16, typetab 24; root 0, addr_min 24, addr_max 32; seq 0, tree 8, 24 bytes | fixed (`CONFIG_MODULES_TREE_LOOKUP`) | `module.h` v6.1+, `kernel/module/internal.h` v6.17, `rbtree_latch.h` |
| K6 | `kernel_param`, `kernel_param_ops`, `kparam_array`, `kparam_string` | name 0, mod 8, ops 16, perm 24, level 26, flags 27, union 32, 40 bytes; flags 0, set 8, get 16, free 24; max 0, elemsize 4, num 8, ops 16, elem 24; maxlen 0, string 8 | fixed | `moduleparam.h`, v4.19, v6.17 |
| K7 | `taint_flag` | c_true 0, c_false 1, module 2, desc 8, 16 bytes | fixed | `panic.h` v6.17 |
| K8 | `attribute`, `attribute_group`, `bin_attribute`, `module_sect_attrs` | name 0, mode 8; attrs 32, bin_attrs union 40, 48 bytes; attr 0, size 16, private 24, 88 bytes; grp 0, attrs 48 | fixed | `sysfs.h` v6.14, v6.17; `kernel/module/sysfs.c` v6.14, v6.17 |
| K9 | `Elf64_Sym` | st_name 0, st_info 4, st_other 5, st_shndx 6, st_value 8, st_size 16, 24 bytes | fixed | ELF gABI |

### 3.3 linuxobjtest and linuxtracetest records

| # | Record | Members and offsets | Class | Source |
|---|---|---|---|---|
| O1 | `task_struct` | flags 0, ptrace 4, sched_class 8, tasks 0x10, mm 0x20, active_mm 0x28, exit_state 0x30, pid 0x34, tgid 0x38, real_parent 0x40, parent 0x48, ptraced 0x50, ptrace_entry 0x60, pid_links 0x70 (4 × 16), thread_node 0xb0, worker_private 0xc0, start_boottime 0xc8, real_cred 0xd0, cred 0xd8, comm 0xe0 (16), fs 0xf0, files 0xf8, nsproxy 0x100, signal 0x108; size 0x1a8 | placed, v6.17 order | `sched.h` v6.17 |
| O2 | `signal_struct`, `cred` | thread_head 0x10; uid 8, gid 0xc, euid 0x18, egid 0x1c, caps 0x30 to 0x50 by 8 (`kernel_cap_t` is one u64), size 0x58 to the last cap | fixed | `sched/signal.h` v4.19, v6.17; `cred.h`, `capability.h` v6.17 |
| O3 | `tk_core`, `timekeeper` | seq 0, timekeeper 8; offs_real 0x40, offs_boot 0x48, size 0x50 | tk_core fixed (v6.1 form); offs_* placed after wall_to_monotonic and the S46 slots 0 to 8 and 0x20 to 0x40 | `kernel/time/timekeeping.c` v6.1; `timekeeper_internal.h` v6.17 |
| O4 | `pid`, `upid`, `pid_namespace`, `idr`, `xarray`, `xa_node`, `address_space` | tasks 0x40, numbers 0x90, size 0xa0; nr 0, ns 8; idr 0; idr_rt 0, 0x18; xa_head 8; shift 0, slots 0x28, size 0x240; i_pages 8, nrpages 0x18 (placed) | fixed except nrpages | `pid.h`, `pid_namespace.h`, `idr.h`, `xarray.h`, `fs.h`, v6.17 |
| O5 | `mm_struct` | mmap 0 (fixed); pgd 0x18, start_brk 0x20, brk 0x28, start_stack 0x30, arg_start 0x38, arg_end 0x40, env_start 0x48, env_end 0x50, context 0x58; size 0xb8 | placed, v4.19 order, after mm_rb and vmacache_seqnum; size covers exe_file (S61b, 0xa0) and the memoryranges maple members (0xa0 to 0xb4) | `mm_types.h` v4.19 |
| O6 | `vm_area_struct` | vm_start 0, vm_end 8, vm_next 0x10, vm_mm 0x40, vm_flags 0x50, vm_pgoff 0x98, vm_file 0xa0, size 0xb0 | fixed | `mm_types.h` v4.19 |
| O7 | `file`, `path`, `fs_struct`, `files_struct`, `fdtable` | f_op 8, f_inode 0x20, f_path 0x40, size 0xb8; mnt 0, dentry 8; root 0x18, pwd 0x28, size 0x38; fdt 0x20, size 0x60 (to fdtab); max_fds 0, fd 8, size 0x38 | fixed | `fs.h` v6.17; `path.h`; `fs_struct.h`, `fdtable.h` v4.19, v6.17 |
| O8 | `dentry`, `qstr`, `dentry_operations` | d_hash 8, d_parent 0x18, d_name 0x20, d_inode 0x30 (fixed); d_op 0x38, d_fsdata 0x40, d_child 0x48, d_subdirs 0x58, size 0x68 (placed, v4.19 order; the linuxobj files test reads d_fsdata right after d_op); hash 0, len 4, name 8; d_dname 0x48, size 0x68 | mixed | `dcache.h` v4.19 to v6.17 |
| O9 | `inode` | i_mode 0 (fixed); i_sb 0x10, i_mapping 0x18, i_ino 0x20, i_nlink 0x28, i_size 0x30, i_atime 0x38, i_mtime 0x48, i_ctime 0x58, i_count 0x68, i_link 0x70, i_private 0x200 (where the linuxobj files test writes it), size 0x208 | placed, v6.1 order | `fs.h` v6.1 |
| O10 | `super_block`, `file_system_type`, `vfsmount`, `mount` | s_dev 0x10, s_type 0x28, s_flags 0x50, s_root 0x68 (fixed); s_uuid 0x70, s_subtype 0x80, size 0x88 (placed); name 0; mnt_root 0, mnt_sb 8, mnt_flags 0x10, 0x20; mnt_parent 0x10, mnt_mountpoint 0x18, mnt 0x20, mnt_node 0x40 (fixed); mnt_devname 0x58, mnt_list 0x60, mnt_share 0x70, mnt_master 0x80, mnt_ns 0x88, mnt_id 0x90, mnt_group_id 0x94, size 0x98 (placed) | mixed | `fs.h` v4.19, v6.17; `mount.h`, `fs/mount.h` v6.17 |
| O11 | `mnt_namespace`, `ns_common`, `nsproxy` | ns 0 (v6.17), list 0x18 (v4.19 member, placed), size 0x38 covering the seq the files test adds at 0x30; stashed 0, ops 8, inum 0x10, 0x18; mnt_ns 0x18, net_ns 0x28, time_ns 0x30, 0x48 | mixed | `fs/mount.h` v4.19, v6.17; `ns_common.h`, `nsproxy.h` v4.19 to v6.17 |
| O12 | `page` | flags 0, mapping 0x18, index 0x20, 64 bytes | fixed | `mm_types.h` v4.19, v6.4 |
| O13 | `net`, `netns_nf` | list 0, ns 0x10, dev_base_head 0x28, nf 0x38, 0xc8; hooks_ipv4 0 (5), ipv6 0x28 (5), arp 0x50 (3), bridge 0x68 (5), 0x90 | placed, v6.17 order | `net_namespace.h`, `netns/netfilter.h`, uapi `netfilter.h`, `netfilter_arp.h` v6.17 |
| O14 | `net_device` | mtu 0, nf_hooks_egress 8, state 0x10, flags 0x18, ip6_ptr 0x20, xdp_prog 0x28, ifindex 0x30, nd_net 0x38, name 0x40, dev_list 0x50, gflags 0x60, operstate 0x64 (unsigned int), perm_addr 0x68 (32), addr_len 0x88, ip_ptr 0x90, dev_addr 0x98, nf_hooks_ingress 0xa0, qdisc 0xa8, tx_queue_len 0xb0, 0xb8 | placed, v6.17 order | `netdevice.h` v6.17 |
| O15 | `Qdisc`, `Qdisc_ops`, `in_device`, `in_ifaddr`, `inet6_dev`, `inet6_ifaddr` | ops 0x18; id 0x10; ifa_list 8 (placed); ifa_next 0x10, ifa_local 0x30, ifa_address 0x34, ifa_scope 0x44, ifa_prefixlen 0x45, 0x78; addr_list 8 (placed); addr 0, prefix_len 0x10, scope 0x32 (u16), if_list 0x50 (placed) | mixed | `sch_generic.h`, `inetdevice.h`, `if_inet6.h` v6.17 (in_ifaddr also v4.19) |
| O16 | `socket`, `socket_alloc`, `sock_common`, `sock` | state 0, sk 0x18, 0x80 (wq on a cache line); socket 0, vfs_inode 0x80; skc_daddr 0, skc_rcv_saddr 4, skc_portpair 0xc (dport 0xc, num 0xe), skc_family 0x10, skc_state 0x12, skc_v6_daddr 0x38, 0x88 (fixed); sk_filter 0x88, sk_socket 0x90, sk_type 0x98, sk_protocol 0x9a, sk_destruct 0xa0, sk_reuseport_cb 0xa8, 0xb0 (placed, v6.17 order) | mixed | `net.h`, `sock.h` v6.17 |
| O17 | Family socks | inet_sock pinet6 0xb0, inet_sport 0xc6; unix_sock addr 0xb0, peer 0x108; netlink_sock portid 0xb8, dst_portid 0xbc, dst_group 0xc0, groups 0xd0 (fixed from the sock), module 0x108 (placed after dump_done_errno); packet_sock ifindex 0xb0, num 0xb4; xdp_sock dev 0xb0, state 0xb8 (placed); all 0x110 | mixed | `inet_sock.h`, `af_unix.h`, `af_netlink.h`, `packet/internal.h`, `xdp_sock.h` v6.17 |
| O18 | `unix_address`, `sockaddr_un` | len 4, name 8; sun_family 0, sun_path 2 (108) | fixed | `af_unix.h` v6.17, uapi `un.h` |
| O19 | `sk_filter`, `bpf_prog`, `bpf_prog_aux` | prog 0x18; type 4, aux 0x38, 0x48; id 0x20 (fixed), name 0x24 (placed), 0x38 | mixed | `filter.h`, `bpf.h` v6.17 |
| O20 | `nf_hook_entry`, `nf_hook_entries`, `nf_hook_ops` | hook 0, priv 8; num_hook_entries 0, hooks 8; list 0, hook 0x20, priority 0x40, 0x48 | fixed | `netfilter.h` v6.17 |
| O21 | linuxobjtest modules | module state 0, list 8, name 0x18, mkobj 0x50 (fixed); syms 0xb0, num_syms 0xb8, mem 0xc0, kallsyms 0x2b8 after seven 72-byte S38 tree elements, size 0x2c0 (placed); module_memory base 0, size 8 (v6.4, no tree lookup); mod_tree_root addr_min 0, addr_max 8 (no tree lookup); mod_kallsyms v4.19 form (0x18) or v6.1 form with typetab 0x18 (0x20) | mixed | `module.h` v4.19, v6.1, v6.4; `kernel/module/internal.h` v6.4 |
| O22 | Export and trace lists | kernel_symbol PREL32 12 bytes (value_offset, name_offset, namespace_offset) or absolute v4.19 (value 0, name 8); ftrace_mod_map list 0x10, mod 0x20, funcs 0x38, 0x50; ftrace_mod_func name 0x10, ip 0x18, size 0x20, 0x28; ftrace_ops trampoline 0x90, trampoline_size 0x98, list 0xa0, 0xb0; bpf_ksym start 0, end 8, name 0x10 (`KSYM_NAME_LEN` 512), lnode 0x210, 0x258 | fixed | `export.h` v4.19, v6.1; `ftrace.c`, `ftrace.h` v6.17; `bpf.h`, `kallsyms.h` v6.1, v6.17 |
| T1 | linuxtracetest module | state 0, list 8, name 0x18, mkobj 0x50 (fixed); core_layout 0xb0, init_layout 0xc8, kallsyms 0xe0 (placed, v6.1 order), size 0x100 covering the tracepoints test members at 0xf0 to 0xfc; module_layout base 0, size 8, text_size 0xc, 0x18 (no tree lookup); mod_tree_root addr_min 0, addr_max 8 | mixed | `module.h` v6.1, `kernel/module/internal.h` v6.1 |
| T2 | linuxtracetest task | flags 0, tasks 8, mm 0x18, active_mm 0x20, pid 0x28, tgid 0x2c, real_parent 0x30, thread_node 0x38, comm 0x48, nsproxy 0x58, signal 0x60, perf_event_list 0x68, 0x78; signal_struct thread_head 0x10 (fixed); nsproxy 0x48; mm_struct pgd 0 | placed, v6.17 order | `sched.h`, `nsproxy.h` v6.17 |

### 3.4 Offsets the dependent tests fix

| # | Test | What it relies on |
|---|---|---|
| D1 | `tools/linux/moduledump` | Writes 16 bytes at module + 0x100 and reads them back as section data, so no kerntest module member may lie there (K2). |
| D2 | `tools/linuxmodule` fuzz test | Reads the section attributes at module + 0x2000. |
| D3 | `tools/linuxmodule`, `tools/linux/tracingftrace` | Write `mod_tree` + 24 and + 32, `kernel_param` + 16 and + 32 and `mod_kallsyms` + 8, + 16, + 24 by number: all fixed offsets (K5, K6). |
| D4 | `tools/linuxobj` files test | d_fsdata at d_op + 8; i_private at 0x200; mnt_namespace seq at 0x30; split inode times at 0x58 to 0x7c (O8, O9, O11). |
| D5 | `tools/linux/socketlist` | Adds task_struct.files at 0x110 to the NewKernel layout (O1). |
| D6 | `tools/linux/processkernelstack` | Adds task_struct.thread at 0x180 and stack at 0x1a0 (O1). |
| D7 | `tools/any/memoryranges` | Adds mm_struct.mm_mt at 0xa0 and map_count at 0xb0 (O5). |
| D8 | `tools/linux/tracingtracepoints` | Adds module.num_tracepoints and tracepoints_ptrs at 0xf0 and 0xf8 inside `ModuleSize` (T1). |
| D9 | The kept `s38`, `s39`, `s46` and `s61b` fixture files | Extend nsproxy (time_ns 0x30), timekeeper (0, 0x20 to 0x40), vm_area_struct (0x48, 0x68, 0x70) and mm_struct (0xa0); module_memory switches to the 72-byte form, with `ModuleMem` as the array start. |

## 4. Algorithm

1. A1 (fixed). Where every member before a declared member has a size and alignment its header fixes, under the configuration of section 3, the member takes its C offset under the x86-64 psABI.
2. A2 (placed). Elsewhere the fixture places the members it declares, and only those, in the header's declaration order at the reference tag named in section 3, each at the next offset aligned to its natural alignment after the end of the previous one, starting at the end of the fixed prefix. Two exceptions: a range a dependent test or a kept fixture writes (section 3.4) is skipped, and a member a dependent test fixes is put where the test puts it.
3. A3 (size). A record's size is the header's size when every member is fixed, else the end of its last declared member or reserved range.
4. A4 (shared records). linuxobjtest declares `file`, `path`, `files_struct`, `fdtable`, `dentry`, `qstr`, `dentry_operations`, `inode`, `timespec64`, `atomic_t` and `ns_common` once, at one layout, for both `AddFS` and `AddNetTypes`, in either order. A member is added to `task_struct` or `nsproxy` by replacing any member of the same name.
5. A5 (symbol table). Every table declares the x86-64 psABI LP64 scalars under their DWARF base type names, so `long` is 8 bytes whatever the fallback in `symbols` does.
6. A6 (helpers). Lists are made circular in the order given (`list_add_tail` order); a thread group shares one `signal_struct` whose `thread_head` comes first; an xarray of indexes below 64 is one node, else a shift-6 root over leaves; an IDR stores ids from 1; kallsyms tables use one-byte tokens equal to the byte, so a name compresses to itself (A-F6).

## 5. Validity rules

| # | Rule | Justification | On failure |
|---|---|---|---|
| L1 | A member ends inside its record; a pointer or a 2, 4 or 8-byte scalar sits on its natural alignment; two members overlap only when one holds the other (union and alias members). | psABI; A1 to A3 | Package test fails |
| L2 | `AddFS` then `AddNetTypes`, or the reverse, give the same members at the same offsets for the shared records. | A4 | Package test fails |
| L3 | The kallsyms tables decode, by A-F6, to the names and addresses given. | A-F6 | Package test fails |
| L4 | Every xarray and IDR entry is found by descending from the head by the node shifts. | A-F10 | Package test fails |

## 6. Failure modes

| Case | Result |
|---|---|
| Reading a page that was never mapped | kerntest: `kerntest: <addr> is not mapped` wrapping `memory.ErrOutOfBounds`; linuxobjtest: `memory.ErrUnmapped`; linuxtracetest: `memory.ErrOutOfBounds`. |
| A read whose range wraps the address space | `memory.ErrOutOfBounds` in all three. |
| A kallsyms symbol whose offset does not fit an `int32` | panic `linuxobjtest: <name> at <addr> is too far from base <base> for kallsyms`. |
| A helper reading a pointer that is not mapped | panic with the read error. |
| `ParamOpsAt` of an unknown name | panic `kerntest: no kernel_param_ops named <name>`. |
| The kerntest table does not build | `t.Fatalf("kerntest: build the table: ...")`; linuxtracetest `Build` returns `linuxtracetest: build the symbol table: %w`. |

## 7. Result schema

The exported API of the three packages is kept name for name and signature for signature: constants, types (`Memory`, `Types`, `Table`, `F`, `T`, `Fixture`, `ModuleSpec`, `Kernel`, `Task`, `Cred`, `Inode`, `SuperBlock`, `Mount`, `MM`, `VMA`, `Net`, `Device`, `InAddr`, `Inet6Addr`, `Sock`, `Modules`, `ModuleSymbol`, `KallsymsLists`, `ElfSym`, `Export`, `FtraceFunc`, `KSym`, `Translating`, `Tree`, `RootFS`, `UserSpaces`, `Flat`, `Member`, `Type`, `Module`), functions and methods. Constant values change to those of section 3; the `Net*` file, dentry, inode, files and task constants now equal the `FS*` ones.

## 8. Limits

None. Fixture memory is bounded by what a test writes.

## 9. Acceptance

- Package tests: L1 over every record the three packages declare, before and after the S39, S46 and S61b extensions; L2; L3 with a two-byte-length name and a non-negative absolute offset; L4 over one and two levels; list and thread-group links; the page-boundary read, hole and wrap behaviour of each `Memory`.
- Fuzz targets: `FuzzMemoryWriteReadsBack` in each package (a write reads back unchanged), 30 s each.
- Dependent tests: every package that imports a fixture package passes with the new values.
- Captures: `linuxfixturefacts` printed the capture's own offsets for 129 record members and 31 record sizes. Every member section 3 classes as fixed at v6.17 has the same offset on mem3_ubuntu24 (6.17), and the sizes of `kobject` 0x40, `module_kobject` 0x60, `kset` 0x60, `module_memory` 0x48, `mod_kallsyms` 0x20, `mod_tree_root` 0x28, `kernel_param` 0x28, `taint_flag` 0x10, `attribute_group` 0x30, `bin_attribute` 0x58, `fdtable` 0x38, `fs_struct` 0x38, `vfsmount` 0x20, `ns_common` 0x18, `nsproxy` 0x48, `page` 0x40, `upid` 0x10, `xa_node` 0x240, `idr` 0x18, `sock_common` 0x88, `socket` 0x80, `sk_filter` 0x20, `nf_hook_ops` 0x48, `ftrace_mod_map` 0x50, `ftrace_mod_func` 0x28, `bpf_ksym` 0x258, `kernel_symbol` 0xc, `file` 0xb8, `qstr` 0x10 and `path` 0x10 agree. mem4_fedora40 (6.14) differs where the headers differ between the tags: `module_memory` is 0x50 with `size` at 0x14 (`rw_copy`), `pid.tasks` 0x38 and `numbers` 0x88, `file.f_op` 0x10 and `f_inode` 0x28, `nf_hook_ops.hook` 0 and `priority` 0x20; `cred` is 0xb8 on both, and the fixture's 0x58 ends at `cap_ambient` by A3. `page.index` is absent on mem3, where the 6.17 table names it in the folio.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The address constants (`Text`, `Etext`, `Data` and the data symbol slots, `ParamOps`, the linuxtracetest data slots) keep their values: dependent tests place their own objects at `Data + 0x2000` to `Data + 0x4000`, `Text + 0x2000` and similar, and moving the slots would collide. | Owner decision: renumber with the tests |
| O2 | `UpidPIDChain` names a member no supported tag has (`upid.pid_chain`); it is kept for the API freeze at the end of `upid` and is not declared in the table. | Owner decision: remove the export. Owner decision 2026-11-12: remove the export. Done: `UpidPIDChain` and its comment removed from `tools/linuxobj/linuxobjtest/pid.go`; no package used it. |
| O3 | Some offsets are set by dependent tests rather than by a header (section 3.4: d_fsdata after d_op, i_private at 0x200, the mnt_namespace seq slot, module + 0x100). | Owner decision: let those tests read the fixture constants, then return the members to A1 or A2 |
| O4 | The fixtures mix reference tags per record (v4.19 for `mm_struct.mmap`, `vm_area_struct`, `d_child`, `mnt_namespace.list`; v6.1 for inode times and `tk_core`; v6.17 elsewhere), because the tool tests cover the older member forms. No single kernel has all of them. | Owner decision |
| O5 | linuxobjtest and linuxtracetest base module types model a kernel without `CONFIG_MODULES_TREE_LOOKUP` (`mod_tree_root.addr_min` at 0); kerntest and the S38 fixture model one with it (24). | Owner decision |
| O6 | Private-structure member names come from the kernel headers (Q3). | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep values |
| O2 | Remove the export |
| O3 | Keep as is |
| O4 | Keep mixed |
| O5 | Keep both models |
| O6 | From headers |

## 11. Provenance

Written from the Linux kernel sources at v4.19, v6.1, v6.4, v6.14 and v6.17 (git.kernel.org, accessed 2026-11-12), the ELF gABI, the x86-64 psABI, the Intel SDM Vol. 3A (page size), and the project's measurement `linuxfixturefacts` on mem3_ubuntu24 and mem4_fedora40. The old fixture files were read only for exported names and callers. Every rule rests on the sources and measurements above. Author: the project.
