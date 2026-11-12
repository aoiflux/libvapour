# S62: Linux kernel, network and file tools

Version 1, 2026-11-12.

## 1. Purpose

This specification covers fifteen Linux tools whose readers are specified elsewhere: the list and task walks (S01, S02), the module model (S06), kallsyms (S38), files, paths and mounts (S39), network namespaces and devices (S40), the kernel object core (S46), the kernel readers (S54), VMCOREINFO (S05) and the socket decoder (S13). Each tool has its own facts, rules, failure modes, schema and measurements below, grouped by subject. The tools keep their registered names and option keys.

`linux.tty.check` answers: which code receives the bytes typed on each terminal? Every tty with a line discipline hands incoming data to the discipline's `receive_buf2` or `receive_buf` handler. A handler that lies outside the kernel image and the known modules, or in a module that has no business there, is how a keystroke logger sits in the input path. The tool lists, for each tty a driver holds, the discipline and each set receive handler with the module or kernel symbol that holds it.

`linux.keyboard.list_notifiers` answers: which callbacks does the console keyboard driver call for every key event? The chain `keyboard_notifier_list` is the documented way for a module to see each keystroke. The tool lists each callback on the chain in call order, with its priority and owner.

`linux.tracing.check_tracepoints` answers: which tracepoints exist in the kernel and its modules, and which probe functions are attached to each? A probe runs on every hit of its tracepoint with the tracepoint's arguments, so a probe in unexpected code observes or alters kernel activity. The tool lists every tracepoint, its static key state and each attached probe with its priority, data pointer and owner.

`linux.tracing.list_perf_events` answers: which tasks opened performance events that run an eBPF program, and which program? A program attached through `perf_event_open` (tracepoint, kprobe, uprobe or a sampling event) runs on every event. The tool lists each such event with its task, PMU, type and config, and the program's id, name and kernel symbol.

`linux.kernel.list_symbols` answers which names the kernel itself would give the addresses an examiner meets: the core image's symbols, decoded from the kernel's own compressed kallsyms tables found through VMCOREINFO without any symbol file, followed by the symbols of loaded modules, ftrace and BPF programs, in the order `/proc/kallsyms` lists them.

`linux.kernel.list_io_memory` lists the kernel's tree of physical address resources, the content of `/proc/iomem`: which ranges are RAM, reserved, ACPI tables or device memory, and which driver claimed each, with each node's place in the tree.

`linux.image.read_vmcoreinfo` lists every VMCOREINFO note found in physical memory and each entry of its table exactly as the kernel wrote it. It needs no symbols and is the first thing to read on an unknown Linux capture: release, page size, KASLR offset and the structure offsets the kernel published about itself.

`linux.framebuffer.list` lists the framebuffers registered with the fbdev core (the console or splash screen a Linux host was showing) with their geometry and pixel format, and can save each one's screen memory, as a PNG picture when the pixel format is packed true colour.

`linux.network.check_operations` answers whether the functions that produce the `/proc/net` listings (`tcp`, `udp`, `raw`, `icmp`, `unix`, `packet`, `netlink`, `arp` and their IPv6 forms) are still the kernel's own. A rootkit that wants to hide a connection from those listings replaces the `show` function of the listing's `struct seq_operations`. The tool reads every member of each table and says, for each, which module or kernel image holds the target and whether the target is where the kernel's own build would put it.

`linux.network.list_interfaces` and `linux.network.list_addresses` list every network device of every network namespace, and the IPv4 and IPv6 addresses configured on each, with the values the kernel itself reports. They are thin tools over the S40 readers and keep S40's row decisions.

`linux.network.list_hooks` lists every function placed in a Netfilter chain, in every namespace and on every device, with its priority, the module or kernel image that holds it, and a check of the entry against the registration the kernel keeps beside it. A packet filter, a NAT rule or a rootkit that inspects traffic all appear here.

`linux.socket.scan` finds `struct sock` objects in physical memory without walking any list, so it also finds sockets that are no longer reachable from a process: closed, orphaned or freed ones whose memory has not been reused. It finds candidates two ways, by the destructor every sock carries and by the open files that hold a socket, and says for each sock whether its `struct socket` still points back at it. The sock is decoded by the S13 decoder.

`linux.mount.list` answers: what did each mount namespace have mounted, and how would a process in it have seen each mount? It gives, per namespace, the lines `/proc/<pid>/mountinfo` would show from a task's root: the mount and parent numbers, the device, the root inside the filesystem, the mount point, the options, the propagation tags, the filesystem type, the source and the superblock options. With `mount_format` it also gives the option column of `/proc/<pid>/mounts`. The path walk, the mount tree and the flag words are S39; this specification adds which task reads which namespace and how a line is assembled.

`linux.file.list_open` answers: which files did each task hold open? It gives, for every thread and descriptor, the name `/proc/<pid>/fd/<n>` would resolve to and the inode facts `stat` would report. The descriptor table, the shown path and the inode readers are S39; this specification adds the row rules and how losses are counted.

## 2. Inputs

### Terminal, keyboard and tracing hooks

#### linux.tty.check

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxkern.Kernel` (S54) | Kernel memory, the symbol table, masked addresses. |
| Symbols | symbol table | `tty_drivers`; the types of TT1 to TT6. |
| Module model | S06 `Views`, `Known`, `Lookup` | Owner of each handler address. |
| Limits | effective `limits.Limits` | `MaxListEntries` (driver list, S01), `MaxTableEntries` (slots per driver). |
| Strict | option `strict` | Fails the run on any loss. |

No tool options.

#### linux.keyboard.list_notifiers

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxkern.Kernel` (S54) | As above. |
| Symbols | symbol table | `keyboard_notifier_list`; `atomic_notifier_head`, `notifier_block`. |
| Module model | S06 | Owner of each callback. |
| Limits | `MaxListEntries` | Blocks on the chain. |
| Strict | option `strict` | Fails the run on any loss. |

No tool options.

#### linux.tracing.check_tracepoints

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxtrace.Kernel` (S54) | Kernel memory, the symbol table, canonical addresses. |
| Symbols | symbol table | The addresses of `__start___tracepoints_ptrs` and `__stop___tracepoints_ptrs` (no type is needed); `tracepoint`, `tracepoint_func`, `static_key`, `module.tracepoints_ptrs`, `module.num_tracepoints`. |
| Module model | S06 | The known modules' own tracepoint sections and the owner of each probe. |
| Limits | `MaxTableEntries` (entries per section), `MaxListEntries` (probes per tracepoint). | |
| Strict | option `strict` | Fails the run on any loss. |

No tool options.

#### linux.tracing.list_perf_events

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxtrace.Kernel` (S54) | As above. |
| Tasks | S01 task walk with threads | Every thread's `perf_event_list`. |
| Symbols | symbol table | `task_struct`, `perf_event`, `perf_event_attr`, `pmu`, `bpf_prog`, `bpf_prog_aux`, `bpf_ksym`. |
| Limits | `MaxListEntries` | Task walk and each event list (S01). |
| Strict | option `strict` | Fails the run on any loss. |

No tool options.

### Kernel symbols, resources, VMCOREINFO and framebuffers

#### linux.kernel.list_symbols

| Field | Type | Meaning |
|---|---|---|
| Physical memory | option `physical_memory` | Searched for VMCOREINFO (S05) to find and decode the core kallsyms tables; needed for the core symbols. |
| Kernel, symbol table | `tools.Context` | Needed for the module, ftrace and BPF symbols (S38 lister); not needed for the core symbols. |
| Options | `linux.kernel.list_symbols.core`, `.modules`, `.ftrace`, `.bpf` (bool) | Select the sources; none set selects all four. A value that is not a boolean is an error. |
| Strict | option `strict` | A damaged VMCOREINFO copy, or any failed module, ftrace or BPF read, fails the run. |
| Limits | effective `limits.Limits` | Passed to the VMCOREINFO search, the kallsyms decoder and the S38 lister. |

#### linux.kernel.list_io_memory

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxkern.Kernel` (S54) | Kernel memory and the symbol table. |
| Symbols | symbol table | `iomem_resource`; `struct resource` members `start`, `end`, `name`, `flags`, `parent`, `sibling`, `child`. |
| Strict | option `strict` | A tree read in part fails the run. |
| Limits | `MaxListEntries`, `MaxRecursionDepth`, `MaxNameBytes` | Section 8. |

#### linux.image.read_vmcoreinfo

| Field | Type | Meaning |
|---|---|---|
| Physical memory | option `physical_memory` | Scanned with the S05 scan. No symbol table is used. |
| Strict | option `strict` | A damaged copy fails the run. |
| Limits | effective `limits.Limits` | Passed to the S05 scan. |

#### linux.framebuffer.list

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxkern.Kernel` (S54) | Kernel memory and the symbol table. |
| Symbols | symbol table | `registered_fb`, optional `num_registered_fb`; the `fb_info`, `fb_var_screeninfo`, `fb_fix_screeninfo`, `fb_bitfield`, `device` and `kobject` members of section 3. |
| Options | `linux.framebuffer.list.dump` (bool), `output_dir`, `max_dump_size` | Save each framebuffer; the directory; the size cap. |
| Strict | option `strict` | An unreadable slot or `fb_info` fails the run. |
| Limits | `MaxArtifactBytes` (through `DumpLimit`), `MaxImageBytes`, `MaxNameBytes` | Section 8. |

### Network objects and socket scan

#### linux.network.check_operations

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxobj.Kernel` | Kernel memory and the symbol table. |
| Symbols | symbol table | The type `seq_operations`; the table symbols of NO2; `_text`, `_etext` (S06 4.5). |
| Module model | S06 `linuxmodule.Model` | `Views().Known()` and `Lookup`. |
| Options | none | Strict mode only. |

#### linux.network.list_interfaces, linux.network.list_addresses

S40 section 2. No options besides strict mode.

#### linux.network.list_hooks

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxobj.Kernel` | As S40. |
| Symbols | symbol table | `net.nf`, `netns_nf` arrays, `nf_hook_entries`, `nf_hook_entry`, `nf_hook_ops`, `net_device.nf_hooks_ingress` and `nf_hooks_egress` when present; `accept_all` when present. |
| Module model | S06 | As above. |
| Limits | effective | `MaxListEntries` for the S01 namespace and device walks. |

#### linux.socket.scan

| Field | Type | Meaning |
|---|---|---|
| Physical memory | option `physical_memory` | The memory scanned. |
| Kernel layer | `tools.Context.Memory` | Kernel-space reads; its `Translate` method, when it has one, gives the physical address of a kernel address. |
| Symbols | symbol table | The destructors of SS1, `socket_file_ops`; `sock.sk_destruct`, `sock.sk_socket`, `sock.__sk_common`, `sock.sk_type`, `sock_common.skc_family`, `file.f_op`, `file.private_data`, `socket.sk`; the S13 decoder's types. |

### Mounts and open files

#### linux.mount.list

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxobj.Kernel` (S39, S46) | Kernel memory, the symbol table and the effective Limits. |
| Tasks | S01 task walk, thread-group leaders | Each task is a possible reader of its namespace. |
| Options | `linux.mount.list.mntns` (list of unsigned), `linux.mount.list.mount_format` (bool), the session PID set, `strict` | Unchanged keys. |
| Limits | `MaxListEntries` (S01, S39 4.6), `MaxPathSteps`, `MaxNameBytes` (S39) | Section 8. |

#### linux.file.list_open

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxobj.Kernel` | As above. |
| Tasks | S01 task walk with threads | Each thread's descriptor table. |
| Path walker | `memoryranges.LinuxWalker` (S39 4.4) | The shown path from the thread's root. |
| Options | `linux.file.list_open.files_only` (bool), the session PID set, `strict` | Unchanged keys. |
| Limits | `MaxTableEntries` (descriptor slots, S39), `MaxPathSteps`, `MaxNameBytes` | Section 8. |

## 3. Facts from the sources

Kernel sources were fetched from `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12 at the tags v4.19, v6.1, v6.4, v6.14 and v6.17; each table states the tags checked, and a row that names fewer tags was checked only at those. Paths are under the kernel tree. The supported captures run 6.17 (Ubuntu 24, mem3) and 6.14 (Fedora 40, mem4). Measurement rows (`…M<n>`) were taken with `linuxkernfacts` on 2026-11-12.

### Terminal, keyboard and tracing hooks

#### linux.tty.check

Tags checked: v4.19, v6.1, v6.4, v6.14, v6.17 for every row.

| # | Fact | Source |
|---|---|---|
| TT1 | `tty_drivers` is a `LIST_HEAD`; `tty_register_driver` links each driver with `list_add(&driver->tty_drivers, &tty_drivers)` and unregistering removes it with `list_del`. | `drivers/tty/tty_io.c`; `include/linux/tty_driver.h` |
| TT2 | `struct tty_driver` has `const char *name`, `int name_base`, `unsigned int num` (devices allocated), `struct tty_struct **ttys` and `struct list_head tty_drivers`. | `include/linux/tty_driver.h` |
| TT3 | `__tty_alloc_driver` sets `num = lines` and allocates `ttys` as `lines` pointers only when `TTY_DRIVER_DEVPTS_MEM` (0x0010) is clear; otherwise `ttys` stays null from `kzalloc`, and the ttys of that driver live in devpts. | `drivers/tty/tty_io.c`; `include/linux/tty_driver.h` |
| TT4 | `tty_standard_install` stores a tty at its own index: `driver->ttys[tty->index] = tty`, and `tty_driver_remove_tty` clears the slot to null. A filled slot therefore holds a tty whose `index` is the slot number and whose `driver` is the driver. | `drivers/tty/tty_io.c` |
| TT5 | `struct tty_struct` has `int index`, `struct tty_driver *driver`, `struct tty_ldisc *ldisc` and `char name[64]`; `struct tty_ldisc` has `struct tty_ldisc_ops *ops`; `struct tty_ldisc_ops` has `char *name`, `receive_buf` and `receive_buf2`. | `include/linux/tty.h`, `include/linux/tty_ldisc.h` |
| TT6 | `alloc_tty_struct` names a tty with `tty_line_name(driver, idx, tty->name)`, which writes the driver's `name` (and `index + name_base` unless the node is unnumbered) into the 64-byte array. | `drivers/tty/tty_io.c` |
| TT7 | `tty_ldisc_receive_buf` calls `ld->ops->receive_buf2` when it is set and otherwise `receive_buf`; `n_tty_ops` sets both (`n_tty_receive_buf`, `n_tty_receive_buf2`). Both members are a receive path. | `drivers/tty/tty_buffer.c`, `drivers/tty/n_tty.c` |
| TTM1 | Both tables type every TT2 and TT5 member (`ttys` as a pointer, `name` as `char[64]`, both handler members). `tty_drivers` is listed. | `linuxkernfacts -only g1types` |
| TTM2 | Drivers and slots. | Section 9 |

#### linux.keyboard.list_notifiers

Tags checked: v4.19, v6.1, v6.4, v6.14, v6.17.

| # | Fact | Source |
|---|---|---|
| KN1 | `keyboard_notifier_list` is a static `ATOMIC_NOTIFIER_HEAD`; `register_keyboard_notifier` adds with `atomic_notifier_chain_register`. | `drivers/tty/vt/keyboard.c` |
| KN2 | `struct atomic_notifier_head` is `spinlock_t lock` then `struct notifier_block *head`; `struct notifier_block` has `notifier_call`, `struct notifier_block *next` and `int priority`. | `include/linux/notifier.h` |
| KN3 | A chain is a singly linked list ending at a null `next`; `notifier_call_chain` calls each block from `head` in order. | `kernel/notifier.c` |
| KN4 | `notifier_chain_register` inserts a block before the first block of lower priority, so a chain is in non-increasing priority. From v6.1 it also refuses a block already on the chain. | `kernel/notifier.c` |
| KNM1 | Both tables type KN2 and list `keyboard_notifier_list`; its `head` is null on both captures. | `linuxkernfacts -only g1types,keyboard` |

#### linux.tracing.check_tracepoints

Tags checked: v4.19, v6.1, v6.4, v6.14, v6.17 unless the row says otherwise.

| # | Fact | Source |
|---|---|---|
| TP1 | The linker script bounds the kernel's entries with `__start___tracepoints_ptrs` and `__stop___tracepoints_ptrs` (written directly at v4.19, through `BOUNDED_SECTION_BY` later); `for_each_kernel_tracepoint` walks `[__start, __stop)` one `tracepoint_ptr_t` at a time. The two symbols' addresses are the section's bounds; no type is involved. | `include/asm-generic/vmlinux.lds.h`, `kernel/tracepoint.c` |
| TP2 | `tracepoint_ptr_t` is `const int` with `CONFIG_HAVE_ARCH_PREL32_RELOCATIONS` and `struct tracepoint * const` without it. | `include/linux/tracepoint-defs.h` |
| TP3 | With the option, `__TRACEPOINT_ENTRY` emits `.long __tracepoint_<name> - .` and `tracepoint_ptr_deref` is `offset_to_ptr(p)`, which is `(unsigned long)p + *p`: a signed 32-bit offset from the entry's own address. Without it the entry is the pointer itself. | `include/linux/tracepoint.h`; `include/linux/compiler.h` |
| TP4 | `arch/x86/Kconfig` `config X86` selects `HAVE_ARCH_PREL32_RELOCATIONS` without condition. `struct module` has `tracepoint_ptr_t *tracepoints_ptrs` and `unsigned int num_tracepoints`, so a table that types the member also types the entry form. | `arch/x86/Kconfig`, `arch/Kconfig`, `include/linux/module.h` |
| TP5 | The section holds whole entries (`iter++` over `tracepoint_ptr_t`), so its size is a multiple of the entry width. | `kernel/tracepoint.c` |
| TP6 | A tracepoint's `name` is `#name` of an identifier that also names the symbol `__tracepoint_<name>`, so it is shorter than `KSYM_NAME_LEN` (128 at v4.19, 512 from v6.1). | `include/linux/tracepoint.h`, `include/linux/kallsyms.h` |
| TP7 | The module loader sets `mod->tracepoints_ptrs` from the module's `__tracepoints_ptrs` section with `sizeof(*mod->tracepoints_ptrs)` and counts `num_tracepoints`; `tracepoint_module_coming` walks `[ptrs, ptrs + num)` with the same deref. | `kernel/module.c` (v4.19), `kernel/module/main.c` (v6.1 to v6.17), `kernel/tracepoint.c` |
| TP8 | `struct tracepoint` has `const char *name`, the static key `key`, and `struct tracepoint_func *funcs`; `struct tracepoint_func` is `void *func`, `void *data`, `int prio`. | `include/linux/tracepoint-defs.h` |
| TP9 | `func_add` builds a new array with the probes in non-increasing priority (a new probe goes before the first of lower priority) and ends it with a null `func`; the kernel calls them in array order. From v6.1, a removed probe can stay as `tp_stub_func` until the array is rebuilt. | `kernel/tracepoint.c` (`tp_stub_func` from v6.1) |
| TP10 | `key` is `struct static_key` at v4.19, v6.1 and v6.4 and `struct static_key_false` (holding `struct static_key key`) at v6.14 and v6.17; `static_key.enabled` is an `atomic_t`. `tracepoint_add_func` enables the key when the first probe is added (`static_key_slow_inc` at v4.19, `static_key_enable` at v6.1 and v6.4, `static_branch_enable` at v6.14 and v6.17) and disables it when the last is removed. An enabled key goes with a non-null `funcs`. | `include/linux/tracepoint-defs.h`, `include/linux/jump_label.h`, `kernel/tracepoint.c` |
| TPM1 | The tables list both bounds with no type (`""`), type `tracepoint` (72 bytes; `name` 0x0, `key` 0x8 as `static_key_false`, `funcs` 0x38) and `tracepoint_func` (24 bytes), and type `module.tracepoints_ptrs` as a pointer to `int`. | `linuxkernfacts -only g1types` |
| TPM2 | Sections: mem3 4128 bytes (divisible by 4 and by 8), mem4 4788 bytes (divisible by 4, not by 8). Under the relative form every entry names a readable tracepoint (1032 of 1032, 1197 of 1197); under the pointer form none does (0 of 516 on mem3; mem4 has no whole pointer entries). | `linuxkernfacts -only tracepoints` |

#### linux.tracing.list_perf_events

Tags checked: v4.19, v6.1, v6.4, v6.14, v6.17 unless the row says otherwise.

| # | Fact | Source |
|---|---|---|
| PE1 | `task_struct.perf_event_list` (with `perf_event_mutex`) exists only with `CONFIG_PERF_EVENTS`. | `include/linux/sched.h` |
| PE2 | `perf_event_open` links each new event to the opening thread with `list_add_tail(&event->owner_entry, &current->perf_event_list)`; `perf_event_exit_task` unlinks them. The list is per thread. | `kernel/events/core.c` |
| PE3 | `struct perf_event` has `struct pmu *pmu`, `struct perf_event_attr attr`, `struct list_head owner_entry` and `struct bpf_prog *prog` (under `CONFIG_BPF_SYSCALL` at v4.19 to v6.4, unconditional at v6.14 and v6.17); `perf_event_attr` has `__u32 type` and `__u64 config`. | `include/linux/perf_event.h`, `include/uapi/linux/perf_event.h` |
| PE4 | `event->prog` is set when a program is attached: by `perf_event_attach_bpf_prog` for tracepoint, kprobe and uprobe events and by `perf_event_set_bpf_handler` for other events; it is cleared on detach. | `kernel/events/core.c`, `kernel/trace/bpf_trace.c` |
| PE5 | `perf_pmu_register` names each PMU (`"tracepoint"`, `"kprobe"`, `"uprobe"`, `"software"`, and at v6.17 `"cpu_clock"`, `"task_clock"`; v4.19 registers the two clocks with a null name) and creates its sysfs device with `dev_set_name(pmu->dev, "%s", pmu->name)`, so a named PMU's name is a sysfs entry name of at most `NAME_MAX` (255) bytes. | `kernel/events/core.c`; `include/uapi/linux/limits.h` |
| PE6 | `struct bpf_prog` has `tag[BPF_TAG_SIZE]` (8), `bpf_func` and `struct bpf_prog_aux *aux`; `bpf_prog_aux` has `u32 id` and `char name[BPF_OBJ_NAME_LEN]` (16), and from v6.1 `struct bpf_ksym ksym` with `char name[KSYM_NAME_LEN]`. | `include/linux/filter.h` (v4.19), `include/linux/bpf.h`, `include/uapi/linux/bpf.h` |
| PE7 | v4.19 `bpf_get_prog_name` builds the program's kernel symbol as `"bpf_prog_"`, the tag in lower-case hexadecimal, then `"_"` and `aux->name` when that is not empty. From v6.1 `bpf_prog_ksym_set_name` writes the symbol into `aux->ksym.name` with the same start, taking the BTF function name in place of `aux->name` when the program has one. | `kernel/bpf/core.c` |
| PEM1 | Both tables type every PE3 and PE6 member, including `bpf_ksym.name` as `char[512]`. | `linuxkernfacts -only g1types` |

### Kernel symbols, resources, VMCOREINFO and framebuffers

#### linux.kernel.list_symbols

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17 unless a row names fewer.

| # | Fact | Source |
|---|---|---|
| KS1 | `/proc/kallsyms` lists the core symbols, then the module, ftrace and BPF symbols, and does not show a symbol whose name is empty (`s_show` returns at `!iter->name[0]`). | S38 K11; `kernel/kallsyms.c` `s_show`, every tag |
| KS2 | `s_show` prints a module-side symbol's letter upper-case when the symbol is exported and lower-case when not; a core symbol's letter is printed as stored. | `kernel/kallsyms.c` `s_show`, every tag |
| KS3 | The kernel assigns a module symbol's letter in `elf_type`: `v` for a weak object and `w` for any other weak symbol; `U` undefined; `a` absolute or in the per-CPU section; `?` other reserved section indexes; `t` in an executable section; for an allocated section with file bytes `r` when not writable, `g` when small (`ARCH_SHF_SMALL`), else `d`; for a section without file bytes (`SHT_NOBITS`) `s` when small, else `b`; `n` in a `.debug` section; `?` otherwise. | `kernel/module.c` (v4.19), `kernel/module/kallsyms.c` (v6.1 to v6.17) `elf_type` |
| KS4 | The core image's letters come from the build's link map; `scripts/mksysmap` documents its letters as the same classes, lower-case for local symbols and upper-case for global ones (`a: local absolute symbols`, `N: debugging symbols`, `U: undefined global symbols`, `w: local weak symbols`). | `scripts/mksysmap`, v6.4, v6.14, v6.17 (the comment is absent at v4.19 and v6.1); `scripts/kallsyms.c` `read_symbol`, every tag |
| KS5 | The core tables are decoded by the project's kallsyms decoder from the seeds the VMCOREINFO note gives; the symbol size is the distance to the next address, as `kallsyms_lookup` measures it. | S38 K1 to K8; S05 |
| KS6 | Module, ftrace and BPF symbols, their letters, sizes and export state come from the S38 lister. | S38 4.5, 4.6, K11, B3 |
| KSM1 | On both captures every listed module, ftrace and BPF letter's case matches its export state as KS2 prints it, every letter has a KS3 class, and no core symbol has an empty name. | Section 9 |

#### linux.kernel.list_io_memory

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17.

| # | Fact | Source |
|---|---|---|
| IO1 | `struct resource` is `resource_size_t start; resource_size_t end; const char *name; unsigned long flags; unsigned long desc; struct resource *parent, *sibling, *child;`, identical at every tag. | `include/linux/ioport.h` |
| IO2 | `iomem_resource` is the root: `.name = "PCI mem"`, `.start = 0`, `.end = -1`, `.flags = IORESOURCE_MEM`. `/proc/iomem` is the `resource_op` sequence over it. | `kernel/resource.c` `iomem_resource`, `ioresources_init` |
| IO3 | The sequence starts at the root's `child` and steps with `next_resource`: the `child` when there is one, else the `sibling`, else up through `parent` to the first ancestor with a sibling. The root itself is not shown. This is a pre-order walk. | `kernel/resource.c` `r_start`, `r_next`, `next_resource` (v4.19 `next_resource(p, sibling_only)`; v6.4 on with a `subtree_root` argument the iterator passes as NULL) |
| IO4 | `r_show` indents a line by twice the number of `parent` steps to a direct child of the root, counting at most `MAX_IORES_LEVEL` (5). It prints `start` and `end` in hexadecimal with at least 4 digits when the root's `end` is below 0x10000 and at least 8 otherwise, and the name, or `<BAD>` when `name` is null. Without `CAP_SYS_ADMIN` the reader sees 0 for both bounds. | `kernel/resource.c` `r_show` |
| IO5 | `__request_resource` refuses a resource with `end < start` or outside the parent's `[start, end]`, inserts it before the first child whose `start` is above its `end`, refuses it when it overlaps a child, and sets `new->parent = root`. `__insert_resource` re-parents the children it takes over (`next->parent = new`). Siblings are therefore in ascending, non-overlapping order inside their parent, and each node's `parent` is the node it hangs under. | `kernel/resource.c` `__request_resource`, `__insert_resource` |
| IO6 | `IORESOURCE_BUSY` is 0x80000000 ("driver has marked this resource busy"). | `include/linux/ioport.h` |
| IOM1 | Both captures type `struct resource` with the IO1 members and hold `iomem_resource`; the tree holds none of the IO5 violations. | Section 9 |

#### linux.image.read_vmcoreinfo

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17.

| # | Fact | Source |
|---|---|---|
| VC1 | Note layout, line format, cut lines, value formats and damage are S05 K1 to K9. | S05 |
| VC2 | `vmcoreinfo_note` is allocated zeroed with `alloc_pages_exact` at boot, and `crash_save_vmcoreinfo` rewrites it at crash time with `CRASHTIME=` appended. | `kernel/crash_core.c` (v4.19 to v6.4), `kernel/vmcore_info.c` (v6.14, v6.17) |
| VC3 | `/sys/kernel/vmcoreinfo` prints `paddr_vmcoreinfo_note()`, the physical address of the note (`__pa(vmcoreinfo_note)` unless the architecture overrides it), and its size. The physical offset of a note in the capture is therefore the value an examiner can compare with that file. | `kernel/ksysfs.c` `vmcoreinfo_show`; `paddr_vmcoreinfo_note` in the files of VC2 |
| VCM1 | On both captures the note `vmcoreinfo_note` points to is one of the listed copies (section 9). | Section 9 |

#### linux.framebuffer.list

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17 unless a row names fewer.

| # | Fact | Source |
|---|---|---|
| FB1 | `struct fb_info *registered_fb[FB_MAX]` and `int num_registered_fb`, with `FB_MAX` 32. | `drivers/video/fbdev/core/fbmem.c`; `include/uapi/linux/fb.h` |
| FB2 | Registration takes the lowest free slot `i`, sets `fb_info->node = i`, increments `num_registered_fb` and stores `registered_fb[i] = fb_info`; unregistration clears `registered_fb[fb_info->node]` and decrements the count. Slots can therefore be free between used ones, and a used slot's `fb_info` has `node` equal to its index. | `fbmem.c` `do_register_framebuffer`, `do_unregister_framebuffer` |
| FB3 | `struct fb_info` holds `int node`, `struct fb_var_screeninfo var`, `struct fb_fix_screeninfo fix`, a union of `char __iomem *screen_base` and `char *screen_buffer`, `unsigned long screen_size`, `u32 state` (`FBINFO_STATE_RUNNING` 0, `FBINFO_STATE_SUSPENDED` 1) and `struct device *dev`, which is under `CONFIG_FB_DEVICE` at v6.14 and v6.17. | `include/linux/fb.h` |
| FB4 | `fb_var_screeninfo` has `xres`, `yres` (visible), `xres_virtual`, `yres_virtual`, `xoffset`, `yoffset` ("offset from virtual to visible resolution"), `bits_per_pixel`, `grayscale` (0 means colour, 1 means grey levels, above 1 a FOURCC code) and the `fb_bitfield`s `red`, `green`, `blue`, `transp`, each `offset` ("beginning of bitfield"), `length` and `msb_right`. `fb_fix_screeninfo` has `char id[16]`, `smem_start` (physical), `smem_len`, `type`, `visual` and `line_length` ("length of a line in bytes"). | `include/uapi/linux/fb.h` |
| FB5 | `FB_TYPE_PACKED_PIXELS` is 0. `FB_VISUAL_MONO01` 0, `MONO10` 1, `TRUECOLOR` 2, `PSEUDOCOLOR` 3, `DIRECTCOLOR` 4, `STATIC_PSEUDOCOLOR` 5, `FOURCC` 6. | `include/uapi/linux/fb.h` |
| FB6 | `v4l2_fourcc(a, b, c, d)` is `a | b << 8 | c << 16 | d << 24`; the big-endian variant sets bit 31. | `include/uapi/linux/videodev2.h`, v4.19, v6.17 |
| FB7 | `fb_read` serves `screen_size` bytes from `screen_base`, or `fix.smem_len` bytes when `screen_size` is 0, and refuses a null `screen_base`. | `fbmem.c` `fb_read` (v4.19 to v6.4); `fb_io_fops.c` `fb_io_read` (v6.14, v6.17) |
| FB8 | The device is created as `device_create(..., "fb%d", node)` and stored in `fb_info->dev`, or `NULL` when creation fails; without `CONFIG_FB_DEVICE` no device is made. | `fbmem.c` (v4.19 to v6.4), `fbsysfs.c` `fb_device_create` (v6.14, v6.17); `fb_internal.h` (v6.14, v6.17) |
| FBM1 | Neither capture's table types `registered_fb` or `num_registered_fb`; both type `fb_info` with the FB3 and FB4 members, `screen_base` included; mem4's has no `fb_info.dev`. | Section 9 |

### Network objects and socket scan

#### linux.network.check_operations

| # | Fact | Source |
|---|---|---|
| NO1 | `struct seq_operations` is `start`, `stop`, `next` and `show`, each a function pointer, in that order. | `include/linux/seq_file.h`, every tag. |
| NO2 | The `/proc/net` listings are created with `proc_create_net` or `proc_create_net_data`, which take the listing's `seq_operations`: `tcp` `tcp4_seq_ops`, `tcp6` `tcp6_seq_ops`, `udp` `udp_seq_ops` (also `udplite`), `udp6` `udp6_seq_ops` (also `udplite6`), `raw` `raw_seq_ops`, `raw6` `raw6_seq_ops`, `icmp` `ping_v4_seq_ops`, `icmp6` `ping_v6_seq_ops`, `unix` `unix_seq_ops`, `packet` `packet_seq_ops`, `netlink` `netlink_seq_ops`, `arp` `arp_seq_ops`. All twelve are registered so at every tag. | `net/ipv4/{tcp_ipv4,udp,udplite,raw,ping,arp}.c`, `net/ipv6/{tcp_ipv6,udp,udplite,raw,ping}.c`, `net/unix/af_unix.c`, `net/packet/af_packet.c`, `net/netlink/af_netlink.c`, every tag. |
| NO3 | Each of the twelve tables is a `const struct seq_operations` initialised with all four members, so none is null in a kernel that was not changed. `udp6_seq_ops` and `raw6_seq_ops` take `start`, `next` and `stop` from the IPv4 files (`udp_seq_start`, `raw_seq_start`); every other member is a function of the table's own protocol. | Same files, every tag. |
| NO4 | A `const` table sits in read-only data, outside `[_text, _etext)` (T7 of S54), so the S06 lookup, which names the kernel only for text, does not find it; a table in a module lies in one of the module's regions. | `arch/x86/kernel/vmlinux.lds.S`, every tag; S06 4.5. |
| NO5 | A function a table names is linked into the kernel image or the module that holds the table, or is exported by a module it depends on; a function pointer the compiler emits points at the function's first byte, where kallsyms names it. | NO3; `kernel/kallsyms.c`, every tag. |
| NOM1 | Both captures' tables list all twelve table symbols (untyped), and `seq_operations` with the four members at 0x0, 0x8, 0x10, 0x18, size 32. | `linuxkernfacts -only g3types`, 2026-11-12. |

#### linux.network.list_interfaces, linux.network.list_addresses

| # | Fact | Source |
|---|---|---|
| NI1 | The namespace, device and address facts are S40 N1 to N6, D1 to D11 and A1 to A6. | S40 section 3. |
| NI2 | The `/sys/class/net/<dev>/operstate` file names each state by its `IF_OPER_` name without the prefix, in lower case (`operstates[]`: `unknown`, `notpresent`, `down`, `lowerlayerdown`, `testing`, `dormant`, `up`). | `net/core/net-sysfs.c`, v4.19, v6.17. |
| NI3 | The tools write the S40 names with the kernel prefixes `IF_OPER_` and `IFF_` dropped and the case kept (`UP`, `UNKNOWN`), as S40 O4 records. Flags are those `dev_get_flags` reports (S40 D4), in bit order. | S40 4.2 steps 6 and 8, O4. |
| NI4 | A kernel built without IPv6 has no `inet6_ifaddr` type; `ip_ptr` and `ip6_ptr` are independent pointers, so the IPv4 list does not depend on the IPv6 one. | `include/linux/netdevice.h`, `include/net/if_inet6.h`, every tag. |

#### linux.network.list_hooks

| # | Fact | Source |
|---|---|---|
| NH1 | `struct net` holds `struct netns_nf nf`; `netns_nf` holds `struct nf_hook_entries __rcu *hooks_ipv4[NF_INET_NUMHOOKS]`, `hooks_ipv6[NF_INET_NUMHOOKS]`, `hooks_arp[NF_ARP_NUMHOOKS]` with `CONFIG_NETFILTER_FAMILY_ARP`, `hooks_bridge[NF_INET_NUMHOOKS]` with `CONFIG_NETFILTER_FAMILY_BRIDGE`, and at v4.19 only `hooks_decnet[NF_DN_NUMHOOKS]` with DECnet. | `include/net/netns/netfilter.h`, `include/net/net_namespace.h`, every tag (`hooks_decnet` at v4.19 only). |
| NH2 | `struct net_device` holds `struct nf_hook_entries __rcu *nf_hooks_ingress` (with `CONFIG_NETFILTER_INGRESS`) at every tag and `nf_hooks_egress` from v6.1. | `include/linux/netdevice.h`, every tag. |
| NH3 | `nf_hook_entry_head` gives the one chain head a registration goes to: `hooks_arp + hooknum`, `hooks_bridge + hooknum`, `hooks_ipv4 + hooknum`, `hooks_ipv6 + hooknum`, and for `NFPROTO_NETDEV` (and, from v6.1, `NFPROTO_INET` with `NF_INET_INGRESS`) the device's `nf_hooks_ingress` or `nf_hooks_egress`. `nf_register_net_hook` places an `NFPROTO_INET` registration other than ingress in both the IPv4 and the IPv6 chain. | `net/netfilter/core.c`, every tag (INET ingress and egress from v6.1). |
| NH4 | `struct nf_hook_entries { u16 num_hook_entries; struct nf_hook_entry hooks[]; }` is followed by `const struct nf_hook_ops *orig_ops[num_hook_entries]` (`nf_hook_entries_get_hook_ops` returns `&hooks[num]`). `allocate_hook_entries_size` returns null for 0 entries, and `nf_hook_entries_grow` refuses more than `MAX_HOOK_COUNT`, 1024. | `include/linux/netfilter.h`, `net/netfilter/core.c`, every tag. |
| NH5 | `struct nf_hook_entry { nf_hookfn *hook; void *priv; }`; `struct nf_hook_ops` has `hook`, `pf`, `hooknum` and `int priority`. `nf_hook_entries_grow` sets `hooks[n].hook = reg->hook` and `orig_ops[n] = reg`, and inserts in ascending priority. | Same, every tag. |
| NH6 | Hook numbers: `NF_INET_PRE_ROUTING` 0 to `NF_INET_POST_ROUTING` 4, `NF_INET_INGRESS` 5 (v6.1 onwards); `NF_ARP_IN` 0, `NF_ARP_OUT` 1, `NF_ARP_FORWARD` 2; `NF_BR_PRE_ROUTING` 0 to `NF_BR_POST_ROUTING` 4; `NF_DN_PRE_ROUTING` 0 to `NF_DN_ROUTE` 6; `NF_NETDEV_INGRESS` 0, `NF_NETDEV_EGRESS` 1 (v6.1 onwards). `NFPROTO_UNSPEC` 0, `INET` 1, `IPV4` 2, `ARP` 3, `NETDEV` 5, `BRIDGE` 7, `IPV6` 10, `DECNET` 12. | `include/uapi/linux/netfilter.h`, `netfilter_arp.h`, `netfilter_bridge.h`, `netfilter_decnet.h` (v4.19), every tag. |
| NH7 | Unregistering a hook does not shrink the chain at once: `nf_remove_net_hook` writes `hooks[i].hook = accept_all` and `orig_ops[i] = &dummy_ops`, a registration with `hook = accept_all` and priority `INT_MIN`. | `net/netfilter/core.c`, every tag. |
| NHM1 | Both tables type the NH1 arrays `hooks_ipv4` [5], `hooks_ipv6` [5], `hooks_arp` [3], `hooks_bridge` [5] (no `hooks_decnet`), `net_device.nf_hooks_ingress` and `nf_hooks_egress`, `nf_hook_entry` size 16, `nf_hook_entries.hooks` at 8, and `nf_hook_ops` (`hook`, `pf`, `hooknum`, `priority` at 0x20/0x38/0x3c/0x40 on mem3, 0x0/0x18/0x1c/0x20 on mem4). `accept_all` is listed, `dummy_ops` is not. | `linuxkernfacts -only g3types`. |

#### linux.socket.scan

| # | Fact | Source |
|---|---|---|
| SS1 | `sock_init_data` sets `sk_destruct = sock_def_destruct` for every sock; families then replace it: `inet_create` with `inet_sock_destruct`; `inet6_create` with `inet_sock_destruct` at v4.19 and `inet6_sock_destruct` from v6.1; `udp_init_sock` with `udp_destruct_sock` (the IPv6 UDP protocol uses `udp_init_sock` at v4.19); `udpv6_init_sock` with `udpv6_destruct_sock` from v6.1; `unix_create1` with `unix_sock_destructor`; `__netlink_create` with `netlink_sock_destruct`; `packet_create` with `packet_sock_destruct`. `sk_clone_lock` copies the parent's destructor into an accepted child. | `net/core/sock.c`, `net/ipv4/af_inet.c`, `net/ipv6/af_inet6.c`, `net/ipv4/udp.c`, `net/ipv6/udp.c`, `net/unix/af_unix.c`, `net/netlink/af_netlink.c`, `net/packet/af_packet.c`, every tag. |
| SS2 | `sk_alloc` sets `sk_family = family`, and a socket is made only for a family registered with `sock_register`, so `skc_family` is a family of S13 N1 and never `AF_UNSPEC`. | `net/core/sock.c`, `net/socket.c`, every tag; S13 N1. |
| SS3 | `sk_type` holds a bare `SOCK_*` value (S13 F9, N2). | S13. |
| SS4 | A pointer is 8 bytes with 8-byte alignment under LP64 (S54 L1); a structure is aligned to its widest member, and slab and kmalloc objects are aligned to at least `__alignof__(unsigned long long)` (`ARCH_KMALLOC_MINALIGN`, `ARCH_SLAB_MINALIGN`). A pointer member of a sock or a file therefore sits at an 8-byte-aligned address, and a direct-map page keeps that alignment in its physical address. | x86-64 psABI 3.1.2; `include/linux/slab.h`, every tag. |
| SS5 | `sock_graft` sets `sk->sk_socket = parent` and `parent->sk = sk`; `sock_orphan` sets `sk_socket` to null when the socket is released while the sock lives on (for example a closing TCP connection). | `include/net/sock.h`, every tag; S13 F3. |
| SS6 | A file is a socket's when `f_op == &socket_file_ops`, and then `private_data` is the `struct socket` (S13 F1, F2). | S13. |
| SSM1 | Both tables list all eight SS1 destructors and `socket_file_ops`; `sock.sk_destruct` is at 0x2d8 (mem3) and 0x2d0 (mem4), `sock.sk_socket` at 0x120, `socket.sk` at 0x18, `file.f_op` and `file.private_data` at 0x8/0x18 (mem3) and 0x10/0x20 (mem4). | `linuxkernfacts -only g3types`. |

### Mounts and open files

#### linux.mount.list

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17 unless a row names fewer.

| # | Fact | Source |
|---|---|---|
| MT1 | `mounts_open_common` takes the reader's namespace from `task->nsproxy->mnt_ns` and its root from `task->fs` (`get_fs_root`). A task with a null `nsproxy` or `mnt_ns` gives `EINVAL`, and one with a null `fs` gives `ENOENT`: such a task has no mount view. | `fs/proc_namespace.c` |
| MT2 | `exit_fs` sets `tsk->fs = NULL`; `exit_task_namespaces` leaves `nsproxy` null (S40 N4). An exiting task therefore has no view. | `fs/fs_struct.c`; `kernel/nsproxy.c` |
| MT3 | `show_mountinfo` prints, in order: `mnt_id`, the parent's `mnt_id`, `MAJOR:MINOR` of `sb->s_dev`; the mount's root (`s_op->show_path` when set, else the dentry path of `mnt_root`); the mount point by `seq_path_root`, which skips the whole line when the mount is not reachable from the reader's root (S39 N5, P3); `ro` or `rw` by `MNT_READONLY` and the mount options; the tags `shared:<mnt_group_id>`, `master:<master's mnt_group_id>`, `propagate_from:<id>` when the dominating id is non-zero and differs from the master's, and `unbindable`, in that order; ` - `; the type; the source (`s_op->show_devname` when set, else `mnt_devname`); `ro` or `rw` by `sb_rdonly` and the superblock options; then `s_op->show_options`. | `fs/proc_namespace.c` `show_mountinfo` |
| MT4 | The source is `mnt_devname ? mnt_devname : "none"` at v4.19, v6.1, v6.4 and v6.14. At v6.17 `show_mountinfo` prints `mnt_devname` alone and `alloc_vfsmnt` stores `"none"` when it is given no name, so the text is the same. | `fs/proc_namespace.c`; `fs/namespace.c` `alloc_vfsmnt`, v6.14, v6.17 |
| MT5 | `show_vfsmnt` (`/proc/<pid>/mounts`) prints the source, the mount point (same skip as MT3), the type, `ro` when `__mnt_is_readonly` (`MNT_READONLY` or `sb_rdonly`) else `rw`, the superblock options, the mount options, `s_op->show_options`, then ` 0 0`. The mount options are `show_mnt_opts` at v4.19 and `show_vfsmnt_opts` from v6.1, which adds `nosymfollow` and `idmapped`. | `fs/proc_namespace.c` `show_vfsmnt`; `fs/namespace.c` `__mnt_is_readonly` |
| MT6 | `mangle` escapes the source with `seq_escape` over `" \t\n\\"` at v4.19 and `" \t\n\\#"` from v6.1; the root and mount point are escaped over `" \t\n\\"`. | `fs/proc_namespace.c` |
| MT7 | `mnt_alloc_id` gives each mount an id unique among live mounts (an IDA at v4.19, an xarray from 1 to `INT_MAX` at v6.14 and v6.17), so a mount id is never shared by two live mounts in any namespace. | `fs/namespace.c` |
| MT8 | The propagation tests are `IS_MNT_SHARED`, `IS_MNT_SLAVE` (`mnt_master` not null) and `IS_MNT_UNBINDABLE`, read from `mnt_flags` to v6.14 and `mnt_t_flags` at v6.17 (S39 N4). The dominating id is S39 N6. | `fs/pnode.h` |
| MT9 | The per-filesystem operations of MT3 and MT5 (`show_path`, `show_devname`, `show_options`) and `security_sb_show_options` are code of the filesystem or security module. | `fs/proc_namespace.c` |
| MTM1 | Mounts, ids and views on the captures. | Section 9 |

#### linux.file.list_open

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17 unless a row names fewer.

| # | Fact | Source |
|---|---|---|
| FO1 | `proc_readfd_common` lists the descriptors of a task in increasing order from 0 below `max_fds`, one entry for each slot that holds a file, named by the number in decimal (`fcheck_files` at v4.19, `fget_task_next` at v6.17). | `fs/proc/fd.c` |
| FO2 | `/proc/<pid>/task/<tid>/fd` reads the thread's own `task->files`. `copy_files` shares the parent's `files_struct` when `CLONE_FILES` is set, so the threads of a process normally list the same table. | `fs/proc/fd.c`; `kernel/fork.c` `copy_files` |
| FO3 | `exit_files` sets `tsk->files = NULL`; such a task has no descriptors. | `fs/file.c` |
| FO4 | `generic_fillattr` reports `dev` as `inode->i_sb->s_dev`, `ino` as `i_ino`, `mode` as `i_mode`, `size` as `i_size_read(inode)`, and the access, modification and change times of the inode (S39 I1, I2). | `fs/stat.c` |
| FO5 | The link target and its pseudo names are S39 F4, P3, P4 and 4.5; the inode type and mode text S39 I3, I4; the device text S39 I5. | S39 |
| FOM1 | Rows, tables and losses on the captures. | Section 9 |

## 4. Algorithm

### Terminal, keyboard and tracing hooks

#### linux.tty.check

1. Walk `tty_drivers` over `tty_driver.tty_drivers`, forwards, with the S01 list walk (TT1).
2. For each driver read `name` (a string of at most the length of `tty_struct.name`, TT6), `num` and `ttys` (TT2). A null `ttys` means the driver keeps no table (TT3) and gives no rows.
3. Read the first `num` slots of `ttys`, at most `MaxTableEntries`. A null slot is an unused line (TT4).
4. A filled slot's tty is this driver's only when its `index` equals the slot number and its `driver` is the driver (TT4); otherwise the slot gives no row.
5. A tty with a null `ldisc`, or a discipline with null `ops`, has no receive path and gives no row. Otherwise read the tty's `name`, the discipline's `name`, and the handler members `receive_buf` and, where the table has it, `receive_buf2` (TT5, TT7).
6. Each set handler is one row. Its owner is the S06 lookup over the known modules, with the kernel image named by the table's exact symbols.
7. Rows are in driver-list order, then slot order, then `receive_buf` before `receive_buf2`.

#### linux.keyboard.list_notifiers

1. Read `keyboard_notifier_list.head` (KN1, KN2).
2. Follow `next` from `head` until it is null (KN3), stopping at a block seen before or after `MaxListEntries` blocks.
3. Each block gives one row, in chain order: the block's address, `notifier_call`, `priority` and the owner of `notifier_call` (S06 lookup).
4. A block whose priority is above its predecessor's is reported (KN4); its row is kept.

#### linux.tracing.check_tracepoints

1. **Kernel section.** The bounds are the addresses of `__start___tracepoints_ptrs` and `__stop___tracepoints_ptrs` (TP1). A stop below the start is an error; equal bounds give no kernel tracepoints. At most `MaxTableEntries` entries of the widest form are read.
2. **Entry form.** The candidates are the 32-bit relative form (TP3) and the pointer form, each only when its width divides the section's size (TP5). Each candidate is scored by the number of its entries that name a readable tracepoint: a non-null target whose `name` pointer is non-null and reads as a non-empty string within 512 bytes (TP6). The highest score wins. A tie goes to the form the table gives `module.tracepoints_ptrs` (TP4: `int` is relative, a pointer is the pointer form), and without that to the relative form x86 selects (TP4). A best score of 0 is `ErrNoEntryForm`.
3. **Decode.** A relative entry at address `a` holding the signed 32-bit `o` names `a + o` (modulo 2^64, then canonical); a pointer entry names its value (TP3).
4. **Module sections.** For each known module (S06 `Known`), when the table has both members, read `tracepoints_ptrs` and `num_tracepoints` (at most `MaxTableEntries`) and decode `num` entries in the kernel's form (TP7).
5. **Probes.** For each tracepoint read `name`, `funcs` and the key's `enabled` count (TP8, TP10). Walk the `tracepoint_func` array from `funcs` until a null `func`, at most `MaxListEntries` entries (TP9). Each entry gives `func`, `data` and `prio`, and the owner of `func`.
6. **Rows.** A tracepoint with probes gives one row per probe in array order; one without gives one row with no probe (open point TP-O1). Rows are in kernel-section order, then each known module in S06 order.
7. A key enabled with no probes, or disabled with probes, is reported (TP10).

#### linux.tracing.list_perf_events

1. Walk every task and thread (S01 task walk with threads).
2. For each, walk `perf_event_list` over `perf_event.owner_entry`, forwards (PE2).
3. An event with a null `prog` gives no row (PE4).
4. For an event with a program: the thread's `pid`, `tgid` and `comm`; `attr.type` and `attr.config`; the PMU's `name` (PE5, at most 256 bytes; a null PMU or name gives an empty value).
5. The program: `bpf_func`, `aux`, `aux->id`, `aux->name`; the symbol is `aux->ksym.name` when the table has `bpf_prog_aux.ksym` and the text is not empty, otherwise built from `tag` and `aux->name` as PE7 (v4.19) builds it.
6. Rows are in task-walk order, then event-list order.

### Kernel symbols, resources, VMCOREINFO and framebuffers

#### linux.kernel.list_symbols

1. Read the options (Inputs). With none set, select all four sources.
2. **Core.** Find the kernel through VMCOREINFO in physical memory and decode its kallsyms tables (S05, S38 KS5). One row per decoded symbol in table order, except those with an empty name (KS1), which are counted. The row's letter is the stored one and its class is KS3 by letter, the upper-case letters taking the class of their lower-case form, except `U` (KS4). The module is `kernel`, the subsystem `core`, and the export state unknown: a core letter's case gives the binding, not the export (KS2, KS4).
3. **Module, ftrace and BPF.** These need the session's symbol table and a Linux profile. Rows come from the S38 lister in that order (KS1, KS6), with the letter, size, module and export state it gives and the KS3 class of the letter. Addresses are given in canonical form.
4. The lister's failures are reported once per reason with their count.

#### linux.kernel.list_io_memory

1. Resolve `iomem_resource` and check that `struct resource` has the IO1 members the walk reads.
2. Read the root (IO2). Walk its descendants in pre-order (IO3): a node's children before its next sibling. The walk keeps its own path of ancestors rather than following `parent` back up, so a damaged `parent` cannot lead it elsewhere; the stored `parent` is compared with the path instead (IO5).
3. Each node gives one row: its address, depth (0 for a child of the root), `start`, `end`, `flags` and name. A null `name` is marked null (IO4); a name that does not read is marked unread.
4. A node that does not read ends its branch: its children and later siblings are not reached. A node reached twice ends its branch the same way.

#### linux.image.read_vmcoreinfo

1. Scan physical memory for VMCOREINFO notes with the S05 scan.
2. Each damaged copy is a diagnostic, or in strict mode the run's error.
3. For each table in offset order, one row per entry in table order: the note's offset, the key, the value text exactly as written, and whether the line was cut (VC1).

#### linux.framebuffer.list

1. With `dump` set, an output directory is required.
2. Resolve `registered_fb`; check the `fb_info` members of FB3 and FB4 (`dev` is optional).
3. Read the 32 slots (FB1). The table gives `registered_fb` no type (FBM1), so the length is `FB_MAX` from the header and each slot is a pointer wide. A null slot is free (FB2).
4. For each used slot read the `fb_info`: `node`, the geometry, the pixel fields, `fix.id`, `smem_start`, `smem_len`, `type`, `visual`, `line_length`, `screen_base`, `screen_size`, `state`. The screen size is `screen_size`, or `smem_len` when that is 0 (FB7).
5. The device name is `dev->kobj.name` when the table has `fb_info.dev`; a null `dev` is a known empty device; without the member the device is unknown (FB8).
6. Compare `num_registered_fb`, when present, with the number of used slots (FB2).
7. **Saving.** Read the screen memory at `screen_base` for the screen size, with pages that do not read as zeros. Save it as a PNG when the layout is packed true colour (`type` 0, `visual` 2, `grayscale` 0, `msb_right` 0 on every field, whole bytes per pixel): pixel (x, y) is the little-endian value of `bits_per_pixel / 8` bytes at `yoffset * line_length + xoffset * bytes + y * line_length + x * bytes`; each field is `length` bits from bit `offset`, scaled to 8 bits; a transparency field of length 0 is opaque (FB4). Otherwise save the raw bytes.
8. The file is named by S00 with kind `framebuffer`, scope `kernel`, the `fb_info` address and `fix.id` as label, extension `png` or `bin`, and created with `extract.CreateNew`, which never replaces a file.

### Network objects and socket scan

#### linux.network.check_operations

1. Read `seq_operations` from the table; its pointer members, in offset order, are the members checked (NO1). Without the type the tool fails.
2. Take the NO2 tables in the NO2 order; a table whose symbol the table does not list is named in one diagnostic and skipped. Without any, the tool fails.
3. Build the S06 views and keep `Known()`; report the views' losses (S06).
4. The table's owner is the module whose region holds the table's address, else the kernel image (NO4).
5. For each member read the pointer at the table address plus the member offset, in kernel memory. A read that fails gives a row with verdict **table does not read** and one diagnostic per table.
6. Judge the target, first match wins (NO3, NO5): null, **not set**; no owner from the S06 lookup, **outside the kernel and modules**; owned by a module that is neither the kernel image nor the table's owner, **in another module**; owned by a module whose symbols do not read, **module symbols do not read**; not exactly at a named symbol, **not at a function start**; otherwise **expected**.

#### linux.network.list_interfaces, linux.network.list_addresses

1. Walk the namespaces and each namespace's devices (S40 4.1, 4.2). Read each device with the S40 reader. A device that does not read, or whose current hardware address is absent, gives no row and a diagnostic (S40 7).
2. The operational state is the S40 T2 name without `IF_OPER_`, absent when the value has no name (NI2, NI3). The flags are the S40 reported flags without `IFF_`, joined by commas in bit order.
3. `list_interfaces` gives one row per device. `list_addresses` gives one row per address: the IPv4 walk, then the IPv6 walk (S40 4.3). Each walk is independent (NI4): a walk that ends early keeps its addresses and is a diagnostic, and a family whose types are missing is one diagnostic.

#### linux.network.list_hooks

1. Resolve `net.nf`, `nf_hook_entries.hooks`, the size of `nf_hook_entry`, and the members of NH5; any missing is `ErrNoHookTypes`. Each NH1 array the table types, with its declared length, and each NH2 device member that is a pointer, is a chain source; a family the kernel was built without has no member and is passed over.
2. Walk the namespaces (S40 4.1). For each namespace, for each array in NH1 order and each index, the head is `net + nf + member + index × pointer size`; then walk the namespace's devices (S40 4.2) and take ingress, then egress, of each device.
3. Read the head. Null means an empty chain. Otherwise read `num_hook_entries`; a value of 0 or above 1024 rejects the chain (NH4).
4. Entry `i` is at `hooks + i × sizeof(nf_hook_entry)`; its registration pointer at `hooks + num × sizeof(nf_hook_entry) + i × pointer size` (NH4). An entry that does not read ends the chain there.
5. Read the registration's `hook`, `pf`, `hooknum` and `priority`. Name the entry's function with the S06 lookup (name, or name+0x<offset>).
6. Check, first match wins: the registration does not read or is null, **registration does not read**; `hook` differs from the entry's function, **function differs from its registration** (NH5); the function is `accept_all`, **removed** (NH7); the registration's family and hook number would not have put it in this chain (NH3: same family and number, an `NFPROTO_INET` registration in the IPv4 or IPv6 chain of its number, or an INET ingress registration in a device ingress chain), **registered for another chain**; the function has no owner, **function outside the kernel and modules**; otherwise **consistent**.
7. Count chains whose priorities, over entries that are neither removed nor unread, are not ascending (NH5).

#### linux.socket.scan

1. Resolve the SS1 destructors and `socket_file_ops`; their running addresses are the needles. Name the ones missing in one diagnostic; with none, fail.
2. Read physical memory in windows and compare each pointer-aligned word with the needles (SS4).
3. **Destructor word** at physical `p`: the candidate sock is `p − offset(sk_destruct)`. Read `skc_family` and `sk_type` from physical memory. Keep the candidate only when the family is one the destructor is set on (`sock_def_destruct`: any N1 family but `AF_UNSPEC`) and the type is named by S13 N2 (SS1 to SS3); count each rejection by cause.
4. **Link.** Read `sk_socket` from physical memory: null is **no socket**; with no translator, **not translated**; else read `socket.sk` in kernel space and translate it: the candidate's own physical address is **socket points back**, another is **socket points elsewhere**, a failure is **socket does not read** (SS5).
5. **File word** at physical `p` (needs a translator): the file is `p − offset(f_op)`; `private_data` is the socket (SS6). Read `socket.sk` and that sock's `sk_socket` in kernel space; the sock is kept only when `sk_socket` is the socket, and then its translated address is a candidate with link **socket points back**. Count each file passed over by cause.
6. Merge candidates by physical address; `Found` holds both ways that found it. Decode each with the S13 decoder over physical memory; a sock whose family, type or protocol does not read is counted and gives no row.
7. Rows are in physical address order.

### Mounts and open files

#### linux.mount.list

1. Read the options; a value of the wrong type is an error.
2. Walk the thread-group leaders (S01), only those of the PID set when one is given.
3. **Views.** For each task in walk order read `fs` and `nsproxy`; when either is null the task has no view (MT1, MT2). Otherwise read `nsproxy.mnt_ns`; null means no view. Without a PID set, only the first task that holds a namespace reads it; with one, every selected task is a view of its own namespace.
4. **Filter.** The namespace number is `mnt_namespace.ns.inum` (S39 4.6 step 2). With `mntns` given, a view whose number reads and is not in the list is dropped; a view whose number does not read is kept and counted for one diagnostic.
5. **Root.** The reader's root is `TaskFSRoot` (S39 4.6 step 5).
6. **Mounts.** `MountPoints` of the namespace in its own order (S39 4.6 step 1).
7. **Line.** For each mount: `mnt_root` (null is an error for the mount); the mount point is the S39 4.3 walk from `(mount, mnt_root)` to the reader's root, and the mount is not shown unless the walk ends at the root (MT3); the root is the dentry path of `mnt_root` (S39 D4); the ids; the superblock (null is an error); the device (S39 I5); the mount options (S39 N5); the tags in MT3 order (MT8); the type (S39 I7); the source, `none` when `mnt_devname` is null or empty (MT4); the superblock options (S39 I7).
8. **Mounts form.** With `mount_format`, the row also carries the MT5 option text: `ro` when the mount or its superblock is read-only, else `rw`, then the superblock options, then the mount options.
9. Rows are in view order, then mount order.

#### linux.file.list_open

1. Read `files_only`; a value of the wrong type is an error.
2. Walk every thread (S01), only those of the PID set when one is given.
3. **Table.** `TaskFDs` (S39 4.1 step 1). No table gives no rows (FO3).
4. **Slots.** `OpenFiles` in slot order (FO1). Slots that do not read end the table: the files read before them are kept and the loss is counted.
5. **Identity.** The thread's tgid, pid and `comm`, read once for the table. A failure loses the table.
6. **Path.** The S39 4.4 shown path from the thread's own root (S39 O1). With `files_only` a pseudo file's path is empty (S39 O3). A path that is not built leaves the path empty, sets `PathUnresolved` and is counted.
7. **Inode.** `f_inode`; none means no stat facts (S39 4.1 step 3). Otherwise the FO4 facts: device from `i_sb` when it is set, the number, the type and mode text, the three times, the size. The facts are taken whole: a failed member read leaves every stat field empty and is counted.
8. Rows are in task-walk order, then slot order.

## 5. Validity rules

### Terminal, keyboard and tracing hooks

#### linux.tty.check

| Rule | Justification | On failure |
|---|---|---|
| A slot's tty has `index` = slot and `driver` = the driver | TT4 | No row; one diagnostic per driver with the count |
| `ttys` null means no table | TT3 | No rows, no diagnostic |
| At most `MaxTableEntries` slots | Section 8 | Diagnostic; lossy |
| Driver and tty names read within the 64 bytes of `tty_struct.name` | TT6 | Empty name, diagnostic |

#### linux.keyboard.list_notifiers

| Rule | Justification | On failure |
|---|---|---|
| Chain ends at null `next` | KN3 | Walk ends `revisited`, `capped` or `entry unreadable`; diagnostic; lossy |
| Priorities non-increasing | KN4 | Diagnostic; row kept |

#### linux.tracing.check_tracepoints

| Rule | Justification | On failure |
|---|---|---|
| A form's width divides the section size | TP5 | Form not a candidate |
| An entry names a tracepoint whose name reads, non-empty, within 512 bytes | TP6 | Entry not counted for the form; after the choice, a diagnostic with the count, and no row for it (lossy) |
| A probe array ends at a null `func` within `MaxListEntries` | TP9 | Diagnostic; lossy |
| Key enabled exactly when there are probes | TP10 | Diagnostic; rows kept |

#### linux.tracing.list_perf_events

| Rule | Justification | On failure |
|---|---|---|
| `bpf_prog.tag` is `BPF_TAG_SIZE` (8) bytes when the symbol is built | PE6 | Symbol empty; diagnostic; lossy |
| A PMU name reads within 256 bytes | PE5 | Empty PMU; diagnostic; lossy |

### Kernel symbols, resources, VMCOREINFO and framebuffers

#### linux.kernel.list_symbols

| Rule | Justification | On failure |
|---|---|---|
| A core symbol has a name | KS1 | Not listed; counted in a diagnostic |
| A core row's export state is unknown | KS2, KS4 | Not a failure |

#### linux.kernel.list_io_memory

| Rule | Justification | On failure |
|---|---|---|
| A node's `parent` is the node it is listed under | IO5 | Row kept; counted in a diagnostic |
| `start ≤ end`, inside the parent's range | IO5 | Row kept; counted |
| A sibling starts after the previous sibling's end | IO5 | Row kept; counted |
| A node is reached once | IO3: the tree has no cycles | Branch ends; diagnostic |

#### linux.image.read_vmcoreinfo

S05 section 5. A cut line is the kernel's own behaviour, so it is marked, not refused.

#### linux.framebuffer.list

| Rule | Justification | On failure |
|---|---|---|
| A used slot's `node` equals its index | FB2 | Row kept; diagnostic |
| `num_registered_fb` equals the used slots | FB2 | Diagnostic |
| A picture's fields lie inside the pixel, red, green and blue are not empty, the visible area fits the screen memory and `line_length` holds a row of pixels | FB4, FB7 | Raw bytes saved instead; diagnostic |

### Network objects and socket scan

#### linux.network.check_operations

| Rule | Justification | On failure |
|---|---|---|
| Target not null | NO3 | Verdict **not set** |
| Target owned by the kernel image or a listed module | NO5, S06 4.5 | **outside the kernel and modules** |
| A module target is in the table's own module | NO3, NO5 | **in another module** |
| Target at a named symbol, offset 0 | NO5 | **not at a function start** |

#### linux.network.list_interfaces, linux.network.list_addresses

S40 section 5, plus: a device whose current hardware address is absent is counted as not read (S40 7).

#### linux.network.list_hooks

| Rule | Justification | On failure |
|---|---|---|
| `num_hook_entries` is 1 to 1024 | NH4 | Chain rejected; diagnostic |
| Entry function equals the registration's `hook` | NH5 | **function differs from its registration** |
| A registration is in the chain `nf_hook_entry_head` gives it | NH3 | **registered for another chain** |
| Priorities ascend along a chain | NH5 | Counted in one diagnostic; rows kept |

#### linux.socket.scan

| Rule | Justification | On failure |
|---|---|---|
| Only aligned words are compared | SS4 | Not a candidate |
| Family is one the destructor is set on, never `AF_UNSPEC` | SS1, SS2 | Not a sock; counted per destructor |
| `sk_type` is a named `SOCK_*` value | SS3 | Not a sock; counted |
| A file's socket's sock points back at the socket | SS5, SS6 | File passed over; counted |

A sock whose socket does not point back is still a row: the link says what was found (SS5). The S13 decoder's rules apply to the decoded fields.

### Mounts and open files

#### linux.mount.list

| Rule | Justification | On failure |
|---|---|---|
| A task with null `fs`, `nsproxy` or `mnt_ns` has no view | MT1, MT2 | No rows from it; not an error |
| One view per namespace without a PID set | MT1: every holder walks the same mounts; MT7 | Later holders are not read |
| A mount is shown only when its mount point walk ends at the reader's root | MT3, S39 P3 | Not shown; not an error |
| `mnt_root` and `mnt_sb` are not null | MT3 (every live mount has both) | The mount is counted and not shown |
| The reader's root reads | S39 4.6 step 5 | The view is counted and gives no rows |

#### linux.file.list_open

| Rule | Justification | On failure |
|---|---|---|
| A null `files` has no descriptors | FO3 | No rows; not an error |
| Slots are listed in order, null slots skipped | FO1 | |
| Stat facts are whole or absent | FO4: one `stat` answers all of them | `InodeOK` false, counted |
| A device needs `i_sb` set | FO4 | A null `i_sb`: `DeviceOK` false, the other facts stand. An `i_sb` or device that does not read fails the stat facts as a whole (`InodeOK` false, counted) |

## 6. Failure modes

### Terminal, keyboard and tracing hooks

#### linux.tty.check

| Case | Result |
|---|---|
| `tty_drivers` missing | `ErrNoDrivers` (`ttycheck: tty_drivers not in the symbol table`) |
| A TT2 or TT5 member missing | The S54 member error, wrapped with the tool name |
| Driver list ends early | `linux.tty.check: tty_drivers at 0x<addr>: list ends <end> at 0x<addr> after <n> drivers` |
| `num` or `ttys` does not read | `linux.tty.check: tty_driver at 0x<addr>: tty table: <cause>` |
| Slots or their ttys do not read | `linux.tty.check: tty_driver at 0x<addr>: <n> of <num> slots or their ttys do not read` |
| Slots capped | `linux.tty.check: tty_driver at 0x<addr>: <num> slots, only the first <max> are read (Limits.MaxTableEntries)` |
| Module model or views fail | S06 diagnostics; owners empty |
| Strict mode | Any of the losses above, or lossy module views, fail the run |

#### linux.keyboard.list_notifiers

| Case | Result |
|---|---|
| `keyboard_notifier_list` missing | `ErrNoList` |
| `head` does not read | Error `linux.keyboard.list_notifiers: keyboard_notifier_list at 0x<addr>: head: <cause>` |
| Chain ends early | `linux.keyboard.list_notifiers: notifier_block at 0x<addr>: chain ends <end> after <n> blocks` |
| Priority out of order | `linux.keyboard.list_notifiers: notifier_block at 0x<addr>: priority <p> is above the <q> of the block before it` |
| Strict mode | A chain that ends early or lossy module views fail the run |

#### linux.tracing.check_tracepoints

| Case | Result |
|---|---|
| A bound symbol missing | `ErrNoTracepoints` |
| Stop below start | Error, `linuxtrace.ErrUnsupported` |
| Section does not read | Error naming the section |
| No form names any tracepoint | `ErrNoEntryForm` |
| Entries that do not name a tracepoint | `linux.tracing.check_tracepoints: __tracepoints_ptrs at 0x<addr>: <n> of <m> entries do not name a readable tracepoint` |
| A module section does not read | Diagnostic naming the module; lossy |
| Probe array capped or unreadable | Diagnostic naming the tracepoint and array; lossy |
| No `static_key.enabled` in the table | One diagnostic; `KeyEnabled` false on every row |
| Strict mode | Any loss fails the run |

#### linux.tracing.list_perf_events

| Case | Result |
|---|---|
| No `task_struct.perf_event_list` | `ErrNoPerfEvents` (PE1) |
| No `perf_event.prog` | No rows; one diagnostic (no program can be attached, PE3) |
| Task walk losses | S01 `TaskWalk.Report` diagnostics; lossy |
| An event list ends early | `linux.tracing.list_perf_events: task_struct at 0x<addr>: perf_event_list ends <end> at 0x<addr> after <n> events` |
| Event or program members do not read | Diagnostic naming the `perf_event` or `bpf_prog`; the row is kept with the fields read |
| Strict mode | Any loss fails the run |

### Kernel symbols, resources, VMCOREINFO and framebuffers

#### linux.kernel.list_symbols

| Case | Result |
|---|---|
| A value that is not a boolean for an option | Error naming the option (`tools.ErrOptionType`) |
| Core selected and no physical memory | `ErrNoPhysical` (`kernelsymbols: the session has no physical memory`) |
| No usable VMCOREINFO, or the decode fails | The `linuxkernel.FindKernel` or `kallsyms.Decode` error |
| A damaged VMCOREINFO copy | The search's diagnostic; in strict mode the damage error |
| Module, ftrace or BPF selected without a symbol table, memory or profile | Error naming `linux.kernel.list_symbols.core` as the way to list without one; a profile that is not Linux: `linux.kernel.list_symbols: profile os "<os>" is not linux` |
| A module, ftrace or BPF read fails | Diagnostic per reason with its count and first message; in strict mode an error |

#### linux.kernel.list_io_memory

| Case | Result |
|---|---|
| `iomem_resource` missing | `ErrNoRoot` |
| A `struct resource` member missing | `ErrUnsupported` naming the member |
| The root does not read | Error with its address |
| A node or its name does not read; a node reached twice; `MaxRecursionDepth` reached | Diagnostic `linux.kernel.list_io_memory: resource at 0x<addr>: <what failed>`; in strict mode the run fails |
| `MaxListEntries` rows listed | The walk stops; diagnostic `linux.kernel.list_io_memory: listing stops at Limits.MaxListEntries (<n>)`; in strict mode the run fails |

#### linux.image.read_vmcoreinfo

| Case | Result |
|---|---|
| No physical memory | `ErrNoPhysical` |
| Damaged copies | One diagnostic each (`linux.image.read_vmcoreinfo: autoload: skipped VMCOREINFO at 0x<off>: <reason>`, or `… skipped VMCOREINFO scan at 0x<off>: …` for a scan window); in strict mode `*autoload.VMCoreInfoDamageError` |
| Cut lines | One diagnostic per note with their count |
| No note at all | No rows, no error |

#### linux.framebuffer.list

| Case | Result |
|---|---|
| `dump` without `output_dir` | `ErrNoOutputDir` |
| `registered_fb` missing (fbdev absent or a module) | `ErrNoRegistry` |
| An `fb_info` member missing | `ErrUnsupported` naming it |
| A slot or `fb_info` does not read | Diagnostic `linux.framebuffer.list: fb_info at 0x<addr> (registered_fb[<i>]): <cause>`; in strict mode the run fails |
| No screen memory, size 0, over the dump limit, or no page reads | Diagnostic; not saved; row kept |
| Some pages do not read | Saved with zeros there; diagnostic with the missing byte count |
| File exists or cannot be written | Diagnostic; `File` empty |

### Network objects and socket scan

#### linux.network.check_operations

| Case | Result |
|---|---|
| No `seq_operations` type | `ErrNoOperationsType` |
| None of the twelve tables listed | `ErrNoTables` |
| Some tables not listed | One diagnostic naming them |
| Module model or views fail | Error `linux.network.check_operations: module model: …` |
| A table member does not read | Row verdict **table does not read**; `<tool>: <table> at 0x<addr>: <member> does not read: <cause>` |
| Strict mode | Any member that does not read, or module views read in part, is an error |

#### linux.network.list_interfaces, linux.network.list_addresses

| Case | Result |
|---|---|
| Profile is not Linux | Error |
| Namespace list missing, or a type gap in a device read | The S40 error, wrapped with the tool name |
| A list walk ends other than closed | `<tool>: net_namespace_list at 0x<addr>: walk ended <end> after <n> namespaces`, or `net at 0x<addr>: device list ended …` |
| A device does not read | `<tool>: net_device at 0x<addr>: does not read: <cause>`; no row |
| An address walk ends early | `<tool>: net_device at 0x<addr>: <family> address walk ended <end> at 0x<addr> after <n> addresses` |
| A family's types missing | `<tool>: <family> addresses are not listed: <cause>`, once |
| Unnamed operational state | Field absent; one diagnostic with the count |
| Strict mode | Any loss above but the missing family and unnamed states is an error |

#### linux.network.list_hooks

| Case | Result |
|---|---|
| A chain type missing | `ErrNoHookTypes` |
| An NH1 member that is not an array of pointers | `ErrNoHookTypes` |
| Module model or views fail | Error |
| Head, count, entry or registration does not read; count out of range; a list walk ends early | One diagnostic each, `<tool>: <object> at 0x<addr>: <what failed>` |
| Chains out of priority order; functions in more than one module | One diagnostic with the count |
| Strict mode | Any read loss or module views read in part is an error |

#### linux.socket.scan

| Case | Result |
|---|---|
| No physical memory | `ErrNoPhysicalMemory` |
| No needle symbol | `ErrNoNeedles` |
| A needed member missing | Error naming it |
| Kernel layer cannot translate | One diagnostic; links are **not translated** and the file route is not taken |
| Part of physical memory does not read | Diagnostic with the window counts; in strict mode an error |
| Rejected words, passed-over files, socks that do not decode | One diagnostic per kind with its count |
| Decoder losses | S13 6, through the decoder's report |

### Mounts and open files

#### linux.mount.list

| Case | Result |
|---|---|
| Profile not Linux | `mountlist.ErrNotLinux` |
| A type or member the readers need is missing | `linux.mount.list: <object> at 0x<addr>: <what>: <cause>`, an error of the tool (`linuxobj.TableGap` or `ErrUnsupported`) |
| `fs`, `nsproxy`, `mnt_ns`, `ns.inum`, the root, a mount's members or its walk do not read | Diagnostic `linux.mount.list: <object> at 0x<addr>: <what failed>: <cause>`; counted |
| A mount tree or list that ends early | Diagnostic `linux.mount.list: mnt_namespace at 0x<addr>: mounts: walk ends after <n> mounts at 0x<addr>: <end>`; counted, rows kept |
| `mntns` given and a namespace number does not read | One diagnostic with the count; those namespaces are listed unfiltered |
| Strict mode | Any count above 0 is an error: `linux.mount.list: strict mode: <n> mounts, namespaces or task roots read in part` |

#### linux.file.list_open

| Case | Result |
|---|---|
| Profile not Linux | `fileopen.ErrNotLinux` |
| A type or member the readers need is missing | An error of the tool, as above |
| A table, its slots or the thread's identity do not read | Diagnostic `linux.file.list_open: task_struct at 0x<addr>: descriptor table: <cause>` (or `fdtable at 0x<addr>: descriptor slots`, `task_struct ...: identity`); counted |
| A path is not built | Diagnostic `linux.file.list_open: file at 0x<addr>: path: <cause>`; `PathUnresolved`; counted |
| `f_inode` or the stat facts do not read | Diagnostic `linux.file.list_open: inode at 0x<addr>: stat facts: <cause>` (or `file at 0x<addr>: f_inode: <cause>`); counted |
| Strict mode | Any count above 0 is an error naming the three counts |

## 7. Result schema

### Terminal, keyboard and tracing hooks

#### linux.tty.check

`ttycheck.Row`, masked addresses (S54 4.1):

| Field | Type | Meaning |
|---|---|---|
| `TTY` | string | `tty_struct.name` |
| `TTYAddress` | uint64 | `struct tty_struct` |
| `Driver`, `DriverAddress` | string, uint64 | `tty_driver.name`, the driver |
| `Discipline`, `OpsAddress` | string, uint64 | `tty_ldisc_ops.name`, the ops |
| `Handler` | `Handler` | `receive_buf` or `receive_buf2` |
| `Address` | uint64 | The handler |
| `Module`, `Symbol` | string | S06 `Owner.Names()`; empty when no owner is found |
| `ModuleAddress`, `ModuleFound` | uint64, bool | `struct module` of the owner (0 for the kernel); whether an owner was found |

#### linux.keyboard.list_notifiers

`keyboardnotifiers.Row`, masked addresses: `BlockAddress`, `Address` (`notifier_call`), `Priority` (int64), `Module`, `Symbol`, `ModuleAddress`, `ModuleFound`, as above.

#### linux.tracing.check_tracepoints

`tracingtracepoints.Probe`, canonical addresses:

| Field | Type | Meaning |
|---|---|---|
| `Tracepoint`, `TracepointAddress` | string, uint64 | `tracepoint.name`, the tracepoint |
| `TracepointOwner` | string | `kernel` or the module whose section holds it |
| `KeyEnabled` | bool | `key.enabled` non-zero |
| `Probes` | int | Probes in the array (0 on a row with no probe) |
| `ProbeAddress`, `ProbeSymbol` | uint64, string | `func` and its owner's symbol; 0 and empty when no probe |
| `DataAddress`, `Priority` | uint64, int64 | `data`, `prio` |
| `Module`, `ModuleAddress`, `ModuleFound` | | Owner of `func` |

#### linux.tracing.list_perf_events

`tracingperf.Event`, canonical addresses: `PID` (`tgid`), `TID` (`pid`), `Process` (`comm`), `EventAddress`, `PMU`, `Type`, `Config`, `ProgramAddress`, `ProgramID`, `ProgramName` (`aux->name`), `ProgramSymbol` (PE7), `ProgramCode` (`bpf_func`).

### Kernel symbols, resources, VMCOREINFO and framebuffers

#### linux.kernel.list_symbols

`kernelsymbols.Row`, in KS1 order:

| Field | Type | Meaning |
|---|---|---|
| `Address` | uint64 | The symbol's address; listed symbols in canonical form |
| `Name`, `NameUnknown` | string, bool | The name; unknown when the lister could not read it |
| `Type` | string | The letter; empty when not known |
| `Description` | string | The KS3 class of the letter; empty for a letter with no class |
| `Size` | int64 | Bytes (KS5, KS6); 0 or less when not established |
| `Subsystem` | string | `core`, `module`, `ftrace` or `bpf` |
| `Module`, `ModuleUnknown` | string, bool | `kernel`, a module name, `__builtin__ftrace` or `bpf` |
| `Exported`, `ExportedUnknown` | bool, bool | KS2; unknown for every core row |

Also exported: `CoreRows(kallsyms.Table)` (step 2) and `Describe(letter)` (the KS3 class).

#### linux.kernel.list_io_memory

`kerneliomemory.Row`, in pre-order: `Address` (the `struct resource`, canonical), `Depth` (0 for a child of the root, not capped), `Start`, `End` (physical, inclusive), `Flags` (as stored), `Name`, `NameState` (`read`, `null`, `unread`).

#### linux.image.read_vmcoreinfo

`imagevmcoreinfo.Row`: `Offset` (physical offset of the note header, VC3), `Key`, `Value` (the text after `=` as the kernel wrote it), `Cut` (the line was cut, S05 K4, K5). Notes in offset order, entries in table order.

#### linux.framebuffer.list

`framebufferlist.Framebuffer`, in slot order:

| Field | Type | Meaning |
|---|---|---|
| `Slot` | int | Index in `registered_fb` |
| `Address` | uint64 | The `fb_info`, canonical |
| `Node` | int64 | `node` |
| `Device`, `DeviceKnown` | string, bool | FB8 and step 5 |
| `ID` | string | `fix.id` |
| `ScreenAddress` | uint64 | `screen_base`, canonical; 0 when null |
| `ScreenSize` | uint64 | Bytes, FB7 |
| `PhysicalStart` | uint64 | `fix.smem_start` |
| `XRes`, `YRes`, `VirtualXRes`, `VirtualYRes` | uint64 | Pixels, FB4 |
| `BitsPerPixel`, `LineLength` | uint64 | FB4; `LineLength` in bytes |
| `Visual` | string | FB5 name in lower case without the prefix, or `visual=<n>` |
| `FourCC` | string | When `grayscale` is above 1: four characters (FB6), ` be` added for bit 31, or `0x<8 hex digits>` when a byte is not printable |
| `State` | string | `running`, `suspended` or `state=<n>` |
| `File` | string | The saved file's name; empty when not saved |

Also exported: `Layout` and `Picture` (step 7), `VisualName`, `StateName`, `FourCCText`, and the sentinels `ErrNoRegistry`, `ErrUnsupported`, `ErrNoOutputDir`, `ErrNotTrueColor`, `ErrOutside`, `ErrTooLarge`.

### Network objects and socket scan

#### linux.network.check_operations

`Handler`, one row per table member, tables in NO2 order and members in offset order:

| Field | Type | Meaning |
|---|---|---|
| `Table` | string | Table symbol |
| `TableAddress` | uint | Its address, masked |
| `ProcFile` | string | `/proc/net/<name>` (NO2) |
| `TableModule` | string | Owner of the table: a module name or `kernel` (NO4) |
| `Member` | string | `start`, `stop`, `next` or `show` |
| `TargetAddress` | uint | The pointer, masked; 0 when the table does not read |
| `Module`, `Symbol` | string | Owner of the target (`kernel` for the image) and its symbol (`name` or `name+0x<n>`); empty when none |
| `Verdict` | `Verdict` | `expected`, `not set`, `outside the kernel and modules`, `in another module`, `module symbols do not read`, `not at a function start`, `table does not read` |

#### linux.network.list_interfaces

`Link`: `NetNS` (uint), `NetNSKnown` (bool), `Index` (int), `Interface` (string), `HardwareAddress` (string, S40 D10), `OperState` (text, NI3), `MTU` (uint), `Qdisc` (text, S40 4.2 step 5: present and empty for no queueing discipline), `TxQueueLength` (uint), `Flags` (string, NI3). Rows in namespace, then device list order.

#### linux.network.list_addresses

`Addr`: `NetNS`, `NetNSKnown`, `Index`, `Interface`, `HardwareAddress`, `Promiscuous` (bool, S40 4.2 step 7), `OperState`, `Family` (`IPv4` or `IPv6`), `Address` (S40 A6 text), `PrefixLength` (uint), `Scope` (S40 A5 words). Rows per device: IPv4 then IPv6, each in walk order.

#### linux.network.list_hooks

`Hook`, rows in namespace order, then array, hook number and entry order, then devices:

| Field | Type | Meaning |
|---|---|---|
| `NetNS`, `NetNSKnown` | uint, bool | Namespace number (S40 N3) |
| `Protocol` | string | Chain family, `NFPROTO_*` (NH6) |
| `Hook` | string | Chain hook, `NF_*` (NH6), or `hook <n>` past the name table |
| `Device` | string | Device name for an ingress or egress chain; empty otherwise |
| `Index` | int | Entry index in the chain |
| `Priority` | int | Registration priority; 0 when it does not read |
| `FunctionAddress` | uint | `hooks[i].hook`, masked |
| `Module`, `Symbol` | text | Owner and symbol; absent when none |
| `OpsAddress` | uint | `orig_ops[i]`, masked |
| `Registered` | string | Registration family `NFPROTO_*`, or `NFPROTO <n>` |
| `Check` | `Check` | Section 4 step 6 values |

#### linux.socket.scan

`Socket`: `SockPhysical` (uint, the sock's physical address), `Found` (`FoundBy` bits: `FoundByDestructor` 1, `FoundByFile` 2), `Link` (`socket points back`, `no socket`, `socket points elsewhere`, `socket does not read`, `not translated`), `SocketAddress` (uint, `sk_socket` masked, 0 when null), and the S13 `Decoded` fields (`Family` to `Coverage`). Rows in physical address order.

### Mounts and open files

#### linux.mount.list

`mountlist.Mount`, one row per shown mount:

| Field | Type | Meaning |
|---|---|---|
| `MntNsID`, `MntNsIDOK` | uint64, bool | The namespace number and whether it read |
| `PID`, `PIDShown` | int64, bool | The reading task's pid, given only with a PID set |
| `MountAddress` | uint64 | The `struct mount`, canonical (new) |
| `MountID`, `ParentID` | int64 | `mnt_id` and the parent's |
| `MajorMinor` | string | `<major>:<minor>` of `s_dev` |
| `Root`, `MountPoint` | string | MT3, unescaped (MT6) |
| `MountOptions` | string | `ro`/`rw` and the mount options, comma-separated |
| `Fields` | string | The tags, space-separated; empty when there are none |
| `FSType`, `FSTypeOK` | string, bool | `s_type->name[.s_subtype]` and whether `s_type` is set |
| `MountSource` | string | MT4 |
| `SBOptions` | string | `ro`/`rw` and the superblock options |
| `MountFormat` | bool | `mount_format` was given |
| `MntOpts` | string | The MT5 option text with `mount_format`; empty otherwise |

#### linux.file.list_open

`fileopen.File`, one row per thread and open descriptor:

| Field | Type | Meaning |
|---|---|---|
| `PID`, `TID`, `Process` | int64, int64, string | tgid, pid, `comm` |
| `FD` | uint64 | The descriptor number |
| `FileAddress` | uint64 | The `struct file`, canonical (new) |
| `Path`, `PathUnresolved` | string, bool | The shown path (4 step 6); `PathUnresolved` when it was not built (new) |
| `Device`, `DeviceOK` | string, bool | `<major>:<minor>` of `i_sb->s_dev` |
| `InodeOK` | bool | The stat facts were read |
| `Inode`, `Type`, `TypeOK`, `Mode`, `Size` | | S39 4.1 steps 5 and 6, FO4 |
| `Changed`, `Modified`, `Accessed` and their `…OK` | `time.Time` UTC, bool | S39 4.1 step 6 |

## 8. Limits

### Terminal, keyboard and tracing hooks

- `MaxListEntries`: the driver list, the keyboard chain, each tracepoint's probe array, the task walk and each event list. A kernel-written chain or array is far shorter (section 9); the cap is what ends a corrupt one.
- `MaxTableEntries`: slots read per tty driver (the `pts`/`ptm` drivers declare 1,048,576 lines but keep no table, TT3), and entries per tracepoint section. A section's length comes from two symbol addresses, not from memory, so a wrong bound would otherwise read without end.
- String bounds come from the sources: 64 bytes for driver and discipline names (TT6), 512 for tracepoint names (TP6), 256 for PMU names (PE5).

### Kernel symbols, resources, VMCOREINFO and framebuffers

#### linux.kernel.list_symbols

The S05 search, the decoder and the S38 lister apply their own Limits; this tool adds none.

#### linux.kernel.list_io_memory

- `MaxListEntries`: rows. The tree has no list head to come back to, so the cap and the revisit check end a corrupt one.
- `MaxRecursionDepth`: depth below the root; deeper children are not listed and a diagnostic says so. The captures' trees are 2 levels deep (section 9).
- `MaxNameBytes`: each name.

#### linux.image.read_vmcoreinfo

S05 section 8.

#### linux.framebuffer.list

- `FB_MAX` (32) slots: the kernel's own bound.
- `DumpLimit` (`max_dump_size`, else `MaxArtifactBytes`): screen memory read for one framebuffer.
- `MaxImageBytes`: 4 bytes per pixel of the picture; and at most 65536 pixels on a side.
- `MaxNameBytes`: the device name.

### Network objects and socket scan

#### linux.network.check_operations

No cap: twelve tables of four members.

#### linux.network.list_interfaces, linux.network.list_addresses

S40 section 8.

#### linux.network.list_hooks

`MaxListEntries` bounds the namespace and device walks (S01). A chain is bounded by the kernel's own 1024 (NH4), not by a Limits field.

#### linux.socket.scan

The scan reads physical memory once in 1 MiB windows. The candidates are bounded by the memory size; no Limits field applies, since a word is either a needle or not.

### Mounts and open files

- `linux.mount.list`: `MaxListEntries` bounds the task walk and each namespace's mount walk; `MaxPathSteps` and `MaxNameBytes` bound each mount point walk and root path (S39 section 8).
- `linux.file.list_open`: `MaxTableEntries` bounds each descriptor table (S39 F2); the path limits as above.

## 9. Acceptance

All figures below were measured with `linuxkernfacts` on 2026-11-12 on `E:\dataset\memory\mem3_ubuntu24.mem` (kernel 6.17) and `mem4_fedora40.mem` (kernel 6.14). Each group's fixtures live in the tool package's own tests.

### Terminal, keyboard and tracing hooks

#### Synthetic fixtures and fuzz targets

- `tools/linux/ttycheck/tty_test.go`: rows per handler in slot order with kernel and module owners; a driver with no table; a table without `receive_buf2`; slots whose index or driver disagree; unreadable slots and strict mode; the `MaxTableEntries` cap; a broken driver list; no `tty_drivers`. Fuzz `FuzzDriverTable` (arbitrary `num`, slot words, index and handler; rows never exceed two per slot read).
- `tools/linux/keyboardnotifiers/notifiers_test.go`: empty chain; chain in order with kernel, module and unowned callbacks; priority out of order; a cycle and strict mode; the `MaxListEntries` cap; no list. Fuzz `FuzzWalkChain` (an arbitrary chain always ends, never lists a block twice and never exceeds the cap).
- `tools/linux/tracingtracepoints/tracepoints_test.go`: a tracepoint without probes, one with kernel and module probes, a module's own section; pointer-form entries chosen when only they resolve; key disagreement; probe-array cap and strict mode; missing bounds and `ErrNoEntryForm`; every `chooseForm` tie and exclusion case. Fuzz `FuzzDecodeEntries` (entry count is size over width; a relative entry is its own address plus its sign-extended offset).
- `tools/linux/tracingperf/events_test.go`: events with programs per thread, an event without one, a `ksym` name and a built name; a kernel without `perf_event.prog`; an unreadable program and strict mode; no `perf_event_list`. Fuzz `FuzzProgramSymbol` (PE7 form for any tag and name).

Each fuzz target ran 30 s without a failure on 2026-11-12.

#### Measurements

`linuxkernfacts -only g1types,tty,keyboard,tracepoints,perf`, 2026-11-12:

| | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| tty drivers on `tty_drivers` | 7, list closed (`ttyDBC`, `ttyprintk`, `ttyMAX`, `ttyS`, `pts`, `ptm`, `tty`) | 6, closed (`ttyUSB`, `ttyDBC`, `ttyS`, `pts`, `ptm`, `tty`) |
| Drivers with no table | 2 (`pts`, `ptm`: flags 0x5f has `TTY_DRIVER_DEVPTS_MEM`, `num` 1,048,576) | 2 (the same) |
| Slots read, filled | 192, 2 | 671, 2 |
| Filled slots whose `index` and `driver` agree (TT4) | 2 of 2 | 2 of 2 |
| Filled slots with no discipline | 0 | 0 |
| Disciplines; with `receive_buf2` | `n_tty` × 2; 2 | `n_tty` × 2; 2 |
| Longest driver name | 9 bytes | 6 bytes |
| `linux.tty.check` rows | 4: `tty2`, `tty6` × (`receive_buf` `n_tty_receive_buf`, `receive_buf2` `n_tty_receive_buf2`), all `kernel`; no diagnostics | 4, the same |
| `keyboard_notifier_list.head` | null | null |
| `linux.keyboard.list_notifiers` rows | 0, no diagnostics | 0, no diagnostics |
| `__tracepoints_ptrs` | 4128 bytes; relative 1032 of 1032 resolve, pointer 0 of 516 | 4788 bytes; relative 1197 of 1197; pointer not a candidate (4788 mod 8 = 4) |
| Form chosen | relative (also the table's type of `module.tracepoints_ptrs`, `int *`) | relative |
| Kernel tracepoints with `funcs` set; with the key enabled | 0; 0 | 0; 0 |
| Known modules; with tracepoints; their tracepoints | 63; 4; 32 (`hv_vmbus` 22, `hv_netvsc` 5, `qrtr` 4, `hv_balloon` 1) | 61; 6; 170 (`sunrpc` 136, `hv_vmbus` 22, `hv_netvsc` 5, `qrtr` 4, `fuse` 2, `hv_balloon` 1) |
| Longest tracepoint name | 40 bytes | 40 bytes |
| `linux.tracing.check_tracepoints` rows | 1064 (1032 kernel + 32 module), all without a probe; no diagnostics | 1367 (1197 + 170), all without a probe; no diagnostics |
| Tasks walked (threads) | 557 | 573 |
| Threads with a non-empty `perf_event_list`; events | 0; 0 | 0; 0 |
| `linux.tracing.list_perf_events` rows | 0, no diagnostics | 0; 3 S01 task-walk diagnostics (one `init_task.tasks` link that does not lead back, the same break every task-walking tool reports on mem4) |

Before this specification `linux.tracing.check_tracepoints` stopped on both captures because the table gives the bound symbols no type (S59 O5); it now needs only their addresses. No tracepoint on either capture has a probe and no key is enabled, which agrees with TP10; the probe, priority, stub and key-disagreement paths are covered by fixtures only. No capture has a keyboard notifier or a perf event, so those row paths are fixtures only as well.

### Kernel symbols, resources, VMCOREINFO and framebuffers

#### linux.kernel.list_symbols

- Fixtures (`tools/linux/kernelsymbols/listing_test.go`, with `symbols/linuxkernel/linuxtest` and `tools/linuxobj/linuxobjtest`): every source in KS1 order; each option set; option type errors; no symbol table (core alone works, the others name the core option); no physical memory; unnamed core symbols left out; letter classes.
- Fuzz: `FuzzCoreRows` (arbitrary symbol tables: rows keep order, never an empty name), `FuzzDescribe`.
- Measured with `linuxkernfacts -only symbols`, 2026-11-12:

| Figure | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| Rows, all sources | 239419 | 275758 |
| Core; module; ftrace; BPF | 223671; 15729; 0; 19 | 256744; 18924; 58; 32 |
| Order of subsystems | core, module, bpf; no subsystem resumes | core, module, ftrace, bpf; none resumes |
| Core symbols with an empty name | 0 | 0 |
| Core letters | `t` 102365, `T` 76004, `d` 21077, `r` 17871, `b` 3682, `D` 1372, `B` 861, `W` 372, `R` 66, `V` 1 | `t` 102777, `T` 80016, `d` 47775, `r` 16960, `b` 3681, `B` 3480, `D` 1201, `A` 414, `W` 366, `R` 73, `V` 1 |
| Module letters | `t` 9529, `r` 4223, `d` 1513, `b` 235, `T` 220, `B` 4, `R` 2, `a` 2, `D` 1 | `t` 10864, `r` 4684, `d` 2902, `b` 296, `T` 170, `B` 4, `R` 2, `a` 2 |
| Letters without a KS3 class; rows without a letter | 0; 0 | 0; 0 |
| Listed symbols upper-case and exported; lower-case and not exported; other (KS2) | 227; 15521; 0 | 234; 18780; 0 |
| Rows with size 0 or less | 2858 | 2734 |
| Core alone / modules alone / ftrace and BPF | 223671 / 15729 / 19 rows, no failures | 256744 / 18924 / 90, no failures |

The core and module counts are those S38 measured; every listed letter's case follows KS2.

#### linux.kernel.list_io_memory

- Fixtures (`resources_test.go`, `tools/linuxkern/kerntest`): pre-order with depths and a null name; a wrong parent, a range outside the parent and overlapping siblings counted with rows kept; an unreadable node ending its branch, and strict mode; a cycle; `MaxListEntries` and `MaxRecursionDepth`; an unreadable name; the root symbol, the type and an unreadable root required.
- Fuzz: `FuzzResourceTree` (arbitrary bytes with child and sibling links: the walk ends, respects the cap and lists no node twice).
- Measured with `linuxkernfacts -only iomem`:

| Figure | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|
| Rows; at depth 0; at depth 1; deeper | 19; 14; 5; 0 | 19; 14; 5; 0 |
| Names read; null; unread | 19; 0; 0 | 19; 0; 0 |
| Wrong parent; outside the parent; overlapping or out-of-order siblings (IO5) | 0; 0; 0 | 0; 0; 0 |
| Rows with `IORESOURCE_BUSY` | 15 | 15 |
| Highest end at depth 0 | 0xfee00fff | 0xfee00fff |
| Top level | `Reserved`, `System RAM`, `Reserved`, `System RAM` (from 0x100000), ..., `ACPI Tables`, `ACPI Non-volatile Storage`, `System RAM` to 0x7fffffff, and devices up to the local APIC page | the same shape |

#### linux.image.read_vmcoreinfo

- Fixtures (`notes_test.go`): two notes listed in offset order with the kernel's text; a line cut at 79 bytes marked with one diagnostic; a damaged copy beside a good one, and strict mode's `*autoload.VMCoreInfoDamageError`; no physical memory.
- Fuzz: `FuzzNotes` (arbitrary images: each note's rows open with `OSRELEASE` and lie inside the image).
- Measured with `linuxkernfacts -only vmcoreinfo`:

| Figure | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|
| Notes (offset: entries) | 0x1a4c000: 107; 0x6067100: 107; 0x67eb05f: 107 | 0x1304000: 106 |
| Rows; cut lines; damaged copies | 321; 0; 0 | 106; 0; 0 |
| `OSRELEASE` | `6.17.0-35-generic` in each | `6.14.5-100.fc40.x86_64` |
| Notes with `CRASHTIME` (VC2) | 0 | 0 |
| `vmcoreinfo_note` translated to physical (VC3); listed | 0x1a4c000; yes | 0x1304000; yes |

#### linux.framebuffer.list

- Fixtures (`registry_test.go`): two framebuffers in slots 0 and 2 (true colour with a device, FOURCC suspended with a null device and a node that disagrees with its slot); no `dev` member; the count check; saving a PNG with exact pixel values and a raw FOURCC file, and a second run that does not replace them; no output directory; an unreadable `fb_info` and strict mode; registry and type required; names and codes; `Picture` refusals and a 16-bit 5-6-5 layout.
- Fuzz: `FuzzPicture` (arbitrary bytes and layouts: no panic, and an image has the asked size).
- Measured with `linuxkernfacts -only framebuffer -framebuffer-dir <dir>`:

| Figure | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|
| `registered_fb`, `num_registered_fb` typed in the table | no, no | no, no |
| `fb_info.dev` in the table | yes | no |
| Rows; slot and node | 1; 0 and 0 | 1; 0 and 0 |
| `num_registered_fb` against used slots | equal | equal |
| `ID`; device | `hyperv_drmdrmfb`; `fb0` | `hyperv_drmdrmfb`; unknown |
| Geometry | 1024x768 visible and virtual, 32 bits, line 4096 bytes, offsets 0,0 | the same |
| Fields red/green/blue/transp (offset/length) | 16/8, 8/8, 0/8, 0/0; `msb_right` 0 | the same |
| `type`, `visual`, `grayscale`, state | 0, truecolor, 0, running | the same |
| Screen size; `smem_start` | 3145728 (4096 x 768); 0 | 3145728; 0 |
| Saved | PNG of 14983 bytes, every page read; it shows the distribution's boot splash with its release name | PNG of 16416 bytes, every page read; it shows a text console with a boot message |

### Network objects and socket scan

#### linux.network.check_operations

- Fixtures (`tools/linux/networkoperations/operations_test.go`): a kernel table with every member expected, rows in offset order with the `/proc/net` name and the missing tables in a diagnostic; a table with a null, a module, a mid-function and an unowned target; a table in a module whose functions are its own and the kernel's; a table that does not read, and strict mode; no tables and no type.
- No fuzz target: the tool parses no bytes; its reads are S46's and its lookup S06's.

| | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| Tables listed | 12 of 12, all in the kernel image | 12 of 12, all in the kernel image |
| Rows | 48 | 48 |
| Verdicts | 48 `expected` | 48 `expected` |
| Diagnostics | 0 | 0 |

#### linux.network.list_interfaces, linux.network.list_addresses

- Fixtures (`tools/linux/networkinterface/interfaces_test.go`): four devices in two namespaces with reported flags (stored `IFF_PROMISC` without `gflags` is not reported, a device without carrier is not `RUNNING`), named and unnamed operational states, present and empty queueing disciplines; both families of addresses with scopes; a device whose `dev_addr` does not read, and strict mode; an IPv4 walk that ends early keeps the IPv6 addresses; a table without `inet6_ifaddr`.
- No fuzz target: the S40 readers are fuzzed (S40 9).

| | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|
| `list_interfaces` rows | 6: `lo` × 4, `eth0`, `docker0` | 7: `lo` × 6, `eth0` |
| Flags | `lo` `UP,LOOPBACK,RUNNING,LOWER_UP`; `eth0` `UP,BROADCAST,RUNNING,MULTICAST,LOWER_UP`; `docker0` `UP,BROADCAST,MULTICAST` | same for `lo`, `eth0` |
| Operational states | `UNKNOWN` (`lo`), `UP` (`eth0`), `DOWN` (`docker0`) | `UNKNOWN`, `UP` |
| `list_addresses` rows | 11 (6 IPv4, 5 IPv6) | 14 (7, 7) |
| Diagnostics | 0 | 0 |

The counts equal S40's M2 figures.

#### linux.network.list_hooks

- Fixtures (`tools/linux/networkhooks/hooks_test.go`): one IPv4 chain holding a consistent kernel entry, an INET registration from a module, a removed entry, an entry whose function differs from its registration, a registration for another hook and an unowned function; a device ingress chain with a NETDEV and an INET ingress registration; chains with counts 0 and 1025, one out of priority order, one whose registration does not read, and strict mode; a chain whose entries cross into memory that does not read; a table without `net.nf`; the NH3 placement rule.
- Fuzz target `FuzzHookChain`: an arbitrary chain block never gives more rows than its count or 1024. 30 s, about 231,000 executions, no failure after the oracle fix for a 1-byte block.

| | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|
| Rows | 24 | 66 |
| Non-empty chains | 16, longest 3 entries | 40, longest 5 |
| By namespace | 18 in init, 2 in each of the other three | 36 in init, 6 in each of the other five |
| Chains | IPv4 15, IPv6 9; no ARP, bridge or device chain holds an entry | IPv4 33, IPv6 33; none in ARP, bridge or devices |
| Registrations | all their own family | 5 `NFPROTO_INET` in each of IPv4 and IPv6, the rest their own family |
| Owners | kernel 8, `nf_nat` 8, `nf_conntrack` 4, `nf_defrag_ipv4` 2, `nf_tables` 2 | kernel 36, `nf_tables` 10, `nf_conntrack` 8, `nf_nat` 8, `nf_defrag_ipv4` 2, `nf_defrag_ipv6` 2 |
| Checks | 24 `consistent` | 66 `consistent` |
| Removed entries, chains out of order, rejected counts | 0, 0, 0 | 0, 0, 0 |

Every NH3, NH4 and NH5 invariant holds on both captures, so the other checks are covered by fixtures only.

#### linux.socket.scan

- Fixtures (`tools/linux/socketscan/scan_test.go`): a unix sock found both ways that points back; an orphaned TCP sock; a UDPv6 sock whose socket belongs to another sock; an `AF_QIPCRTR` sock with the default destructor that is not decoded; words rejected for family and for type; a file whose sock does not lead back; a kernel layer that cannot translate; no physical memory and no needles.
- Fuzz target `FuzzSweep`: arbitrary words around a destructor value; every row is aligned and inside memory. 30 s, about 4,500 executions, no failure.
- Ground truth: every sock `linux.socket.list` reaches (S13) is translated and looked up among the scan's rows.

| | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|
| Rows | 958 | 1322 |
| Found by destructor and file / destructor only / file only | 755 / 203 / 0 | 824 / 498 / 0 |
| Links: points back / no socket / does not read / elsewhere | 821 / 135 / 2 / 0 | 926 / 394 / 2 / 0 |
| Destructor-only socks that point back (sockets no file holds) | 66: `AF_INET` 10, `AF_INET6` 20, `AF_NETLINK` 35, `AF_QIPCRTR` 1 | 102: 18, 32, 51, 1 |
| Socks with no socket | `AF_UNIX` 53, `AF_INET` 37, `AF_NETLINK` 27, `AF_INET6` 17, `AF_PACKET` 1 | `AF_UNIX` 309, `AF_NETLINK` 55, `AF_INET6` 23, `AF_INET` 7 |
| Coverage | 956 `full`, 2 `family not decoded` | 1316 `full`, 4 `partial`, 2 `family not decoded` |
| Words rejected | 1 per destructor (3 for `udpv6_destruct_sock`), all by family | 0 |
| Files passed over | 28 (`socket.sk` null or unread) | 95 |
| `linux.socket.list` socks found | 755 of 755, all both ways, all pointing back | 824 of 824 |

Before `udp_destruct_sock` and `udpv6_destruct_sock` were added to SS1, 7 (mem3) and 10 (mem4) socks were found by their file alone. These are the UDP sockets of S13 9: 5 and 2 on mem3. With all eight destructors, no live sock is found by its file alone. The two ways therefore agree on every live socket of both captures. The destructor alone adds the kernel's own sockets, which no file holds, and the socks whose socket is gone.

### Mounts and open files

#### Synthetic fixtures and fuzz targets

- `tools/linux/mountlist/views_test.go`: one view per namespace from its first holder; every selected task with a PID set; a chrooted reader that sees only the mounts below its root, the mount point then being `/`; tasks with null `fs` and null `nsproxy`; the namespace filter and an option of the wrong type; the mounts form with a read-only superblock that has `sync`; a slave whose dominating group is its master's, shown as `master:1` with source `none`; a mount whose superblock does not read, and a null superblock, counted with strict mode failing; a reader root that does not read. Fuzz `FuzzMountRecord` (arbitrary bytes over a `struct mount`: the tool never fails and never shows more mounts than the namespace holds).
- `tools/linux/fileopen/descriptors_test.go`: two descriptors with every stat fact; null slots in order; a task with no table; an inode that does not read and a superblock that does not read; a path that is not built, flagged and counted with strict mode failing; a reader root that does not read; a slot page that does not read; a thread sharing its leader's table; the PID set, `files_only` and an option of the wrong type; a Windows profile. Fuzz `FuzzDescriptorSlots` (arbitrary slot words: rows never exceed `max_fds` and stay in slot order).

Both fuzz targets ran 30 s without a failure on 2026-11-12 (231,136 and 1,776,651 executions).

#### Measurements

`linuxkernfacts -only files,mounts`, 2026-11-12:

| | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| Thread-group leaders; with null `fs`, `nsproxy`, `files` | 203; 0, 0, 0 | 242; 1, 1, 1 (the exiting task of S40 M2) |
| Mount namespaces held | 17 | 23 |
| Mounts in them; with a self-parented root | 1413; 17 (one per namespace) | 941; 23 |
| Mount ids held by two mounts (MT7) | 0 | 0 |
| `linux.mount.list` rows (one view per namespace); diagnostics | 1348; none | 888; 3 (the S01 `init_task.tasks` break every task walk reports on mem4) |
| Mounts not shown (outside the first holder's root) | 65: each namespace's own root mount, and 49 of 52 in the namespace whose first task is chrooted (S39 section 9) | 53 |
| Mount ids listed twice | 0 | 0 |
| Source `none` | 16 | 76 |
| Tags `shared` / `master` / `propagate_from` / `unbindable` | 873 / 1216 / 0 / 0 | 867 / 758 / 0 / 0 |
| `mount_format` rows whose MT5 options differ from the mountinfo options | 0 of 1348 | 0 of 888 |
| `linux.file.list_open` rows (every thread); threads with rows; leaders | 8530; 468; 115 | 8865; 454; 123 |
| Distinct `struct file` behind them | 1743 | 2310 |
| A (thread, descriptor) listed twice | 0 | 0 |
| Rows without stat facts; without a device | 0; 0 | 0; 0 |
| Rows with a time whose nanoseconds are out of range | 0 | 0 |
| Paths not built; empty paths | 0; 0 | 0; 0 |
| `files_only`: rows with an empty path (pseudo files) | 7005 | 7184 |

The row counts equal S39's (8530 and 8865, 1348 and 888). Mount namespaces that only an exiting task or none holds are not reached by any view; the tool reads namespaces through tasks only (MT-O3). No capture has a reader whose root does not read, a table that does not read or a superblock that does not read, so those paths are covered by fixtures only.

## 10. Open points

Open points marked "Owner decision" are settled by the owner at the final stage of the rewrite; the default described is what the code does until then.

### Terminal, keyboard and tracing hooks

| # | Point | Closes with |
|---|---|---|
| TT-O1 | Owner decision: `linux.tty.check` gives one row per set handler (`receive_buf` and `receive_buf2`, TT7), so a tty has up to two rows; before it had one row per tty for `receive_buf` only. The tty name field is `TTY` (was `Name`); new fields `TTYAddress`, `Driver`, `DriverAddress`, `Discipline`, `OpsAddress`, `Handler`, `ModuleAddress`, `ModuleFound`. | Owner choice at the final stage |
| TT-O2 | Owner decision: a slot whose tty does not point back (TT4) gives no row and a diagnostic, rather than a flagged row. | Owner choice |
| TT-O3 | ttys of `TTY_DRIVER_DEVPTS_MEM` drivers (pseudo-terminals) live in devpts and are not listed (TT3); a hook on a pty's discipline is not seen. Reaching them through devpts inodes is not specified. | A spec revision |
| KN-O1 | Owner decision: new fields `BlockAddress`, `Priority`, `ModuleAddress`, `ModuleFound`. | Owner choice |
| TP-O1 | Owner decision: every tracepoint gives a row, one with no probe when it has none, so the tool produces 1064 and 1367 rows on the captures. The alternative is probe rows only (0 on both captures). Fields `TracepointOwner`, `KeyEnabled`, `Probes`, `DataAddress` are new; `Probe` is renamed `ProbeSymbol`. | Owner choice |
| TP-O2 | Probes on the captures: none, so the probe path is fixtures only. | A capture with tracing active (for example a running BPF raw tracepoint) |
| TP-O3 | The static-call trampoline (`static_call_key`, v6.1 on) that a single probe is called through is not compared with `funcs[0]`. | A spec revision |
| PE-O1 | Owner decision: `Event` fields are `PID` (tgid) and `TID` (pid, the owning thread), `PMU` (was `Event`), `ProgramName` (was `ShortName`), `ProgramSymbol` (was `FullName`), `ProgramAddress` (was `Address`); `EventAddress`, `Type`, `Config`, `ProgramID`, `ProgramCode` are new. | Owner choice |
| PE-O2 | The trace event's own name (`trace_event_call` name or `tp->name`, chosen by `TRACE_EVENT_FL_TRACEPOINT`) is not read: the flag bits move between tags and live in an anonymous enumeration the table names only by its constants (S59 4.4). | A table lookup by enumeration constant |
| PE-O3 | No capture has a perf event; every row path is fixtures only. | A capture with a perf-attached program |

### Kernel symbols, resources, VMCOREINFO and framebuffers

| # | Point | Closes with |
|---|---|---|
| KS-O1 | Owner decision: `Row` fields renamed to this spec's vocabulary: `SubSystem` to `Subsystem`, `ModuleName` to `Module`, `SymbolName` to `Name`, `SymbolNameUnknown` to `NameUnknown`; `ModuleUnknown` added. `Rows` is `CoreRows`; `Symbols` and `SymbolRows` are no longer exported; `Describe` is new. | Owner choice |
| KS-O2 | Owner decision: core rows' export state is unknown (KS2, KS4); a core letter's case gives the binding only. Before, upper case was reported as exported. | Owner choice |
| KS-O3 | Owner decision: `Description` is the KS3 class of the letter (for example `code`, `read-only data`, `absolute or per-CPU value`), replacing the earlier wording. | Owner choice |
| KS-O4 | Owner decision: core symbols with an empty name are not listed (KS1), and are counted; none on either capture. | Owner choice |
| IO-O1 | Owner decision: `Row` gains `Address` and `Flags`, and `NameState` replaces `NameUnreadable`. `Depth` is the tree depth; `/proc/iomem` stops counting at 5 (IO4). No capture has a tree deeper than 1. | Owner choice |
| IO-O2 | `flags` are given as stored, without names; `ioport_resource` (`/proc/ioports`) is not listed. | Owner decision: name the flags or add the I/O port tree |
| VC-O1 | Owner decision: `Value` is the text the kernel wrote (`SYMBOL(...)` and `KERNELOFFSET` in hexadecimal without `0x`), not a re-rendered number; `Cut` is new. | Owner choice |
| VC-O2 | mem3 holds two copies besides `vmcoreinfo_note` (0x6067100 and 0x67eb05f, the second not 4-byte aligned) with the same 107 entries. What memory holds them is not known. | Finding the owner of those pages (page-frame owner lookup) |
| FB-O1 | Owner decision: `Framebuffer` fields follow section 7. `Address` is now the `fb_info` (the screen memory is `ScreenAddress`); `Resolution` is replaced by `VirtualXRes`/`VirtualYRes` beside the visible `XRes`/`YRes`; `Size` is `ScreenSize`; `BPP` is `BitsPerPixel`; `DeviceAvailable` is `DeviceKnown`; `Filename`/`FilenameUnreadable` are `File`; `Slot`, `Node`, `PhysicalStart`, `LineLength`, `Visual` and `FourCC` are new; `State` words are lower case. `FourCC`, `FileName` and `ToImage` are replaced by `FourCCText`, the S00 name and `Picture`. | Owner choice |
| FB-O2 | Owner decision: the artefact kind `framebuffer` is not in S00's table; this tool uses it with the S00 form. Owner decision 2026-11-12: add the kind to S00. Done: S00 4.1 lists kind `framebuffer` (`fb_info` address, `fix.id` label, `png` or `bin`); the tool uses `extract.KindFramebuffer` and `extract.ExtPNG` in place of its own constant and literal; file names unchanged; files `docs/specs/S00-artifact-names.md`, `extract/artifactname.go`, `tools/linux/framebufferlist/picture.go`. | Owner adds the kind to S00 |
| FB-O3 | Only packed true colour is saved as a picture; pseudo-colour (palette), FOURCC, mono and `msb_right` layouts are saved as raw bytes. | A capture with such a framebuffer |
| FB-O4 | Screen memory is read through `screen_base` only. A framebuffer whose memory is device memory outside the capture (`smem_start` set, VRAM not in RAM) saves zeros; both captures' `smem_start` is 0 (a shadow buffer in kernel memory). | A capture of a host with a device framebuffer |
| FB-O5 | `FB_MAX` is taken from the header because the symbol table types no variables (S59 O5). | Owner decision with S59 O5 |

### Network objects and socket scan

| # | Point | Closes with |
|---|---|---|
| NO-O1 | Owner decision: `check_operations` now lists every member of every table with a verdict, where it listed only suspect members; `SymbolName` and `Address` are renamed `Table` and `TargetAddress`, with `ProcFile`, `TableModule`, `Module`, `Symbol` and `Verdict` added. | Owner choice (Q2) |
| NO-O2 | Kernels before 4.18 kept the tables in `tcp_seq_afinfo` and friends; no tag checked has that layout, so it is not read. | A pre-4.18 capture (Q7) |
| NO-O3 | A rootkit can also replace a `proc_dir_entry`'s `seq_ops` pointer or the file operations of `/proc/net`; only the tables themselves are checked. | A spec revision |
| NI-O1 | Owner decision: row fields renamed from the spec vocabulary (`NetNSAvailable`/`NSAvailable` to `NetNSKnown`, `NS` to `NetNS`, `MAC` to `HardwareAddress`, `IP` to `Address`, `Prefix` to `PrefixLength`, `ScopeType` to `Scope`, `State` to `OperState`, `Qlen` to `TxQueueLength`); `Addr` gains `Family`. | Owner choice (Q2) |
| NI-O2 | Owner decision: `Flags` now holds every flag `dev_get_flags` reports, `RUNNING` included, where `RUNNING` was left out. `Qdisc` is present and empty for a device with no queueing discipline, where it was absent. | Owner choice |
| NH-O1 | Owner decision: chain and hook names keep the kernel prefixes (`NFPROTO_IPV4`, `NF_INET_LOCAL_IN`), where they were `IPV4` and `LOCAL_IN`; fields renamed (`Proto` to `Protocol`, `Handler` to `FunctionAddress`, `NetNSAvailable` to `NetNSKnown`), `IsHooked` replaced by `Check`, and `Device`, `Index`, `OpsAddress`, `Registered` added. | Owner choice (Q2) |
| NH-O2 | Kernels before 4.16 kept hooks in lists or per-namespace `hooks[][]` arrays; no tag checked has them, so they are not read. | A pre-4.16 capture (Q7) |
| NH-O3 | A removed entry is recognised by `accept_all` only; `dummy_ops` is not in either capture's table (NHM1). Neither capture holds a removed entry, a device chain entry, an ARP or bridge entry, or a chain out of order. | A capture taken while a hook is unregistered |
| SS-O1 | Owner decision: the scan now keeps every sock that passes the SS1 to SS3 rules, with its link, where rows with no addresses and zero ports were dropped; this lists the kernel's own sockets and socks whose socket is gone (section 9). `Offset` is renamed `SockPhysical`, `Proto`/`SrcAddr`/`SrcPort`/`DstAddr`/`DstPort` follow S13's `Protocol`/`LocalAddress`/`LocalPort`/`RemoteAddress`/`RemotePort`, and `Link`, `SocketAddress`, `NetNS`, `NetNSKnown` and `Coverage` are added. | Owner choice (Q2) |
| SS-O2 | Families whose destructor is not in SS1 (for example vsock, Bluetooth, SCTP or MPTCP sockets) are found only through a file, so a closed one is not found. | A spec revision per family |
| SS-O3 | A freed sock whose slab object was reused keeps a destructor word until overwritten; the family and type rules reject some, and the link says **no socket** or **socket points elsewhere**, but a stale sock can still look whole. The slab state of the object is not read. | A spec revision reading slab freelists |
| SS-O4 | The mem3 rejected words (one per destructor) were not traced to their holder. | An experiment that names the page holding them |

### Mounts and open files

| # | Point | Closes with |
|---|---|---|
| MT-O1 | Owner decision: the row keeps the S39 field names, which follow the `mountinfo` columns (`MntNsID`, `MajorMinor`, `Fields`, `SBOptions`, `MntOpts`); a rename to the specification's words (`Namespace`, `Device`, `Tags`, `SuperOptions`, `MountsOptions`) is open. `MountAddress` is new. | Owner choice (Q2) |
| MT-O2 | Owner decision: `MntOpts` is the `/proc/<pid>/mounts` option column (MT5) and is empty without `mount_format`; before, it was always the union of the mount and superblock options. | Owner choice |
| MT-O3 | A mount namespace that no task holds (one bound to an nsfs file, for example) is not listed: views come from tasks (MT1). | A spec revision with a namespace source other than tasks |
| MT-O4 | Filesystem and security-module operations (MT9) are not run: a filesystem with its own `show_path` or `show_devname` (for example cgroup or overlay) may show a different root or source, and no filesystem-specific or security options are given. | Owner decision; a per-filesystem specification |
| MT-O5 | Values are unescaped (MT6); a mount point or source with a space shows the space, not `\040`. | Owner choice |
| MT-O6 | Owner decision: a mount that does not read is counted and left out, and strict mode fails; before, it was skipped with one summary diagnostic. | Owner choice |
| FO-O1 | Owner decision: `FileAddress` and `PathUnresolved` are new; the other fields keep their S39 names (Q2). | Owner choice |
| FO-O2 | Owner decision: a failed path, inode or slot read is one diagnostic per object in the brief's form, not one summary; on a damaged image there may be many. | Owner choice |
| FO-O3 | A pseudo file whose `d_dname` is not run (S39 O4) shows an empty, unresolved path. | A capture that holds one |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| TT-O1 | One row per handler |
| TT-O2 | Diagnostic, no row |
| TT-O3 | Defer to v0.2.0 |
| KN-O1 | Accept |
| TP-O1 | Row for every tracepoint |
| TP-O2 | Defer to v0.2.0 |
| TP-O3 | Defer to v0.2.0 |
| PE-O1 | Accept |
| PE-O2 | Defer to v0.2.0 |
| PE-O3 | Defer to v0.2.0 |
| KS-O1 | Accept |
| KS-O2 | Unknown |
| KS-O3 | KS3 class wording |
| KS-O4 | Leave out and count |
| IO-O1 | Accept |
| IO-O2 | Keep raw flags, no ports |
| VC-O1 | Kernel's text |
| VC-O2 | Defer to v0.2.0 |
| FB-O1 | Accept |
| FB-O2 | Add the kind to S00 |
| FB-O3 | Defer to v0.2.0 |
| FB-O4 | Defer to v0.2.0 |
| FB-O5 | Take from header |
| NO-O1 | List every member |
| NO-O2 | Defer to v0.2.0 |
| NO-O3 | Defer to v0.2.0 |
| NI-O1 | Accept |
| NI-O2 | Include RUNNING, empty Qdisc |
| NH-O1 | Keep kernel prefixes |
| NH-O2 | Defer to v0.2.0 |
| NH-O3 | Defer to v0.2.0 |
| SS-O1 | Keep every sock with link |
| SS-O2 | Defer to v0.2.0 |
| SS-O3 | Defer to v0.2.0 |
| SS-O4 | Defer to v0.2.0 |
| MT-O1 | Keep S39 names |
| MT-O2 | Mounts option column |
| MT-O3 | Defer to v0.2.0 |
| MT-O4 | Do not run them |
| MT-O5 | Show unescaped |
| MT-O6 | Count and omit |
| FO-O1 | Accept |
| FO-O2 | One per object |
| FO-O3 | Defer to v0.2.0 |

## 11. Provenance

Written from the Linux kernel sources at the tags in section 3, the RFCs and format documents each group cites, the project's specifications S01, S02, S05, S06, S13, S38, S39, S40, S46, S54 and S59, and the project's measurements in section 9. Every rule rests on the sources and measurements above, and the specification cites no earlier implementation.
