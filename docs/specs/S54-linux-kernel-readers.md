# S54: Linux kernel readers

Version 1, 2026-11-12.

## 1. Purpose

A Linux tool answers an examiner's question by reading kernel objects one member at a time: the name of a tty, the address in a function pointer, the length of a ring buffer, the flags of a program. Two readers serve thirteen tool packages: `linuxkern.Kernel` and `linuxtrace.Kernel`. From the session's symbol table and kernel memory they give the offset of a member, the value of an integer member at its declared width and sign (bitfields included), a pointer member, the size of a type, a string held in a fixed array or behind a pointer, the address of a symbol, and the KASLR shift between the table's addresses and the running kernel. A wrong width or sign reads as a plausible wrong value, not as an error, so every answer follows the C layout rules of the x86 ABI and the kernel's own type definitions.

This specification defines both readers. `linuxobj.Kernel` (S46) is a third reader with its own specification; merging the three is out of scope. The list, task and tree walks are S01 and S02 (`tools/linuxwalk`) and the module model is S06 (`tools/linuxmodule`); both readers hand those out and re-derive nothing of them.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Context | `tools.Context` | Kernel memory, the symbol table, the profile, options and Limits. |
| Paging mode | option `paging_mode` | The session's mode name; a name ending `la57` selects 5-level addresses. |
| Physical memory | option `physical_memory` | Searched for VMCOREINFO when the table cannot give the KASLR shift. |
| Strict | option `strict` | A damaged VMCOREINFO copy fails the shift instead of being skipped. |
| Limits | effective `limits.Limits` | Passed to the S01 walker and the VMCOREINFO search. |

The readers take no options of their own.

## 3. Facts from the sources

Kernel tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17, fetched from `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12, unless a row names fewer. The x86-64 psABI is version 1.0, `x86-64-ABI/low-level-sys-info.tex` at commit e1ce0983 (2025-03-12) of `https://gitlab.com/x86-psABIs/x86-64-ABI`, section 3.1.2. The supported captures run 6.17 (Ubuntu 24, mem3) and 6.14 (Fedora 40, mem4).

### C layout

| # | Fact | Source |
|---|---|---|
| L1 | Sizes in bytes: `char`, `signed char`, `unsigned char` and `_Bool` 1; `short` 2; `int` and `enum` 4; `long` 8 under LP64 and 4 under ILP32; `long long` 8; a pointer 8 under LP64 and 4 under ILP32. `char` is a signed byte. An `enum` is `signed int`, widened to `unsigned int`, `long` or `unsigned long` only when its values need it. `size_t` is `unsigned long` under LP64 and `unsigned int` under ILP32. | psABI 3.1.2, the scalar-types table and the text after it |
| L2 | A `_Bool` stored in memory is one byte whose value is 0 or 1. A null pointer has the value zero. | psABI 3.1.2 |
| L3 | Bit-fields are allocated from right to left (least significant bits first), each is contained in a storage unit appropriate for its declared type, and units may be shared with other members. A bit-field that is neither `signed` nor `unsigned` always has a non-negative value, with the range of the unsigned type of its width. | psABI 3.1.2, "Bit-Fields" and its bit-field ranges table |
| L4 | Memory is little-endian: the low-order bytes of a value are at the lower address, and bits in each byte are numbered from right to left. | psABI 3.1.2 (`__int128` storage, byte layout); S01 X1 |

### Kernel types and build

| # | Fact | Source |
|---|---|---|
| T1 | `__s8`/`__u8` to `__s64`/`__u64` are `signed`/`unsigned` `char`, `short`, `int` and `long long`; `s8`/`u8` to `s64`/`u64` are typedefs of those. | `include/uapi/asm-generic/int-ll64.h`, `include/asm-generic/int-ll64.h`, every tag |
| T2 | `bool` is `_Bool`; `uintptr_t` and `ulong` are `unsigned long`; `size_t` and `ssize_t` are `__kernel_size_t` and `__kernel_ssize_t`, which are `unsigned long` and `long` (`unsigned int` and `int` on a 32-bit kernel); `phys_addr_t` is `u64` or `u32` by configuration and `resource_size_t` is `phys_addr_t`. | `include/linux/types.h`, `include/uapi/asm-generic/posix_types.h`, `arch/x86/include/uapi/asm/posix_types_64.h`, every tag |
| T3 | `__BITS_PER_LONG` is 64 on x86-64 and 32 otherwise. | `arch/x86/include/uapi/asm/bitsperlong.h`, every tag |
| T4 | The top-level Makefile builds the kernel with `-funsigned-char` at v6.4, v6.14 and v6.17; v4.19 and v6.1 have no such flag. Plain `char` is therefore unsigned on the captures' kernels, against L1. | `Makefile`, every tag |
| T5 | With structure randomisation configured, `__randomize_layout` expands to the `randomize_layout` attribute, so a structure's member order changes between builds. | `include/linux/compiler_types.h`, v6.1, v6.17 (v4.19 takes it from the plugin header) |
| T6 | `strscpy` always leaves the destination NUL-terminated unless it has no bytes. `__set_task_comm` copies at most `sizeof(comm) - 1` bytes and zero-fills the rest at v6.14 and v6.17, and uses `strlcpy` at v4.19 and `strscpy_pad` at v6.1 and v6.4. `TASK_COMM_LEN` is 16. | `lib/string.c` (comment at v4.19 and v6.1, the forced NUL in `sized_strscpy` at v6.14 and v6.17), `fs/exec.c`, `include/linux/sched.h`, every tag |
| T7 | The linker script sets `_text` and then `_stext` at the same location, the start of the image's `.text`. | `arch/x86/kernel/vmlinux.lds.S`, every tag |
| T8 | When KASLR moves the kernel, `handle_relocations` applies one delta, `virt_addr - LOAD_PHYSICAL_ADDR` on x86-64, to every relocation of the image. | `arch/x86/boot/compressed/misc.c`, every tag |
| T9 | `__START_KERNEL_map` is 0xffffffff80000000 and `KERNEL_IMAGE_SIZE` is 1 GiB with KASLR configured (512 MiB without). | `arch/x86/include/asm/page_64_types.h`, every tag |

### Addresses

| # | Fact | Source |
|---|---|---|
| A1 | A linear address is canonical for 4-level paging when bits 63:47 are identical and for 5-level paging when bits 63:56 are identical. | S04 A14 (Intel SDM 4.5) |
| A2 | 32-bit and PAE paging translate 32-bit linear addresses. | S04 A1 (Intel SDM 5.3 to 5.5) |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Table shapes. Both captures' tables list, name, type and locate their symbols, answer type lookups and give member widths. Over the structures reachable from 21 roots (1,455 on mem3 and 1,290 on mem4, with 13,466 and 12,186 members), scalar members name a C base type after typedefs (`_Bool`, `char`, `signed char`, `unsigned char`, `short int`, `short unsigned int`, `int`, `unsigned int`, `long int`, `long unsigned int`, `long long int`, `long long unsigned int`) or an enumeration, never a typedef such as `u32`; the widths are those of L1 under LP64. Two enumeration-typed members, of `blk_integrity_checksum` and `rw_hint`, are 1 byte wide. Of 461 and 438 bitfields, none lies outside its unit and none sits at an offset that is not a multiple of its unit's width. | `kernelreaderfacts`, 2026-11-12 |
| M2 | Shift. `_text` and `_stext` are listed at 0xffffffff81000000 on both tables and run at the same address, as T7 says; with `_etext`, `init_task` and `linux_banner` they move by 0x11400000 on mem3 and 0x8000000 on mem4. The VMCOREINFO note gives the same shift on both, with no damaged copy. | Same script |
| M3 | Tool use. See section 9. | Same script |

## 4. Algorithm

### 4.1 Address form

1. The width is 32 bits with 4-byte pointers (A2), 57 bits when the paging mode name ends `la57`, and 48 bits otherwise (A1). The mask keeps the low width bits.
2. The canonical form of an address is its masked value with the top kept bit copied into every bit above it (A1). At 32 bits the masked value is the canonical form.
3. `linuxkern.Kernel` gives every pointer and symbol address in masked form, and its memory reader `Mem` puts an address in canonical form before each read. `linuxtrace.Kernel` gives every address in canonical form and reads the session's memory with the address it is given.

### 4.2 Memory reads

1. **Read** returns exactly the bytes asked for. Zero bytes is an empty result with no read. A range whose end, address plus size, is 2^64 or more is an error (`linuxkern: <n> bytes at 0x<addr> run past the top of the address space`): the test is that the 64-bit sum wraps, so a range whose last byte is 2^64 − 1 is refused too. A failed read and a short read are errors.
2. **Readable** reads every page of the range, a page at a time, because a layer may answer a multi-page read from its first page. A size of 0 means one byte. A range whose end is 2^64 or more does not read, by the same wrap test; so the byte at 2^64 − 1 never reads.
3. **Padded read** returns the range with each page that does not read replaced by zeros (`extract.ReadPadded`).
4. **Pointer** is a pointer-wide little-endian word (L4). **ReadUint** decodes 1 to 8 bytes little-endian; other widths are an error.

### 4.3 Members, types and integers

1. **Member path.** `linuxkern` resolves a dotted path one name at a time; each name before the last must be a member whose type is a named structure or union, neither a pointer nor an array. The offset is the sum of the members' offsets. `linuxtrace` resolves one member. Offsets come only from the table (T5).
2. **Type size.** A structure's size when the table gives one above 0; else the table's own size of the type; else the C width of a base or typedef name (step 3); else an error.
3. **C width of a name.** 1 for `char`, `signed char`, `unsigned char`, `_Bool`, `bool`, `u8`, `s8`, `__u8`, `__s8`; 2 for the `short` names and the 16-bit typedefs; 4 for the `int` names and the 32-bit typedefs; 8 for the `long long` names and the 64-bit typedefs; the pointer width for the `long` names, `size_t`, `ssize_t`, `uintptr_t` and `ulong` (L1, T1 to T3). Other names have no C width.
4. **Integer width.** A pointer member is a pointer wide. Otherwise the table's width for the member; else the C width of its type name; else the type's size (step 2). The table's width comes first because an enumeration declared packed is narrower than L1's 4 bytes (M1). An array is not an integer, and neither is a member whose width is 0 or above 8.
5. **Bitfield.** A member with a bit length is read from the unit of the integer width at the member's offset, taking the bit length from the bit offset upwards (L3, L4). A bitfield whose bits do not all lie inside its unit is refused (L3). A member with no bit length is not a bitfield, and any bit offset the table gives it is ignored.
6. **Sign.** Unsigned: pointers; type names that contain `unsigned`; `_Bool`, `bool`, plain `char` (T4), `u8` to `u64`, `__u8` to `__u64`, `size_t`, `uintptr_t`, `ulong`, `phys_addr_t`, `resource_size_t` (T1, T2); a member typed as a structure or union (a small aggregate such as `atomic_t` reads as its bytes and has no sign of its own); a member with no type name. Every other integer, enumerations included (L1), is signed. A bitfield is signed only when its type name says `signed` and is not unsigned by this rule, because the table cannot tell `int` from `signed int` and L3 makes a plain bitfield non-negative.
7. **Uint** returns the bits. **Int** sign-extends them from the top bit of the width or bit length when the member is signed.

### 4.4 Pointers

1. A pointer member, or an unsigned integer member exactly a pointer wide that is not a bitfield, is read as a pointer. The kernel keeps some addresses in `unsigned long` members (S06 F9). Any other member is refused.
2. **Pointee size** is the size of the pointed-to type, a pointer wide for a pointer to a pointer, and 0 for `void`, a function or a type with no size.
3. **Deref** (`linuxtrace`) reads the pointer and says whether it is set (non-zero once masked) and its whole pointee reads (4.2 step 2, so a pointee of size 0 needs one byte).

### 4.5 Strings

1. **String at an address.** Read at most `count` bytes, a page at a time, and stop at the first NUL. The string is the bytes before the NUL, or all `count` bytes when there is none. A `count` of 0 is an error. A page that is still needed and does not read is an error, not a shorter string: the missing bytes may hold more of it. When the last page below 2^64 holds no NUL and bytes are still to be read, the result is the error `linuxkern: string runs past the top of the address space`. A NUL found before that point ends the string normally.
2. **String in an array member.** The member must be an array with a declared length whose element is 1 byte wide; its length is that many bytes, read by step 1. A kernel-written array holds a NUL (T6), and a full array without one is returned whole; the byte after the array is never read.
3. Bytes that are not UTF-8 are replaced as `util.DecodeUTF8Replace` does, so rows hold valid text.

### 4.6 Symbols, the table listing and the KASLR shift

1. **Symbol** gives the running address from the table, masked (`linuxkern`) or canonical (`linuxtrace`); an absent symbol is `ErrNoSymbol` (`linuxkern`) or an error naming it (`linuxtrace`).
2. **Shift.** When the table lists its symbols, the shift is the running address of `_text` less its listed address, else that of `_stext` (T7, T8, M2). Otherwise the VMCOREINFO notes in physical memory are searched (`linuxkernel.FindKernel`) and the first that gives a layout supplies the shift. A damaged copy before it is a diagnostic `<tool>: VMCOREINFO note at 0x<offset>: skipped: <reason>`, or, in strict mode, an error carrying the damage. No physical memory is an error. The shift is found once per reader.
3. **Table listing** gives every symbol in the table's own (link-time) space. A table that lists its symbols gives them directly. A table that only names them gives each name's running address, less the shift when the result lies in the image mapping, `[__START_KERNEL_map, __START_KERNEL_map + 1 GiB)` (T8, T9); other symbols, such as per-CPU offsets, do not move. A table that does neither is `ErrNoSymbolList`.
4. **Names at an address** are the table's names at the canonical address, in name order. A table with no address index gives none (`linuxkern` also says so).

### 4.7 Walkers and the module model

`Walker` hands the S01 reader the kernel memory, the table, the reader's address form (masked for `linuxkern`, canonical for `linuxtrace`) and the effective Limits. `Modules` builds the S06 model over that walker once per reader and keeps its result or error.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Profile is Linux, pointers are 4 or 8 bytes (`linuxkern.New`) | A2, L1 | Error from `New` |
| A path passes only through structure members | 4.3 step 1 | Error naming the member |
| An integer member is not an array and is 1 to 8 bytes wide | L1, 4.3 step 4 | `ErrNotInteger` |
| A bitfield's bits lie inside its unit | L3, M1 | `ErrNotInteger` |
| A pointer member is a pointer or a pointer-wide unsigned integer | L1, S06 F9 | Error naming the member |
| A string array has a declared length and 1-byte elements | T6, L1 | `ErrNotByteArray` |
| A string reads up to its NUL or count | 4.5 step 1 | `ErrStringUnread` |
| A string asks for at least one byte | 4.5 step 1 | `ErrNoString` |
| A read ends below 2^64: the 64-bit sum of address and size does not wrap | Arithmetic bound | Error; Readable is false |

## 6. Failure modes

| Case | Result |
|---|---|
| A member, type or symbol is not in the table | Error wrapping the table's error, or `ErrNoSymbol` |
| Memory does not read | The layer's error; `ErrShortRead` for a short read |
| A string's later page does not read | `ErrStringUnread`, with the string's address and the failing page |
| No table listing | `ErrNoSymbolList` |
| No shift from the list and no physical memory | Error |
| A damaged VMCOREINFO copy | Diagnostic, or in strict mode an error with the damage (`autoload.VMCoreInfoDamageError`) |
| No enumerations in the table (`EnumName`) | Error |

Leaf errors and sentinels carry the prefix `linuxkern:`; `linuxtrace` adds `linuxtrace:` and the member and address. Callers add the tool and object.

## 7. Result schema

The readers produce values, not rows. The exported surface is kept as the tools use it.

`linuxkern`:
- `Kernel` with `Mem`, `Sym`, `PtrSize`, `Mask`; `New`, `Context`, `Diag`, `Canonical`, `Walker`, `Modules`.
- Memory: `Read`, `Valid`, `Readable`, `ReadPadded`, `ReadPointer`, `ReadUint`, `PageSize`.
- Symbols: `HasSymbol`, `Symbol`, `SymbolType`, `TableSymbols`, `SymbolTypeRef`, `Shift`, `SymbolsAt`, `SymbolLister`, `SymbolTyper`, `ErrNoSymbol`, `ErrNoSymbolList`.
- Members: `Member` (`Offset`, `Field`, `Parent`), `HasType`, `HasMember`, `TypeSize`, `Uint`, `Int`, `Ptr`, `PointeeSize`, `ElementSize`, `StringAt`, `MemberString`.
- New, shared with `linuxtrace`: `AddressMask`, `CanonicalAddress`, `CWidth`, `CUnsigned`, `SizeOf`, `HasType` (function), `Integer` and `IntegerMember` (with `Value` and `ReadSigned`), `PointerMember`, `PointeeSize` (function), `ElementSize` (function), `ReadString`, `ByteArrayLength`, `Readable` (function), `SymbolsAt` (function), and the sentinels `ErrNotInteger`, `ErrNotByteArray`, `ErrNoString`, `ErrStringUnread`, `ErrStringPastSpace`, `ErrShortRead`.

`linuxtrace`: `Kernel` with `New`, `Context`, `Memory`, `Symbols`, `Masked`, `Canonical`, `PointerSize`, `Walker`, `Modules`, `Field`, `Has`, `HasType`, `HasSymbol`, `Symbol`, `SizeOf`, `PointeeSize`, `Readable`, `Uint`, `Int`, `Pointer`, `PointerAt`, `Deref`, `StringAt`, `CharArray`, `ReadPadded`, `SymbolLocator`, `SymbolsAt`, `EnumName`, `EnumField`; the functions `Readable` and `SignExtend`; `ErrUnsupported` (the S01 sentinel).

Names at an address are sorted by name in both readers. `EnumField` returns the member's value under the 4.3 sign rule and the enumeration's type name.

## 8. Limits

The readers apply no cap of their own. A string read is bounded by the caller's `count` or the array's declared length. The effective Limits go to the S01 walker and the VMCOREINFO search.

## 9. Acceptance

- Synthetic fixtures from section 3: address forms for 4-byte, 4-level and 5-level kernels; canonical reads of masked addresses; exact and short reads; Readable over a page that does not read; integer members of every width with signed, unsigned, plain-bitfield, `signed char` bitfield, packed enumeration and small-structure types; a bitfield outside its unit; arrays refused as integers; pointers and `unsigned long` addresses accepted, `int` and `long` refused; strings ending at a NUL, at the count, across a page, into a page that does not read, and with bytes that are not UTF-8; array strings with and without a NUL and non-byte arrays refused; the shift from `_text`, from VMCOREINFO past a damaged copy, and refused in strict mode; listings from a listing table, from names, and refused; names at an address in order; the module model built once.
- Fuzz targets: `FuzzReadString` (arbitrary bytes, start, count and an unmapped page) and `FuzzIntegerMember` (arbitrary width, bit offset, bit length, type name and bytes), both in `tools/linuxkern`. `linuxtrace` parses nothing of its own; its reads go through the same functions.
- On both captures (M3), every tool that uses the readers runs, and the tool results are compared with those of the readers this one replaced.

### M3: tool use on the captures

Run on 2026-11-12 with `kernelreaderfacts` over the sixteen tools whose packages use the readers (`linux.framebuffer.list`, `linux.interrupt.check`, `linux.kernel.list_io_memory`, `linux.keyboard.list_notifiers`, `linux.log.read_kernel`, `linux.memory.list_elf_files`, `linux.module.list`, `linux.pagecache.list_files`, `linux.process.check_identity`, `linux.process.read_kernel_stack`, `linux.syscall.list`, `linux.tracing.list_bpf_programs`, `linux.tracing.check_ftrace`, `linux.tracing.list_perf_events`, `linux.tracing.check_tracepoints`, `linux.tty.check`). Note, 2026-11-12, after this run: `linux.memory.list_elf_files`, `linux.process.check_identity` and `linux.process.read_kernel_stack` now import `linuxobj`, not `linuxkern` directly; the figures below were not re-measured. Calls are counted when the reader is the code that asks the table or the memory, not when a tool drives a walker the reader handed out.

| Figure | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|
| Members the tools ask the readers for (distinct type and member) | 61 | 59 |
| Of those, resolved by the table | 61 | 58 (`fb_info.dev` is absent; the framebuffer tool probes for it) |
| Bitfield members resolved | 2 (`printk_info.flags`, `printk_info.level`, through `Member`; the log tool decodes them) | 2 (the same) |
| Integer reads through `Uint` or `Int` | 65 | 64 |
| Of those, bitfields | 0 | 0 |
| Signed-typed reads with the top bit set | 0 | 0 |
| String reads | 24 (`StringAt` 21, `MemberString` 2, `CharArray` 1) | 23 (`StringAt` 20, `MemberString` 2, `CharArray` 1) |
| Of those, ended at a NUL / at the count / failed | 24 / 0 / 0 | 23 / 0 / 0 |
| String lengths (bytes before the NUL) | 1-7: 4, 8-15: 18, 16-31: 1, 32-63: 1 | 1-7: 3, 8-15: 18, 16-31: 1, 32-63: 1 |
| Array strings | `tty_struct.name` [64]: 2, longest 4; `fb_fix_screeninfo.id` [16]: 1, length 15 | the same |
| Tool results identical to those of the replaced readers | 16 of 16 | 16 of 16 |

`linux.tracing.check_tracepoints` ends on both captures with the same error before and after, because the table gives `__start___tracepoints_ptrs` no type; that is the tool's own rule, not the readers'.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Whether a plain `int` bitfield is signed is the compiler's choice; L3 says it is not, and the table cannot tell `int` from `signed int`. The readers follow L3. | Owner decision; a capture whose tools read a signed bitfield with its top bit set (none in M3) |
| O2 | Plain `char` is taken as unsigned (T4). Kernels before v6.2 built it signed (L1); `Int` on a plain `char` member of such a kernel would read 0x80 to 0xff as positive. No tool reads one (M3). | Owner decision; a capture of an older kernel (Q7) |
| O3 | A small structure such as `atomic_t` read as an integer has no sign, so `Int` on it does not sign-extend `counter`. | Owner decision |
| O4 | 4-byte pointers and 5-level paging are written from the sources only; no capture runs them. | A 32-bit or LA57 capture (Q7) |
| O5 | The exported names added in section 7 for the two readers to share, and the kept names, are owner questions Q2. | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Follow L3 |
| O2 | Unsigned (T4) |
| O3 | No sign extension |
| O4 | Defer to v0.2.0 |
| O5 | Accept names |

## 11. Provenance

Written from the kernel sources at the tags in section 3, the x86-64 psABI section 3.1.2, the project's specifications S01, S04 and S06, and the project's measurements in section 3 and section 9. Every rule rests on the sources and measurements above.
