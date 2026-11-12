# S10: Linux interrupt descriptor table check

Version 1, 2026-11-12.

## 1. Purpose

On x86, every exception and interrupt enters the kernel through a gate in the interrupt descriptor table (IDT). A rootkit that rewrites a gate, or points the CPUs at a table of its own, runs its code on every page fault, timer tick or system call made through `int 0x80`, before the kernel sees the event. An examiner needs, for each of the 256 vectors: the gate the CPUs use, where its handler lies (the kernel image, the kernel's freed init text, a module, or nowhere known), and whether the table the CPUs load differs from the kernel's own `idt_table`.

This specification defines how the table is found, how a gate descriptor is decoded, and how each handler is placed. Address ownership is S06 4.5.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxkern.Kernel` | Memory, symbol table, pointer width and address form. |
| Module model | S06 model, with the S07 known-module set | Owner of an address outside the kernel image. |
| Symbols | session symbol table | `idt_table`, `idt_descr`, `_text`, `_etext`, `_sinittext`, `_einittext`; the type `gate_struct` and `desc_ptr` when the table has them. |
| Limits | effective `limits.Limits` | Section 8. |
| Options | none | The tool takes no options. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17. The supported captures run 6.14 (Fedora 40) and 6.17 (Ubuntu 24). The Intel manual is the Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3A, order number 253668-093US; in this edition interrupt and exception handling is chapter 7.

| # | Fact | Source |
|---|---|---|
| G1 | There are 256 vectors. The IDT need not hold more than 256 descriptors, and a vector that references a descriptor beyond the IDT limit raises #GP. | SDM 3A 7.10; `IDT_ENTRIES` 256 and `NR_VECTORS` 256 in `arch/x86/include/asm/segment.h` and `irq_vectors.h`, every tag. |
| G2 | IDTR holds the table's linear base and a 16-bit limit, the offset of the last valid byte. LIDT loads it from memory; it cannot be read back from memory. | SDM 3A 2.4.3, 7.10, Figure 7-1. |
| G3 | In protected mode a gate is 8 bytes: offset 15:0 in bytes 1:0, segment selector in bytes 3:2, type in bits 11:8 of bytes 7:4, a zero bit 12, DPL in bits 14:13, P in bit 15, offset 31:16 in bytes 7:6. A task gate carries a TSS selector in bytes 3:2 and no offset. | SDM 3A 7.11, Figure 7-2. |
| G4 | In IA-32e mode a gate is 16 bytes. Bytes 7:0 are as G3, except that bits 2:0 of bytes 7:4 are the IST index and bits 7:3 are zero; bytes 11:8 hold offset 63:32; bytes 15:12 are reserved. The vector is scaled by 16. | SDM 3A 7.14.1, Figure 7-8; 7.14.5 ("a 3-bit IST index field"). |
| G5 | Type encodings for system descriptors: 5 task gate, 6 16-bit interrupt gate, 7 16-bit trap gate, 0xC call gate, 0xE interrupt gate, 0xF trap gate. In IA-32e mode only 0xE and 0xF can be referenced from the IDT: 6 and 7 raise #GP(0), and task gates are not supported. | SDM 3A Table 3-2; 7.14.1; 7.14.5. |
| G6 | An IST index of 0 means no IST stack switch. | SDM 3A 7.14.5. |
| K1 | `struct gate_struct { u16 offset_low; u16 segment; struct idt_bits bits; u16 offset_middle; u32 offset_high; u32 reserved; }` (the last two on x86-64 only), packed; `struct idt_bits { u16 ist:3, zero:5, type:5, dpl:2, p:1; }`. `gate_offset` joins the three offset parts. `gate_desc` is `struct gate_struct`. | `arch/x86/include/asm/desc_defs.h`, every tag. |
| K2 | Gate types: `GATE_INTERRUPT` 0xE, `GATE_TRAP` 0xF, `GATE_CALL` 0xC, `GATE_TASK` 0x5. | `desc_defs.h`, every tag. |
| K3 | `struct desc_ptr { unsigned short size; unsigned long address; }`, packed. | `desc_defs.h`, every tag. |
| K4 | The kernel has one table, `gate_desc idt_table[IDT_ENTRIES] __page_aligned_bss`, and one `struct desc_ptr idt_descr` whose size is the table size minus 1 and whose address starts as `idt_table`. Every CPU loads `idt_descr` (`load_current_idt`, `idt_setup_*`). There is no per-CPU IDT. `idt_table` and `idt_descr` are global at v4.19 and `static` from v6.1. | `arch/x86/kernel/idt.c`, every tag. |
| K5 | After the gates are set up, x86-64 maps the physical page of `idt_table` read-only at `CPU_ENTRY_AREA_RO_IDT` and sets `idt_descr.address` to that address, so the CPUs index a second virtual copy of the same page. At v4.19 this is in `trap_init`; from v6.1 in `idt_map_in_cea`. `CPU_ENTRY_AREA_RO_IDT` is `CPU_ENTRY_AREA_BASE`, which is `-4 << P4D_SHIFT` with `P4D_SHIFT` 39: 0xfffffe0000000000. | `arch/x86/kernel/traps.c` v4.19; `arch/x86/kernel/idt.c` v6.1 to v6.17; `arch/x86/include/asm/cpu_entry_area.h` v4.19, `pgtable_areas.h` v6.1 to v6.17, `pgtable_64_types.h` every tag. |
| K6 | v4.19 x86-64 also has `debug_idt_table`, a copy of `idt_table` with vector 1 on the default stack, loaded through `debug_idt_descr` only while a CPU's `debug_idt_ctr` is set. It is gone from v6.1. | `arch/x86/kernel/idt.c` and `arch/x86/include/asm/desc.h` v4.19, v6.1. |
| K7 | `bringup_idt_table` (v6.1 on) is loaded only by the x86-64 start-up code, before `idt_setup_early_handler` loads `idt_table`. | `arch/x86/kernel/head64.c` v6.1, v6.14, v6.17. |
| K8 | Every gate the kernel writes is built by `G()` or `set_intr_gate` with P set, the segment `__KERNEL_CS`, and type `GATE_INTERRUPT`, except the 32-bit double-fault task gate (`TSKG`). `__KERNEL_CS` is `GDT_ENTRY_KERNEL_CS * 8`: 0x10 on x86-64 (entry 2), 0x60 on 32-bit (entry 12). | `arch/x86/kernel/idt.c`, `arch/x86/include/asm/segment.h`, every tag. |
| K9 | `SYSG` gates have DPL 3: `int3` (vector 3), overflow (4) and `IA32_SYSCALL_VECTOR` 0x80. All others have DPL 0. | `idt.c` every tag; `irq_vectors.h`. |
| K10 | Fill order: `idt_setup_early_handler` sets vectors 0 to 31 (`NUM_EXCEPTION_VECTORS`) to `early_idt_handler_array[i]`, and on 32-bit vectors 32 to 255 to `early_ignore_irq`. Later steps overwrite the listed exceptions (`def_idts`, `early_idts`, `early_pf_idts`), vector 0x80 when ia32 is enabled, the APIC vectors, every remaining vector from `FIRST_EXTERNAL_VECTOR` (0x20) below `FIRST_SYSTEM_VECTOR` with `irq_entries_start + stride × (i − 0x20)`, and every remaining system vector with a spurious entry. So all 256 gates are written, and an exception vector the kernel has no handler for keeps its `early_idt_handler_array` entry. | `idt.c` `idt_setup_early_handler`, `idt_setup_traps`, `idt_setup_apic_and_irq_gates`, every tag; `arch/x86/kernel/head64.c` every tag. |
| K11 | `early_idt_handler_array` is in `.init.text` (`__INIT`), placed between `_sinittext` and `_einittext`, after `_etext`. `free_initmem` frees `__init_begin` to `__init_end`, which holds `.init.text`, once boot ends. `EARLY_IDT_HANDLER_SIZE` is 9, and 9 + `ENDBR_INSN_SIZE` from v6.1. | `arch/x86/kernel/head_64.S`, `include/linux/init.h`, `include/asm-generic/vmlinux.lds.h`, `arch/x86/kernel/vmlinux.lds.S`, `arch/x86/mm/init.c`, `segment.h`, v4.19, v6.17. |
| K12 | `irq_entries_start`, `spurious_entries_start` and the `asm_exc_*`/`asm_sysvec_*` entry points are in `.entry.text` or `.text`, inside `[_text, _etext)`. | `arch/x86/include/asm/idtentry.h` v6.1 to v6.17; `arch/x86/entry/entry_64.S` v4.19; `vmlinux.lds.S` (`ENTRY_TEXT` inside `.text`, before `_etext`), every tag. |
| K13 | With FRED enabled (present at v6.14 and v6.17, absent at v6.4; `CONFIG_X86_FRED`), `trap_init` skips `idt_setup_traps` and events are delivered without the IDT. | `arch/x86/kernel/traps.c` v6.4, v6.14, v6.17; SDM 3A 7.10 note. |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Symbol-table shapes. Both captures type `gate_struct` at 16 bytes (offset_low 0, segment 2, bits 4, offset_middle 6, offset_high 8, reserved 0xc), `idt_bits` with ist bits 0:3, zero 3:5, type 8:5, dpl 13:2, p 15:1, and `desc_ptr` at 10 bytes (size 0, address 2). `idt_table`, `idt_descr`, `bringup_idt_table`, `_sinittext`, `_einittext` and `early_idt_handler_array` are present and untyped; `debug_idt_table` is absent. | `idtfacts` on mem3_ubuntu24 and mem4_fedora40, 2026-11-12. |
| M2 | `idt_descr` holds size 0xfff and address 0xfffffe0000000000 on both captures, and the 256 entries read there equal `idt_table` byte for byte. | Same script. |
| M3 | Gate values and handler placement per capture. | Section 9 table. |

## 4. Algorithm

### 4.1 Shape

1. The entry size E is 16 bytes with 8-byte pointers (G4) and 8 bytes with 4-byte pointers (G3).
2. If the symbol table types `gate_struct` and its size is not E, stop with an error wrapping `ErrUnsupported` (K1).
3. `idt_table` gives the table address T. A missing symbol is `ErrNoTable`.

### 4.2 The loaded copy

1. If `idt_descr` is in the symbol table, read its `size` (2 bytes) and `address` (pointer width) at the offsets of `desc_ptr.size` and `desc_ptr.address` when the table types `desc_ptr`, otherwise 0 and 2 (K3). The address, in the address form, is the loaded copy L (K4, K5).
2. If `idt_descr` is missing or does not read, there is no loaded copy, with a diagnostic.
3. A size other than 256 × E − 1 gets a diagnostic. The rows still cover 256 vectors (G1).

### 4.3 Each vector

For each vector v from 0 to 255:

1. Read E bytes at T + v × E, and at L + v × E when there is a loaded copy and L ≠ T.
2. The decoded entry is the loaded copy's bytes when they read (**source** `loaded`), else `idt_table`'s (**source** `idt_table`). When neither reads, the vector is counted as unread and has no row.
3. **Differs** is true when both read and their bytes are not equal.
4. Decode the entry (4.4).
5. Place the handler (4.5).

### 4.4 Gate decode

Given E bytes, little-endian (S06 F15):

- Offset: bytes 1:0, then bytes 7:6 as bits 31:16, and with E = 16 bytes 11:8 as bits 63:32 (G3, G4).
- Selector: bytes 3:2.
- From the 16-bit word at bytes 5:4: IST is bits 2:0 when E = 16 and 0 otherwise; type is bits 11:8; S is bit 12; DPL is bits 14:13; P is bit 15.
- Gate type (G5):
  - S set: `invalid`.
  - E = 16: 0xE `interrupt`, 0xF `trap`, anything else `invalid`.
  - E = 8: 5 `task`, 6 `interrupt16`, 7 `trap16`, 0xE `interrupt`, 0xF `trap`, anything else `invalid`.
- The handler address is the offset in the address form. A `task` gate has no handler (G3): its address is 0.

Fewer than E bytes is `ErrShortGate`.

### 4.5 Handler placement

1. A `task` gate is placed `none`.
2. Look the address up with S06 4.5 and no modules. An owner of the kernel image is `kernel`, with the module name `kernel` and the symbol the kernel namer gives.
3. Otherwise, an address in `[_sinittext, _einittext)` is `kernel_init`, with the module name `kernel` and the first name the symbol table gives for the address, if any (K10, K11).
4. Otherwise, build the S07 known-module set once per run and look the address up in it. A module owner is `module`, with its module name and symbol (S06 4.5).
5. Otherwise the handler is `unowned`, with empty module and symbol.

The kernel namer gives the symbol-table names at exactly the address, in byte order.

## 5. Validity rules

The check reports facts; it does not drop a gate.

| Rule | Justification | On failure |
|---|---|---|
| `gate_struct`, when typed, is E bytes | K1, G3, G4 | `ErrUnsupported` |
| `idt_descr.size` is 256 × E − 1 | K4 | Diagnostic |
| A handler is in the kernel image | K10, K12 | Placement `kernel_init`, `module` or `unowned` |
| The loaded copy equals `idt_table` | K5 | `Differs` on the row, and one diagnostic with the count |

On a clean kernel every gate is present, `interrupt`, selector `__KERNEL_CS`, and placed `kernel`, except exception vectors with no kernel handler, which are `kernel_init` (K8, K10, K11; M3). A `kernel_init` handler points at freed memory, but the CPU raises none of those vectors in normal running: they are reserved or belong to features the kernel did not configure.

## 6. Failure modes

| Case | Result |
|---|---|
| `idt_table` missing | `ErrNoTable` |
| `gate_struct` of another size | Error wrapping `ErrUnsupported` |
| `idt_descr` missing or unreadable | Diagnostic; rows from `idt_table` only |
| A vector reads in neither copy | Counted; one diagnostic with the count |
| The known-module set cannot be built, or a view is lossy | The S07 view diagnostics; module handlers are then `unowned` |
| Strict mode | Unread vectors, and a lossy or failed module view, are errors. A missing loaded copy and a `Differs` row are not. |

Sentinels have the prefix `interruptcheck:`. Diagnostics have the form `linux.interrupt.check: <object> at 0x<addr>: <what failed>`.

## 7. Result schema

One row per vector that reads, in vector order.

| Field | Type | Meaning |
|---|---|---|
| `Index` | uint64 | The vector, 0 to 255 |
| `Address` | uint64 | Handler address in the address form; 0 for a task gate |
| `Module` | string | `kernel`, a module name, or empty when unowned or none |
| `Symbol` | string | Symbol at the handler, `name+0x<offset>` inside a module (S06 7); empty when unknown |
| `Placement` | typed string | `kernel`, `kernel_init`, `module`, `unowned`, `none` |
| `Type` | typed string | `interrupt`, `trap`, `task`, `interrupt16`, `trap16`, `invalid` |
| `Selector` | uint16 | Code segment selector, or the TSS selector of a task gate |
| `DPL` | uint8 | 0 to 3 |
| `IST` | uint8 | 0 to 7; always 0 with 8-byte gates |
| `Present` | bool | The P bit |
| `Source` | typed string | `loaded` or `idt_table` (4.3) |
| `Differs` | bool | 4.3 step 3 |

## 8. Limits

No `Limits` field applies to the table: it has 256 entries (G1). The known-module set uses the S07 limits.

## 9. Acceptance

- Synthetic fixtures: a clean table with a loaded copy; a gate hooked into a module; an unowned handler; a handler in init text; a loaded copy that differs; no `idt_descr`; an unreadable vector; a `gate_struct` of the wrong size; 8-byte gates with a task gate.
- A fuzz target over the gate decoder on arbitrary bytes and both entry sizes, and one over the whole check on an arbitrary table.
- On both captures:

| Capture | Rows | Source | Differs | Present | Type | Selector | DPL 3 | IST set | `kernel` | `kernel_init` | `module` | `unowned` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mem3_ubuntu24 (6.17) | 256 | loaded | 0 | 256 | 256 `interrupt` | 256 × 0x10 | 3, 4, 0x80 | 1:3, 2:2, 8:1, 18:4, 29:5 | 247 | 9 | 0 | 0 |
| mem4_fedora40 (6.14) | 256 | loaded | 0 | 256 | 256 `interrupt` | 256 × 0x10 | 3, 4, 0x80 | 1:3, 2:2, 8:1, 18:4, 29:5 | 247 | 9 | 0 | 0 |

The `kernel_init` vectors are 22 to 28, 30 and 31 on both, at `early_idt_handler_array + v × 9` on mem3 and `+ v × 13` on mem4 (K11: 13 is 9 plus a 4-byte ENDBR). On both, 44 `kernel` handlers have an exact symbol name. The 203 without one are vectors 33 to 127, 129 to 234, 239 and 245, which point inside the `irq_entries_start` and `spurious_entries_start` stubs (K10); vectors 32 and 235 are those symbols' first entries. Measured with `idtfacts`, 2026-11-12.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | IDTR is a CPU register (G2) and a memory image does not hold it. A CPU loaded with another table after `idt_descr` was written is not seen. | A capture format that records CPU state |
| O2 | With FRED enabled (K13) the IDT is not used; the rows then describe an unused table. The image has no simple marker for it. | A FRED capture, and a rule on the CPU feature bits |
| O3 | `debug_idt_table` (K6) exists only up to v5.x and is not checked. | Owner decision: add it if a v4.19 capture joins the matrix (Q7) |
| O4 | Device-vector handlers inside `irq_entries_start` have no exact symbol, so `Symbol` is empty. A nearest-symbol name for the kernel image is not in the shared lookup. | Owner decision: a nearest-symbol kernel namer in S06 |
| O5 | 4-byte pointers (32-bit kernels, 8-byte gates, `__KERNEL_CS` 0x60, the task gate for #DF) are written from the sources only. | A 32-bit capture (Q7) |
| O6 | Field and value names (`Placement`, `Source`, `Differs`, the gate type names) are new. | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept the limit |
| O2 | Report rows, leave FRED unknown |
| O3 | Skip until a v4.19 capture joins |
| O4 | Leave Symbol empty |
| O5 | Ship as written, mark untested |
| O6 | Accept the new names |

## 11. Provenance

Author: the project, 2026-11-12. Sources: the kernel files in section 3 at the tags stated, fetched from git.kernel.org on 2026-11-12, and the Intel SDM Volume 3A, 253668-093US. Measurements: `idtfacts` on the two Linux captures. Every rule rests on the sources and measurements above.
