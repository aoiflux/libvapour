# S76: The session: opening a capture and handing tools a context

Version 1, 2026-11-12.

## 1. Purpose

Every question an examiner puts to a capture goes through one entry point: the session. It opens the file, finds which kernel ran, which page-table root and paging mode it ran on, where its image was loaded, and which symbols belong to it, and then gives every tool the same `tools.Context` (S70). A mistake here is silent everywhere else: a table for another build answers every name with wrong offsets, a wrong root reads another address space, an unmoved table points every global at an RVA. The session therefore takes each of these facts from the capture, checks it against a second fact where one exists, refuses what contradicts, and says in its diagnostics where each fact came from.

This specification covers package `libvapour` (the repository root): `OpenWindowsMemory`, `OpenLinuxMemory`, `OpenMemory`, `AnalyzeMemory`, `Session` and its methods, the views over symbol tables that move them to the running image or add measured types, and the cache of per-root address spaces. The pieces it joins are specified elsewhere: capture readers S71, paging-mode detection S04, translation and the Windows root and base finders S53, VMCOREINFO S05, kernel identification and symbol loading S75 and S32, the build reader S03, the measured tcpip layouts S28 and S67, the context and its options S70.

## 2. Inputs

| Input | Type | Use |
|---|---|---|
| Capture path | string | Opened through the file provider (S71 4.10 step 2): raw, crash dump, lime or ELF core. |
| Operating system | `"windows"` or `"linux"`, case and surrounding spaces aside | `OpenMemory` dispatch. |
| `OpenConfig.SymbolsPath` | path to a table file | An explicit table instead of identification (Windows) or assembly (Linux). |
| `OpenConfig.KernelCR3` | uint64 | When non-zero, must name the root the session finds (4.2 step 3, 4.5 step 2). |
| `OpenConfig.Strict` | bool | Option `strict`; passed to the provider, which refuses a repaired container (S71 4.10 step 2); refuses a damaged VMCOREINFO copy (4.5 step 3) and a Windows kernel base nothing confirmed (4.3 step 5). |
| `OpenConfig.PID` | uint64 | Option `pid` when non-zero. |
| `OpenConfig.CollectDiagnostics` | bool | Creates the `diagnostics` sink (S70). |
| `ProcessListSanityFilter`, `ProcessListActiveOnly`, `ProcessListCrossCheckCSV`, `ProcessListCrossCheck`, `NetworkScanIncludeCorrupt` | | Options `any.process.list.sanity_filter`, `.active_only`, `.cross_checker`, `windows.network.scan.include_corrupt`. |
| `OfflineOnly`, `SymbolLoad` | | Symbol loading (S75 4.6, S32). `OfflineOnly` in either place keeps the session off the network. |
| `PagefilePaths` | paths, index = pagefile number | Windows paged-out entries (4.2 step 5). |
| `Limits` | `limits.Limits` | Resolved once; every step uses the resolved caps (section 8). |
| `ToolOptions` | map | Checked for wrong forms at open (4.1 step 1), then copied into the context's options before the config fields (4.8). |

## 3. Facts from the sources

| # | Fact | Source |
|---|---|---|
| F1 | The paging mode is chosen by CR0.PG, CR4.PAE, CR4.LA57 and IA32_EFER.LME: processor control state, not part of an address space. | Intel SDM Vol. 3A (253668-093US) 5.3 to 5.5; S04 A1 |
| F2 | CR3 bits 11:0 are flags or the PCID; bits M−1:12 locate the root table. | SDM Vol. 3A Tables 5-12, 5-13; S04 A5 |
| F3 | A PDB places a public symbol at section `VirtualAddress` + offset, an RVA of at most 0xFFFFFFFF. | S32 4.4 step 5 |
| F4 | A CodeView RSDS record holds the PDB's GUID, age and path; the GUID and age name the build. The record is reached from the image header through the Debug data directory (seventh, at 160 in a PE32+ optional header) and a 28-byte debug directory entry of type 2. | Microsoft Learn "PE Format" (Optional Header Data Directories, Debug Directory), accessed 2026-11-12; S75 W1 to W3; S53 L1, L2 |
| F5 | The kernel's PDB is named `ntoskrnl`, `ntkrnlmp`, `ntkrnlpa` or `ntkrpamp`. | S75 W5 |
| F6 | The processor start page's CR3 equals the kernel root found from the process list on all five Windows captures. | S32 M9 |
| F7 | `KUSER_SHARED_DATA` carries `NtBuildNumber`, `NtMajorVersion`, `NtMinorVersion` at 0x260, 0x26C, 0x270; the kernel's own `NtBuildNumber` carries the build in its low 28 bits and a decoration in its top 4. | S03 B3, B4, 4.7 steps 2 to 4, O1 |
| F8 | tcpip layouts are measured for builds 14393, 19041 to 19045 and 26100; `LayoutForBuild` refuses every other build. | S28 section 3, S67 4.1 |
| F9 | Of the four Windows base methods, the list head and the process list take under 20 ms; the image scan found the base on all five captures in 0.5 to 2.6 s; the debugger data block scan found it on two of five in 1.5 to 7.8 s. | S53 9.2 |
| F10 | A paged-out entry is decoded in the pre-17134 layout only; `CheckPagefilePTELayout` accepts a table only in that layout. | S53 4.3 |
| F11 | Only the Linux kernel image window [0xFFFFFFFF80000000, 0xFFFFFFFFC0000000) moves with the KASLR shift; `SYMBOL()` values outside it are stored pointers. A table built from the image is in link-time space. | S75 L10, 4.10 steps 3 to 5; Linux `arch/x86/include/asm/page_64_types.h` at v4.19, v6.1, v6.4, v6.14, v6.17 (through S75) |
| F12 | The Linux root is `SYMBOL(swapper_pg_dir)` − 0xFFFFFFFF80000000 + `NUMBER(phys_base)`. | S05 4.4 step 6 |
| F13 | The kernel layer's user half belongs to whichever task was current when the capture was taken, so per-process reads need that process's own root. | S70 F10 |
| F14 | A capture that never changes may cache page-table entries; a reader says so through `ImmutableSnapshot`. | S71 4.1 step 4; S53 4.5 |
| F15 | An ELF core with a `CORE` note of type `NT_AUXV`, `NT_SIGINFO` or `NT_FILE` and no VMCOREINFO is one process's memory and is refused with `ErrProcessCore`. | S71 E6, 4.9 step 4 |

### Measurements

`sessionfacts` on 2026-11-12, offline, symbol tables from the user's cache. Windows `-os windows` on mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 and mem7_server2025 (26100, crash dumps); Linux `-os linux` on mem3_ubuntu24 (6.17.0-35-generic) and mem4_fedora40 (6.14.5-100.fc40.x86_64). Times are on the measuring host with the capture in the file cache.

| # | Measurement | mem1 | mem2 | mem5 | mem6 | mem7 |
|---|---|---|---|---|---|---|
| M1 | Identification method; base; root; time | start page; 0xfffff8037d130000; 0x7d5000; 273 ms | start page; 0xfffff80563400000; 0x7d4000; 16 ms | start page; 0xfffff80145019000; 0x7d2000; 34 ms | header; 0xfffff804a6ba0000; 0x7d5000; 2 ms | header; 0xfffff801a1850000; 0x7d5000; 2 ms |
| M2 | Build; table from the cache; load time | ntkrnlmp 0D960CE1…-1; 53 ms | ntkrnlmp F57E740B…-1; 38 ms | ntkrnlmp 3DFC5F72…-1; 33 ms | ntkrnlmp 953A8DE8…-1; 51 ms | same build; 41 ms |
| M3 | System process scan: root; equals M1's root; time; its Blink less `PsActiveProcessHead`'s RVA equals M1's base | 0x7d5000; yes; 1.1 s; yes | 0x7d4000; yes; 2.0 s; yes | 0x7d2000; yes; 1.9 to 6.1 s; yes | 0x7d5000; yes; 201 ms; yes | 0x7d5000; yes; 107 ms; yes |
| M4 | Paging mode on M1's root | undecided (an all-ones PDE refutes 4-level, S53 O10) | x64 | x64 | x64 | x64 |
| M5 | `_LIST_ENTRY.Flink`, `.Blink`; `_EPROCESS.Pcb`, `UniqueProcessId`, `ActiveProcessLinks`, `ImageFileName`; `_KPROCESS.DirectoryTableBase` | 0, 8; 0, 0x1d0, 0x1d8, 0x338; 0x28 | 0, 8; 0, 0x440, 0x448, 0x5a8; 0x28 | 0, 8; 0, 0x2e8, 0x2f0, 0x450; 0x28 | as mem1 | as mem1 |
| M6 | Session: open time; root; base and where from; layout | 86 ms; 0x7d5000; M1's base, from the start page, confirmed; tcpip-26100 | 65 ms; 0x7d4000; start page, confirmed; tcpip-19041-19045 | 68 ms; 0x7d2000; start page, confirmed; tcpip-14393 | 56 ms; 0x7d5000; header, confirmed; tcpip-26100 | 57 ms; 0x7d5000; header, confirmed; tcpip-26100 |
| M7 | `any.process.list` through the session: processes | 83 | 153 | 71 | 101 | 90 |

| # | Measurement | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|---|
| M8 | VMCOREINFO offset; root; paging mode; image shift | 0x1a4c000; 0x73040000; linux-x64; 0x11400000 | 0x1304000; 0x5482c000; linux-x64; 0x8000000 |
| M9 | Table assembled from the capture: kallsyms names, typed, with several addresses; `SYMBOL()` values that agree | 212684, 439, 2269; 13 | 219461, 411, 2965; 13 |
| M10 | Open time; processes listed | 1.74 s; 203 | 1.59 s; 242 |

M3 shows the scan is the costly step of a Windows open whenever it runs (up to 6.1 s on mem5 in one run) and that it adds nothing the identification did not already give on these captures: the same root, and a list head that leads to the same base.

## 4. Algorithm

### 4.1 Opening the capture (all sessions)

1. Resolve `Limits`; resolve the symbol-load options with `OfflineOnly` from either place, the resolved limits, and `MaxTableEntries` for table reads when the caller set none. Check `ToolOptions` for values of the wrong form (O7): every key S70's `ValidateOptions` reads (`pid`, `strict`, `max_dump_size`, `kernel_base`, `kernel_dtb`, `output_dir`, `paging_mode`, `windows.network.scan.layout`, `physical_memory`, `diagnostics`), the bool keys the session names (`any.process.list.sanity_filter`, `.active_only`, `windows.network.scan.include_corrupt`), `any.process.list.start_flink` as a number, and `any.process.list.cross_checker` as a `processlist.CrossChecker`. Keys only one tool reads are left to that tool. A value any of these rejects fails the open before the file is touched, all bad keys joined in one error wrapping `tools.ErrOptionType`.
2. Open the path with the file provider (S71), passing `Strict` and the limits. A process core is refused there (F15). Each provider diagnostic becomes a session note, first in order.
3. `OpenMemory` dispatches on the operating-system name; another name fails.

### 4.2 Windows: symbols, root and paging mode

1. Symbols and the identity to check them against.
   - No `SymbolsPath`: identify the kernel (S75 4.1, including the scan) and load that build's table (S75 4.6). Note the build, method and table.
   - With `SymbolsPath`: read the table, then ask for the running kernel without the scan (S75 4.1 step 4). A table naming a build and a running kernel of another build is refused (`errOtherKernelBuild`). A table naming no build is used with the running kernel's identity, noted as unchecked. With no running kernel, a table naming a build is checked against that build (method "build the symbol table names"); a table naming none is used as it is, its RVAs unmoved, with a note.
2. Builds are the same when GUID (letter case aside) and age are equal and, when both name a PDB, the names are equal letter case aside (F4).
3. Root: the identity's root when it has one (crash dump header or start page, F6, M3), else the System process scan (S53 4.8). CR3 flag bits are dropped (F2). A non-zero `KernelCR3` whose frame differs refuses the open. The root and its source are noted.
4. Paging mode: S04 on the root with the table's pointer width; undecided is read as 4-level (M4) with a note giving S04's evidence.
5. Pagefiles, when any path is non-empty: refused with a note when `CheckPagefilePTELayout` refuses the table (F10); else each non-empty path is opened as the pagefile of its index, and one that does not open fails the session.
6. Address spaces: one translator per root in the kernel's mode (F1), with the entry cache when the capture is immutable (F14) and the pagefiles when accepted. The kernel space is the one for the root.

### 4.3 Windows: kernel base

Only when the table places `PsActiveProcessHead` at an RVA (F3) and there is an identity (4.2 step 1).

1. Candidates, in this order (F9, M3): the identity's own base; the System process's Blink less the head's RVA; the walk of the active process list from the System entry; the kernel image scan by PDB name (only when the identity names a PDB); the debugger data block scan. The System process scan runs at most once and only when a candidate needs it.
2. Each candidate's image is asked for its CodeView records through the kernel space (S53 4.10).
   - A record naming the identity's build confirms the candidate; the search stops.
   - A record naming another kernel PDB (F5) refuses the session: the running kernel is found and the symbols are not its own.
   - Records naming only other PDBs: the candidate is passed over.
   - No record that reads: the first such candidate is kept as unconfirmed, and the search goes on.
3. A provisional identity (S75 4.4 step 3) must be confirmed; otherwise the session is refused (`errBaseUnconfirmed`), listing what each candidate gave.
4. A confirmed or unconfirmed base moves the table (4.4); its source is noted, with the read failure when unconfirmed. No base leaves the table unmoved, with a note listing each candidate's failure.
5. In strict mode (O4) a base nothing confirmed refuses the open (`errStrictKernelBase`): an unconfirmed base, naming its source and the read failure; no base, listing each candidate's failure; and a table that needs a base but has no build to check one against (4.2 step 1, an explicit table naming no build on a capture naming no running kernel). A table that places `PsActiveProcessHead` in the kernel half needs no base and is not refused.

### 4.4 Moving a table

A moved table answers `LookupSymbol` with the inner address plus the shift for every address its predicate accepts, and with the inner address otherwise; arithmetic is modulo 2^64. `SymbolsAt(a)` asks the inner table at `a − shift` and keeps the symbols that move, and at `a` and keeps those that do not, so both directions agree. Type, member and read calls pass through. `TableSymbols`, `SymbolNames` and `SymbolTypeRef` pass through in the table's own space, as `symbols.Symbol` documents.

- Windows predicate: an RVA, at most 0xFFFFFFFF (F3); shift: the base.
- Linux predicate: the image window (F11); shift: VMCOREINFO's `KERNELOFFSET` (S05).

### 4.5 Linux

1. Find the kernel from VMCOREINFO (S75 4.10 step 1); its notes join the session's.
2. A non-zero `KernelCR3` whose frame differs from VMCOREINFO's root (F12) refuses the open.
3. In strict mode a damaged VMCOREINFO copy refuses the open (S05 `DamageError`).
4. Table: `SymbolsPath`, or one assembled from the capture (S75 4.10 step 3) with a note of its counts (M9).
5. Move it by the shift (4.4) and check it with `CheckTable` against the table's own banner (S75 4.10 step 5). A table that fails is refused.
6. Note the release, VMCOREINFO offset, root, paging mode, shift, table source and agreement count. The kernel space is VMCOREINFO's (S75 4.10 step 2); process spaces are built with the same layout per root.

### 4.6 Address spaces and module PDBs

1. `ProcessMemory(cr3)` drops the flag bits (F2), refuses a zero frame or one at or past the capture's end, and returns one reader per frame for the whole session (a capture does not change).
2. `LoadPDB(fp)` loads each fingerprint once with the session's load options and keeps its error too, so a module the server lacks is asked for once.

### 4.7 Windows network layout

1. Read the build (S03 4.7) through the kernel space and the moved table.
2. Ask `LayoutForBuild` for the kernel build when it reads. When it does not read or has no layout, ask for the shared copy, but only when the same page reads NT version 10.0, the version of every measured layout (F7, F8). No range test is added: `LayoutForBuild` already refuses every build that was not measured.
3. A layout found is layered over the moved table and named in option `windows.network.scan.layout`; none found is a note listing each attempt.
4. A layered table answers type questions from the kernel table when it has the type and from the layout otherwise; symbols come from the kernel table alone (the layouts hold types only).

### 4.8 Options

The context's options are a copy of `ToolOptions`, then `diagnostics` (a new sink) when `CollectDiagnostics`, `strict`, `pid`, the process-list and network flags from the config, then the session's own: `physical_memory`, `kernel_dtb`, `paging_mode`, `kernel_base` (Windows, when moved), `windows.network.scan.layout`, and `any.process.list.start_flink` when the System process scan ran. Cross-check rows are a copy of `ProcessListCrossCheck` followed by the rows of `ProcessListCrossCheckCSV`; a file that does not read fails the open. The caller's map and slice are never written.

### 4.9 Diagnostics, runs and close

1. Session notes go into the `diagnostics` sink first when the options hold one; `Diagnostics` then returns a copy of the sink (session notes and every tool's lines in order). Without a sink it returns a copy of the session notes.
2. `Execute` runs one tool by name. `ExecuteAll` runs every registered tool in registry order; `ExecuteSelected` runs the names given, one row each, a name the registry lacks carrying the registry's error. Each row has the tool's spec, result, error and duration.
3. `Close` closes the capture and the pagefiles, joins their errors, and is a no-op the second time. `AnalyzeMemory` opens, runs all or the named tools, closes, and returns the close error with the report.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| An explicit table and the running kernel name the same build | F4, 4.2 step 1 | `errOtherKernelBuild`, open refused |
| A given root equals the found root, flag bits aside | F2, F6, F12 | Open refused |
| A base's CodeView record names the loaded build | F4 | Next candidate; another kernel build refuses |
| A provisional build is confirmed by a base | S75 4.4 | `errBaseUnconfirmed`, open refused |
| In strict mode, a table that needs a base has a confirmed one | O4 | `errStrictKernelBase`, open refused |
| `ToolOptions` values in the forms their readers take | S70 4.2 to 4.5, O7 | `tools.ErrOptionType`, open refused |
| A table needs a base when `PsActiveProcessHead` is an RVA | F3 | Table used as it is |
| Pagefiles only in the decoded layout | F10 | Note; paged-out pages unread |
| A process root has a frame inside the capture | F2, S53 A13 | `ProcessMemory` error |
| The shared build stands in only on NT 10.0 | F7, F8 | Note; no layout |
| A Linux table matches the banner and in-window `SYMBOL()` values | F11, S75 4.10 | Open refused |
| No damaged VMCOREINFO copy in strict mode | S05 | Open refused |

## 6. Failure modes

| Case | Result |
|---|---|
| Limits or symbol options rejected | `libvapour: open config: …` |
| Option of the wrong form | `libvapour: open config: tools: option value of the wrong form: "<key>" is <value>; want <forms>`, every bad key joined |
| File missing, unreadable, unknown container, process core | `libvapour: open capture <path>: …` (wrapping the provider's error, `memory.ErrProcessCore` among them) |
| Operating system not windows or linux | `libvapour: operating system "<name>" is not windows or linux` |
| Windows kernel not identified, symbols not loaded | `libvapour: identify the windows kernel: …`; `libvapour: load symbols for <build>: …` |
| Explicit table unreadable, or for another build | `libvapour: read symbol table <path>: …`; `libvapour: symbol table <path>: libvapour: the symbols are for another kernel build: …` |
| No root | `libvapour: find the kernel page-table root: …` |
| Root given differs | `libvapour: kernel page-table root 0x<given> was given, the capture's is 0x<root> from <source>` (Linux: `…, VMCOREINFO at 0x<offset> gives 0x<root>`) |
| Base of another build; provisional build unconfirmed | `libvapour: kernel base: …` wrapping `errOtherKernelBuild` or `errBaseUnconfirmed` |
| Strict mode, base nothing confirmed | `libvapour: kernel base: libvapour: strict mode refuses a kernel base nothing confirmed: 0x<base> from <source>: <read failure>`; `…: kernel <build>: no kernel base found (tried: …)`; `…: no kernel build to check a base against` |
| Strict mode, repaired container | `libvapour: open capture <path>: …` wrapping `memory.ErrStrictRepair` (S71) |
| Pagefile does not open | `libvapour: open pagefile <n> <path>: …` |
| Cross-check file | `libvapour: process cross-check file <path>: …` |
| Linux kernel not found, strict damage, table mismatch | `libvapour: find the linux kernel: …`; `libvapour: strict mode: …`; `libvapour: symbol table <source> does not match the kernel: …`; `libvapour: no symbol table given and none assembled from the capture: …` |
| Process root unusable | `libvapour: page-table root 0x<v> has no frame`; `… is past the capture's end 0x<size>` |

Every failure after the capture opens closes it and any pagefile before returning. Notes, not failures: undecided paging mode, refused pagefiles, no or unconfirmed base (outside strict mode), no network layout, an unchecked explicit table.

## 7. Result schema

The exported API is unchanged: `Version` ("0.1.0", tied to the README status line), `Limits` (the `limits` type), `OpenConfig` and its fields, `Session` with `Context`, `Execute`, `ExecuteAll`, `ExecuteSelected`, `Diagnostics`, `Close`, `ToolExecution{Spec, Result, Error, Duration}`, `ExecutionReport{Tools, Diagnostics, TotalDuration}`, `OpenWindowsMemory`, `OpenLinuxMemory`, `OpenMemory`, `AnalyzeMemory`. The context is S70's `tools.Context` with the options of 4.8. Diagnostic lines start `libvapour: ` (or `memory: ` for the provider's, `linuxkernel`'s own for VMCOREINFO copies), lowercase, no trailing period.

## 8. Limits

| Limit | Use |
|---|---|
| All of `Limits` | Resolved once (4.1 step 1) and handed to the provider, identification, VMCOREINFO, symbol reads and the context. |
| `MaxTableEntries` | Table reads when the symbol options set none. |
| `PTECacheEntries` | Each address space's entry cache (S53 4.5). |
| `MaxListEntries` | The process-list base candidate (S53 4.9). |

The session adds no limit of its own. Cached address spaces are one per distinct root a run asks for, bounded by the processes the tools visit.

## 9. Acceptance

1. Synthetic Windows captures (`s76_fixture_test.go`): 4-level tables after S53 P1 and P2, a kernel image whose header carries a CodeView record (F4), `PsActiveProcessHead`, a System process with the 26100 member offsets (M5), and optionally a start page (S32 4.7), a `NtBuildNumber` and a paged-out entry. Tests (`s76_windowssession_test.go`): root and base from the System scan with the table's own build, the start entry set; root and base from the start page with a cached table, offline, no request made, no scan; another build refused both at the base and against the running kernel; a table naming no build following the running kernel, and left unmoved without one; a given root with flag bits accepted and another refused; pagefiles read in the 14393 layout, refused in the 19045 layout, a missing file failing only when accepted; the network layout from the kernel build with kernel types and symbols still answered; options from the config over the map, the caller's map and slice untouched, a bad cross-check file refused; diagnostics in the sink in order and returned as copies; one row per tool asked for, `ExecuteAll` over the whole registry including `windows.module.list`; a second close; `AnalyzeMemory`; in strict mode a confirmed base opening, and no base, an unconfirmed base and a table with no build to check against refused, each opening outside strict mode; options of the wrong form for each checked key refused before the file is opened, every bad key named, and good options with an unknown key accepted.
2. Synthetic Linux captures (`s76_linuxsession_test.go`, on `linuxkernel/linuxtest`): the image window moved and a stored pointer not, a process space reading the banner, notes; another banner, no banner and `_stext` elsewhere refused; a given root; a damaged copy noted, refused when strict; no VMCOREINFO.
3. Parts (`s76_parts_test.go`): the address-space cache, pagefile numbering, both table views, every base-candidate outcome, the explicit-table rules, build comparison and PDB base names, every network-layout choice, the module-PDB memo for a table and for a failure, and each open refusal including a process core (an ELF header and PT_NOTE after the gABI, F15).
4. Fuzz target `FuzzMovedTableAgreesWithItself` (any shift and two addresses: every symbol `LookupSymbol` gives is named by `SymbolsAt` at that address), 30 s on 2026-11-12: 1,774,724 executions, no failure.
5. On the captures (M6 to M10): all seven open offline; the Windows sessions take root and base from the identification, confirm the base by its CodeView record, need no System scan, and open in 56 to 86 ms; each gets the layout of its build; every session lists the processes of M7 and M10.
6. Real-image tests (`-tags realimage`) compile.
7. Strict mode on the captures (`sessionfacts -strict`, 2026-11-12, offline): mem1, mem2, mem5 and mem7 open with a confirmed base (from the start page on the first three, the crash dump header on mem7); mem6 is refused at the capture (`memory.ErrStrictRepair`, run 240 recounted, S71 C4); mem3 and mem4 open. In strict mode `any.process.list` stops on mem2, mem5, mem7 and mem4 at its own strict list checks (S70 `StrictMode`); that is the tool's behaviour, not the session's.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The root comes from the crash dump header or start page when the identification has one. The header's root equals the System root on mem6 and mem7 (M3), but no Microsoft document says which process's root a dump header records; on a dump taken in another process's context, the kernel space's user half would be that process's (F13). | Owner decision (default: use it); a dump taken from a user process context |
| O2 | `any.process.list.start_flink` is set only when the System scan ran; with a moved table the list tool walks `PsActiveProcessHead` and does not use it. | Owner decision |
| O3 | `KernelCR3` is now checked on Windows too; before it was read only by Linux sessions. | Owner decision |
| O4 | Strict mode does not refuse an unconfirmed or absent Windows kernel base; only notes say so. | Owner decision: refuse in strict mode. Owner decision 2026-11-12: refuse in strict mode. Done: an unconfirmed base, no base, and a table needing a base with no build to check it against refuse a strict open with `errStrictKernelBase` (4.3 step 5); windows_session.go, s76_windowssession_test.go; measured in acceptance 7. |
| O5 | The capture provider's diagnostics (`memory: … opened as …`, container repairs) are now session notes. | Owner decision (Q2) |
| O6 | Diagnostic and error texts are this specification's (section 6). | Owner decision (Q2) |
| O7 | Options of the wrong form fail when a tool reads them, not at open, so a run of many tools still runs the others. | Owner decision: validate at open. Owner decision 2026-11-12: validate at open. Done: `ToolOptions` is checked before the file is opened for every key the shared readers and the session name (4.1 step 1); keys only one tool reads are still checked by that tool, since no registry of per-tool keys exists; session.go, s76_windowssession_test.go. Owner decision 2026-11-12 (follow-up D18): a registry of per-tool option keys is deferred to v0.2.0. |
| O8 | `OpenConfig.PID` 0 means "not set", so PID 0 can be asked for only through `ToolOptions["pid"]` (S70: `pid` 0 is PID 0). | Owner decision on the field |
| O9 | The root package imports `windows.module.list` only so that a program importing nothing else can run it. | Owner decision: register no tool or every tool |
| O10 | `AnalyzeMemory` returns a close failure with the report; before, it dropped it. | None; behaviour change |
| O11 | Base candidates try the image scan before the debugger data block scan (F9). | None; order change |
| O12 | An explicit table that names no build, on a capture that names no running kernel, is not moved, though a list-head base might be found; nothing could confirm it. | Owner decision |
| O13 | Every Windows session gets the x64 profile, and an undecided mode is read as 4-level even for a 4-byte-pointer table; no 32-bit capture was measured. | A 32-bit capture (Q7) |
| O14 | The network build range test (10240 to 30000) was dropped: `LayoutForBuild` refuses unmeasured builds (F8). | None |
| O15 | The new sentinels `errOtherKernelBuild` and `errBaseUnconfirmed` are unexported; callers see them only in the text. | Owner decision: export them |
| O16 | The empty `doc.go` was removed; the package has no package comment. | None |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Use the header root |
| O2 | Only after scan |
| O3 | Check |
| O4 | Refuse in strict mode |
| O5 | Session notes |
| O6 | Accept |
| O7 | Validate at open |
| O8 | Keep, use ToolOptions |
| O9 | Keep one tool |
| O10 | Return it |
| O11 | Image scan first |
| O12 | Do not move |
| O13 | x64 profile |
| O14 | Stay dropped |
| O15 | Keep unexported |
| O16 | No package comment |

## 11. Provenance

Author: the project, 2026-11-12. Sources: Intel SDM Vol. 3A (253668-093US) paging chapter; Microsoft Learn "PE Format" (accessed 2026-11-12); the ELF gABI header and program header; the Linux kernel headers through S05 and S75 at v4.19, v6.1, v6.4, v6.14 and v6.17; the ntkrnlmp PDB types and symbols of builds 14393, 19045 and 26100 through the project's tables; the project's specifications S03, S04, S05, S28, S32, S53, S67, S70, S71 and S75; and the measurements of section 3 with `sessionfacts`. No other analysis tool's source, table or output was read; the files replaced were read only for their exported names and callers. Reviewer: pending.
