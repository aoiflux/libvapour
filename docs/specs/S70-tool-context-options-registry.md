# S70: Tool context, options and registry

Version 1, 2026-11-12.

## 1. Purpose

Every tool receives the same thing from a session: the kernel's address space, its symbols, a profile, the session's options, a way to reach a process's address space, a PDB loader and the resource caps. Every tool also needs the same small services: typed reads of its options, the process filter, a pattern filter, a place to report what it could not read, and, for the Windows pool scans, a check that the kernel is one the scans are measured on. A tool is found and run by name.

This specification defines that contract once, so that each tool decides only what is its own. It covers package `tools` at its top level: the context, the option readers and the options the context itself owns, the PID set, the pattern option, the pool-scan setup, the tool registry and the page size. It does not cover what any tool reads from an image.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | `memory.MemoryReader` for kernel virtual addresses. Required. |
| Symbol table | The kernel's types and globals. Required. |
| Profile | The image's platform and pointer size. Required. |
| Options | A map from key to value, shared by the session and every tool it runs. Values may come from a program or from text typed by an examiner. |
| Process memory | Optional factory from a page-table root to a process's address space. |
| PDB loader | Optional factory from a CodeView fingerprint to a symbol table (S32). |
| Limits | `limits.Limits`, used here through `Bounds()`; `MaxArtifactBytes` caps `DumpLimit` (4.5) and every field reaches the kernel frame map (4.8). |

Options owned by this package. The keys are kept from release 0.1.0 (owner decision Q2, section 10).

| Key | Value | Set by |
|---|---|---|
| `pid` | PID set (4.3) | Examiner |
| `strict` | bool | Examiner |
| `diagnostics` | `*[]string` sink | Session |
| `output_dir` | string | Examiner |
| `max_dump_size` | unsigned integer, bytes | Examiner |
| `physical_memory` | `memory.MemoryReader` | Session |
| `kernel_base` | unsigned integer, address | Session |
| `kernel_dtb` | unsigned integer, physical address | Session |
| `paging_mode` | string, a `layers` paging-mode name | Session |
| `windows.network.scan.layout` | string, the measured layout's name | Session |

The image is untrusted. Option values typed by an examiner may be anything.

## 3. Facts from the sources

| # | Fact | Source |
|---|---|---|
| F1 | A 4-level or 5-level paging entry that maps a page with no larger page size maps a 4-KByte page. Bits 11:0 of a linear address are the offset into it. | Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 3A (order number 253668-093US), chapter 5 "Paging", 4-level and 5-level paging translation figures. |
| F2 | x86 Linux uses a page shift of 12: `#define PAGE_SHIFT 12` in `arch/x86/include/asm/page_types.h` at v4.19, v6.1 and v6.4. At v6.14 and v6.17 `PAGE_SHIFT` is `CONFIG_PAGE_SHIFT` (`include/vdso/page.h`), which `arch/Kconfig` sets to 12 for `PAGE_SIZE_4KB`, the only page size `arch/x86/Kconfig` offers (`select HAVE_PAGE_SIZE_4KB`). | Linux, the files named, at the five tags. |
| F3 | `GetProcessId` returns a `DWORD`. | Microsoft Learn, "GetProcessId function (processthreadsapi.h)", accessed 2026-11-12. |
| F4 | Linux limits PIDs to `PID_MAX_LIMIT`: 4 × 1024 × 1024 on 64-bit kernels, at most `PAGE_SIZE * 8` or 0x8000 otherwise. | Linux `include/linux/threads.h` at v4.19, v6.1, v6.4, v6.14 and v6.17. |
| F5 | Windows 8 and Windows Server 2012 are version 6.2. Windows 7 is 6.1. Windows 10 and later report 10.0. Windows 2000, version 5.0, is the oldest entry. | Microsoft Learn, "Operating System Version", page dated 2020-09-15, accessed 2026-11-12. |
| F6 | The same page advises testing for the feature rather than the version where a feature can be tested. | As F5. |
| F7 | `KUSER_SHARED_DATA` carries `NtMajorVersion`, `NtMinorVersion` and `NtBuildNumber`; the kernel's own `NtBuildNumber` carries the build. The S03 reader returns each value with its own error. | S03, B3 to B5, 4.7. |
| F8 | Object headers have `InfoMask` from Windows 8 on. Tables without it are older and were not measured; the pool scans refuse those builds. | S31, O3. |
| F9 | The pool scans resolve the pool header and object header layouts from the table (`scan.ResolvePoolHeaderLayout`, `scan.ResolveObjectLayout`), the minimum allocation for a filter (`MinimumSize`), a kernel-mapping residency (`WithResidency`) and the type identity (`scan.ResolveObjectIdentity`). | S31. |
| F10 | CR3 holds the physical address of the top paging structure of the task current on the processor. The session's kernel layer is built from the CR3 value found at acquisition (S04, S53), so its user half is that task's. | Intel SDM Vol. 3A, chapter 5, CR3 format tables. |
| F11 | Go's `regexp` package implements RE2 syntax, and the `(?i)` flag makes the match case-insensitive. | Go standard library documentation, packages `regexp` and `regexp/syntax`, Go 1.26. |
| F12 | Tool names follow `platform.subject.verb`. | Owner decision 2026-11-10. |
| F13 | An option of the wrong type is an error (2026-11-03). `pid` 0 means PID 0, an empty `pid` list is an error, and patterns use RE2 (options matrix, 2026-11-07). Strict mode fails on the first unreadable read. Limits caps are enforced and diagnosed. | Owner decisions. |

### Measurements

M1 to M4 come from `toolcorefacts`, run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100), and over mem3_ubuntu24 (6.17) and mem4_fedora40 (6.14) for M3.

| # | Measured |
|---|---|
| M1 | The tree registers 142 tools: 12 `any`, 41 `linux`, 89 `windows`. Every name has exactly three dot-separated parts, each a lowercase letter followed by lowercase letters, digits or `_`. Every tool has a description. |
| M2 | On all five Windows captures: NT version 10.0, kernel build equal to the shared build (26100, 19045, 14393, 26100, 26100), decoration 0xF. The pool-scan gate passes. Every table has `ObHeaderCookie`. `_MMPTE_HARDWARE.PageFrameNumber` starts at bit 12. |
| M3 | Each session context passes `Validate`. Windows sessions set `diagnostics` (`*[]string`), `kernel_base`, `kernel_dtb` (`uint64`), `paging_mode`, `windows.network.scan.layout` (`string`) and `physical_memory` (a file reader, or a crash-dump reader on the two Server 2025 captures). Linux sessions set `kernel_dtb`, `paging_mode` and `physical_memory`. |
| M4 | Kernel frame map: 1,895, 1,539, 415, 1,566 and 1,698 page tables; 19 unreadable on mem1 and none elsewhere; no partly-present large page on any capture; built in under 1.4 s each. The pool header is 0x10 bytes with the tag at 0x4 and 0x10 alignment; the object header body is at 0x30, optional headers reach 0xd0; the process allocation minimum is 0x880 (26100), 0xa80 (19045) and 0x7f0 (14393). |

## 4. Algorithm

### 4.1 Context

1. `Validate` checks, in order: kernel memory present (`ErrMissingMemoryReader`); Limits resolve (`limits.Error`); symbol table present (`ErrMissingSymbolTable`); profile present (`ErrMissingProfile`); then every option of section 2 reads (4.2). Each tool calls it before it reads.
2. `Bounds` returns the resolved Limits, or the defaults when they do not resolve. `Validate` has already reported a bad value; `Bounds` must still give caps.
3. `ProcessSpace(root)`: with no factory the kernel reader is returned, because such a session has one address space. With a factory, its reader is returned. A factory error or a nil reader gives `ErrProcessSpaceUnavailable` and never the kernel reader: the kernel layer was built from the CR3 the capture caught (F10), so its user half belongs to whichever process ran, and reads through it would give that process's pages under another's name.
4. `AddDiagnostic` formats one line into the `diagnostics` sink. With no sink, the line is dropped: a caller that asked for none wants none.
5. `StrictMode` is true when `strict` reads true, and also when `strict` does not read. A strict reading that fails stops a run; a lax one that fails hides gaps. The tools decide what strict mode stops: per owner decision, strict mode fails on the first unreadable read.
6. `WithoutPIDFilter` returns a context whose options map is a copy without `pid`. Setup reads that must see every process (a symbol resolved through one chosen process) use it. The copy shares every value, so the diagnostics sink is the same.
7. `Execute` records the running tool's name; `Running` returns it, so that shared helpers can name the tool in diagnostics.

The context is not safe for concurrent use: tools keep result caches in the shared options map, and the sink is appended to without a lock. One context per goroutine; the readers may be shared.

### 4.2 Option readers

Each reader returns the zero value and no error for an absent key. A present value that is not one of the forms below is an error that wraps `ErrOptionType` and names the key, the value and the forms wanted (owner decision: an option of the wrong type is an error). Unknown keys are not errors, because every tool reads the same map.

| Reader | Forms accepted |
|---|---|
| `BoolOption` | `bool`; a string that, trimmed and lowercased, is `true`, `1`, `yes`, `on` (true) or `false`, `0`, `no`, `off` (false). |
| `UintOption` | Any Go integer kind holding a value of 0 or more; a string that, trimmed, is decimal digits, or `0x` or `0X` followed by hex digits, within 64 bits. It also reports whether the key was present. |
| `StringOption` | `string`. |
| `StringListOption` | `[]string`; a string, split at `,`. Items are trimmed and empty items dropped. |
| `UintListOption` | `[]uint64`; `[]int` with no negative item; a string split at `,` with each non-empty trimmed item in the `UintOption` string form. Empty items are dropped. |
| `PatternOption` | 4.4. |

Leading-zero octal is not accepted as octal: `010` is ten, as an examiner reading a decimal PID list expects. A float is refused even when whole, because it cannot carry every 64-bit address exactly.

### 4.3 PID set

1. Absent `pid`: every process.
2. Forms: one value in a `UintOption` form; `[]uint64`; `[]int` with no negative item; a string split at `,` in which every trimmed item is in the `UintOption` string form.
3. An empty item, an empty list, or an empty string is an error (owner decision: an empty `pid` list is an error). Unlike other lists, an empty PID item is not dropped: `4,,8` is more likely a typing slip than a request, and dropping items narrows a filter silently.
4. A PID above 0xFFFFFFFF is an error. No Windows process can have one (F3), and no Linux one (F4).
5. `0` means PID 0, the idle process (owner decision).
6. `PIDs()` returns the set. When the option does not read it returns a set that keeps nothing, so a tool that skipped `Validate` reports no process instead of every process.
7. `Key()` is `""` for every process, `"unread"` for the unreadable set, and otherwise the PIDs in ascending decimal joined by `,`. Two equal filters have equal keys, so a tool can key a cache by it.

### 4.4 Pattern option

1. Read the key as a string (4.2). An empty string means no pattern.
2. Prefix `(?i)` when the caller asks for case-insensitive matching (F11), and compile with Go `regexp`, which is RE2 (owner decision). RE2 runs in time linear in the input, so a pattern from the examiner cannot stall a scan of a large image.
3. A compile error wraps `ErrOptionType` and names the key and the examiner's pattern, without the prefix.

### 4.5 Session values

| Accessor | Rule |
|---|---|
| `OutputDir` | The `output_dir` string and true; false when absent, empty or not a string. No default: a tool that writes files and has no directory fails instead of choosing a place on the examiner's disk. |
| `MaxDumpSize` | `max_dump_size`, or 0 when absent or unreadable. |
| `DumpLimit` | The smaller of `max_dump_size` (when above 0) and `Bounds().MaxArtifactBytes`. The Limits cap holds even when the option asks for more (owner decision: Limits caps are enforced). |
| `PhysicalMemory` | The `physical_memory` reader, or nil. |
| `KernelBase`, `KernelDTB` | The value and true; false when absent or unreadable. |
| `PagingMode`, `NetworkScanLayout` | The string, or `""`. |

### 4.6 Pool-scan build gate

`RequirePoolScanBuild(tool)`:

1. With no kernel memory or no symbol table, pass: `Validate` reports those.
2. Read the build with the S03 reader (F7).
3. The NT version is read when `VersionErr` is nil and the major version is not 0. A zero major is a page of zeros, not a version: F5 lists no version below 5.0.
4. The kernel build is read when `KernelErr` is nil and the build is not 0.
5. With the version read, refuse versions below 6.2 (F5, F8). The version is preferred because it is the documented member (F7); the build split rests on S03 O1.
6. Else with the build read, refuse builds below 9200 (section 10, O1).
7. Else pass, with the diagnostic `<tool>: windows build unread; pool scan not gated by build: <reason>`. The scan's own layout checks (4.7) still refuse a table without the members it needs.
8. A refusal is `<tool>: windows <major.minor or "unread"> build <build or "unread">: ErrPoolScanUnsupportedBuild`. It is returned and added as a diagnostic, so a run that collects diagnostics shows why the scan has no rows.

`HasObjectHeaderCookie` is true when the table has the global `ObHeaderCookie` (S31 T7, O4; M2).

### 4.7 Pool-scan setup

`StructureScan(tool, filters...)` and `ExecutiveScan(tool, filter, tag)`:

1. Run the gate (4.6); its refusal is returned.
2. Resolve the pool header layout (structure scan) or the object layout (executive scan) from the table (F9). A failure is returned as `<tool>: pool header layout: %w` or `<tool>: object layout: %w`.
3. For each filter, compute `MinimumSize`. A failure (the body type is missing) is returned as `<tool>: pool tag "<tag>": <error>` and added as a diagnostic with `; pool scan not run` after it.
4. Build the kernel frame map (4.8) and attach it as the residency. When it cannot be built, the scan runs without it and the diagnostic says what that loses: duplicate allocations are not ranked by kernel mapping, and, for an executive scan, the TypeIndex test by address is skipped. When page tables were unreadable, or large pages only partly present, the counts are reported the same way, since frames reached only through them count as unmapped.
5. Executive scan only: resolve the object identity (F9). A failure is a diagnostic, and the scan matches on the body type tag only.

A missing residency or identity weakens a check but does not stop the scan. Each gap gets a diagnostic, because a silently skipped check would read as a clean result.

### 4.8 Kernel frames

`KernelFrames` maps the kernel's page tables from `physical_memory`, `kernel_dtb` and the paging mode named by `paging_mode`, with the context's Limits, through `layers.MapFrames` (S53). Each missing input is its own error.

### 4.9 Registry

1. `Register(spec, run)` refuses a name not of the form of M1 and F12 (three dot-separated parts, each `[a-z][a-z0-9_]*`), a nil run function, and a name already registered (`ErrToolAlreadyRegistered`). `MustRegister` panics on the same refusals, for registration in `init`.
2. `Get(name)` returns the tool or `ErrToolNotFound`.
3. `List()` returns every spec sorted by name, so every listing and every run of all tools has one order.
4. `Execute(ctx, name)` finds the tool, records its name in the context (4.1 step 7) and runs it. A panic in the tool is recovered: `Execute` returns a nil result and an error wrapping `ErrToolPanicked`, naming the tool and the panic value (wrapped too when it is an error). The stack is not put in the message (O5).
5. The registry is guarded by a read-write lock: registration happens in `init`, lookups at any time.

### 4.10 Page size

`PageSize` is 0x1000 (F1, F2, M2). It is the translation granule of every supported image. Larger pages are runs of it.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Option values in the forms of 4.2 and 4.3 only | Owner decision (wrong type is an error); an unreadable PID filter read as unset would widen the output to every process | `ErrOptionType` |
| PID at most 0xFFFFFFFF | F3, F4 | `ErrOptionType` |
| At least one PID, no empty item | Owner decision | `ErrOptionType` |
| NT version at least 6.2, else kernel build at least 9200 | F5, F8, O1 | `ErrPoolScanUnsupportedBuild` |
| Tool names of three lowercase parts, unique | F12, M1 | Registration error |

## 6. Failure modes

| Condition | Result |
|---|---|
| No kernel memory, symbol table or profile | `ErrMissingMemoryReader`, `ErrMissingSymbolTable`, `ErrMissingProfile` |
| Limits out of range | `*limits.Error` from `Validate`; defaults from `Bounds` |
| Option of the wrong form | `ErrOptionType`, naming key, value and wanted forms; all bad options are joined |
| Process space not built | `ErrProcessSpaceUnavailable`, wrapping the factory's error or naming the root |
| Unknown tool | `ErrToolNotFound`, naming it |
| Duplicate tool | `ErrToolAlreadyRegistered`, naming it |
| Tool panics during `Execute` | `ErrToolPanicked`, naming the tool and the panic value; no stack |
| Build before Windows 8 | `ErrPoolScanUnsupportedBuild` and a diagnostic |
| Build unread | Diagnostic; the scan runs |
| Pool or object layout unresolved | Error |
| Filter body type missing | Error and diagnostic |
| Kernel frames not built, tables unreadable, large pages partial | Diagnostic; the scan runs with what it has |
| Object identity unresolved | Diagnostic; the scan matches on the body tag |

Messages are lowercase with no trailing period. Leaf errors start with `tools:`, diagnostics with the tool's name.

## 7. Result schema

| Export | Form |
|---|---|
| `Context` | Fields `Memory`, `Symbols`, `Profile`, `Options`, `ProcessMemory`, `LoadPDB`, `Limits` |
| `PIDSet` | `All() bool`, `Keep(pid uint64) bool`, `Key() string` (4.3) |
| `Spec` | `Name`, `Description` |
| `RegisteredTool` | `Spec`, `Run(Context) (any, error)` |
| `RunFunc` | `func(Context) (any, error)` |
| `PageSize` | 0x1000 |

Every exported name, signature, option key and sentinel of release 0.1.0 is kept. `ErrToolPanicked` is new (O5).

## 8. Limits

`Bounds()` gives every tool its caps. This package enforces `MaxArtifactBytes` through `DumpLimit` (4.5) and passes the whole set to the kernel frame map (4.8), which enforces its own. No loop in this package depends on image data.

## 9. Acceptance

1. `toolcorefacts` on the seven captures: every session context validates (M3); the gate passes on the five Windows captures (M2); the registry lists 142 tools in name order, all in the 4.9 form (M1).
2. Option fixtures: every accepted form of each reader, and one refused value per form, each wrapping `ErrOptionType` and naming its key.
3. PID fixtures: absent, single, list, text with hex, PID 0, empty string, empty item, empty list, negative, above 0xFFFFFFFF, wrong type; `Keep` of an unread set; `Key` order.
4. Pattern fixtures: empty, valid, case folding, invalid RE2 (a back-reference) naming the examiner's text.
5. Gate fixtures over a synthetic table: 6.1 refused, 6.2 and 10.0 passed, version unread with build 7601 refused and 9200 passed, nothing read passing with a diagnostic, a zero major falling back to the build.
6. Pool-setup fixtures: refused build, missing pool header, missing body type with its diagnostic, no physical layer with its diagnostic.
7. Registry fixtures: bad names, nil run, duplicate, unknown name, sorted list, `Running` during a run; a text panic and a runtime panic each return `ErrToolPanicked` naming the tool, the runtime error reachable with `errors.As`, and no stack text.
8. `ProcessSpace` never returns the kernel reader when a factory fails or returns nil.
9. A source check that no tool reads `pid` except through `PIDs`.
10. Fuzz targets over the text forms of `UintOption`, `UintListOption`, the PID option and `PatternOption`: no panic; an accepted PID text gives a set whose `Key` parses back to the same set.

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | The kernel-build threshold 9200 (used only when the NT version does not read) has no Microsoft Learn page that states it; only Learn community answers quote "6.2.9200". It agrees with S03 4.8. | Owner decision: keep 9200, or refuse every build below 10240 (the first Windows 10 build) when the version is unread. A Windows 8 capture would also settle it. |
| O2 | Option keys and the bool words (`yes`, `on` and their opposites) are kept from release 0.1.0. | Owner decision Q2. |
| O3 | `StrictMode` reads an unreadable `strict` as strict. `Validate` reports the value first, so only a tool that skips `Validate` sees the difference. | Owner decision. |
| O4 | `DumpLimit` now holds `max_dump_size` to `MaxArtifactBytes`. Before, the option could exceed the cap. | Owner decision. |
| O5 | `Execute` does not recover a tool's panic; a panic on hostile data ends the caller's run. | Owner decision: recover and return an error, or leave panics visible. Owner decision 2026-11-12: recover and return error. Done: `Execute` recovers and returns `ErrToolPanicked` naming the tool and the panic value, without the stack (4.9 step 4, section 6, acceptance 7); tools/registry.go, tools/registry_test.go. |
| O6 | A float option value is refused even when whole (4.2). Options decoded from JSON arrive as float64. | Owner decision, if the options gain a JSON front end. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep 9200 |
| O2 | Keep |
| O3 | Strict |
| O4 | Cap it |
| O5 | Recover and return error |
| O6 | Refuse floats |

## 11. Provenance

Author: the project, 2026-11-12. Sources: as cited in section 3, with access dates; Linux files fetched from git.kernel.org at the five tags on 2026-11-12. Measurements: `toolcorefacts` on the seven captures named in section 3. Every rule rests on the sources and measurements above.
