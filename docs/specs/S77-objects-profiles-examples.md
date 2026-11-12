# S77: Typed objects, profiles and the example programs

Version 1, 2026-11-12.

## 1. Purpose

A program built on libvapour needs three things this specification covers. It needs to read a kernel structure by member name, through the symbol table, without working out offsets and widths itself (`objects`). It needs to know which operating system and pointer width a session targets (`profiles`). And a reader learning the library needs short programs that open a capture, run a few tools and print what they found in a way a terminal cannot be tricked by (`examples/` and their shared helper `examples/internal/cli`).

Covered: `objects` (`doc.go`, `object.go`), `profiles` (`doc.go`, `profile.go`), `examples/internal/cli` (`cli.go`, `text.go`), and the programs `memory`, `network`, `processes`, `processlist`, `registry`, `timeline` and `triage` (`doc.go`, `main.go` each). Not covered: `examples/showcase` (S78) and the root package (S76).

## 2. Inputs

| Part | Input |
|---|---|
| `objects` | A `memory.MemoryReader`, a `symbols.SymbolTable`, a record name and the record's address. Member names from the caller. |
| `profiles` | None. |
| `cli` | Command-line flags; strings, numbers and times from tool rows, any of which may hold bytes from the image. |
| Programs | One capture path and the flags of section 7.3. Each program uses only `libvapour.OpenMemory` or `libvapour.AnalyzeMemory`, `libvapour.OpenConfig` (`PID`, `ToolOptions`, the process-list fields) and the typed `Run` functions of the tools it names. |

Limits: none of its own. The programs run with the session's default `Limits`.

## 3. Facts from the sources

### 3.1 Symbol tables (project format, S58)

`symbols/FORMAT.md`, format 1, and the `symbols` package API.

| # | Fact |
|---|---|
| F1 | A record member has an offset in bytes from the start of the record and a type expression: a name, `*T` (pointer to T), `[N]T` (array of N elements; `[0]T` a trailing array of no declared length), or `@O:L T` (L bits from bit O of a T storage unit). `*` alone is a pointer to a type the table does not name, such as a function. |
| F2 | `pointer_width` is 4 or 8, the bytes in a pointer. `SymbolTable.ReadPointer` reads that many bytes. |
| F3 | `symbols.ResolveIntField` gives a member's width (from the table's `FieldSizer` or its type expression) and its bit range; `IntField.Read` reads exactly that width and cuts a bitfield out of its unit. A width outside 1..8 is refused. |
| F4 | `TypeRef` carries the innermost name at every level, and `Element` the level below. `SymbolTable.Struct(name)` succeeds only for a record. |
| F5 | A missing member is `symbols.UnknownFieldError`. |

### 3.2 Pointer width of the targets

| # | Fact | Source |
|---|---|---|
| P1 | "In the LLP64 data model, only pointers expand to 64 bits; all other basic data types (integer and long) remain 32 bits in length." | Microsoft Learn, "Abstract Data Models", updated 2025-03-13, accessed 2026-11-12 |
| P2 | `#if defined(__x86_64__) && !defined(__ILP32__)` defines `__BITS_PER_LONG 64`, and `uintptr_t` is `typedef unsigned long`. | `arch/x86/include/uapi/asm/bitsperlong.h` and `include/linux/types.h` at v4.19, v6.1, v6.4, v6.14 and v6.17 |
| P3 | Measured: the kernel symbol table's pointer width is 8 on mem1, mem2 (Windows) and mem3, mem4 (Linux) (M1). |

### 3.3 Terminal text

| # | Fact | Source |
|---|---|---|
| T1 | Columns 0 and 1 of the ASCII table (0x00..0x1F) are control characters; 2/0 (0x20) is SP; 7/15 (0x7F) is DEL, "used primarily to 'erase'". The graphic characters are 0x21..0x7E. | RFC 20, sections 2, 4.1 and 5.2 |
| T2 | "`\x` followed by exactly two hexadecimal digits; `\u` followed by exactly four hexadecimal digits; `\U` followed by exactly eight hexadecimal digits"; `\n`, `\r`, `\t` and `\\` are single-character escapes. | The Go Programming Language Specification, "Rune literals", language version go1.27 (2026-05-26), accessed 2026-11-12 |
| T3 | A date-time is written `full-date "T" full-time`, `Z` for UTC. | RFC 3339 section 5.6 |

### 3.4 Tools the programs run

Names and option keys are the registered ones: `any.process.list` (S25), `any.process.tree` and `any.process.read_arguments` (S56, S61), `windows.module.list` (S55), `linux.module.list` (S07), `windows.library.list` and `linux.library.list` (S56, S61), `windows.thread.list` (S50), `any.memory.list` (S24, S39), `windows.process.dump` and `windows.memory.dump` (S68, S73), `windows.registry.read_key` with `windows.registry.read_key.hive`, `.path`, `.recurse` (S63), `windows.network.list` and `windows.network.scan` (S28), `linux.socket.list` (S13), `any.timeline.list` with `any.timeline.list.tool_filter`, `.create_bodyfile` and `output_dir` (S60), `any.memory.find_code` (S35), `windows.process.compare` (S26), `windows.library.compare` (S56). Row fields used are those each spec's section 7 defines. Two row rules matter here:

- R1. A Windows `any.memory.list` row sets `PathUnreadable` also when the range maps no file (S24 O8). A Linux row sets it only when the name could not be built (S39).
- R2. A `windows.library.compare` row with `LoaderListsEmpty` says nothing through its three list flags.

### 3.5 Measurements

`objectfacts` and the seven programs, built and run on the captures present on 2026-11-12: mem1 (Windows 11, 26100), mem2 (Windows 10, 19045), mem3 (Ubuntu, 6.17), mem4 (Fedora, 6.14). mem5, mem6 and mem7 were not present.

- **M1 Profiles.** Every session reports `windows-x64`/`windows` or `linux-x64`/`linux`, pointer 8, and a symbol table of pointer width 8.
- **M2 Objects on Windows (mem1, mem2).** From `PsInitialSystemProcess`: `_EPROCESS.UniqueProcessId` by `Uint64` is 4; by `Uint32` it is refused (8 bytes wide). `ImageFileName` by `Bytes(15)` is `System`; `Bytes(16)` is refused (15-byte member). `Peb` is `ErrNullPointer`. `Struct("Pcb")` then `Uint64("DirectoryTableBase")` gives 0x7d5000 (mem1) and 0x7d4000 (mem2). `Struct("ActiveProcessLinks")` then `Pointer("Flink")` gives a `_LIST_ENTRY`.
- **M3 Objects on Linux (mem3, mem4).** From `init_task`: `pid` by `Uint32` is 0, `comm` by `Bytes(16)` is `swapper/0`, `Bytes(17)` is refused, `mm` is `ErrNullPointer`, `real_parent` leads back to `init_task` itself (pid 0), and `Struct("tasks")` then `Pointer("next")` gives a `list_head`.
- **M4 Programs.** Table 9.2.

## 4. Algorithm

### 4.1 `objects`

An `Object` is a record name and an address, read through a reader and a table. Every method first finds the member (F1, F5): no reader or no table is an error, and an address that wraps past 2^64 is an error.

1. `Uint64(m)` and `Uint32(m)`: an array member is refused (read it with `Bytes`), and so is a record held in place (reach it with `Struct`). The width comes from `ResolveIntField` (F3); a member wider than 8 or 4 bytes is refused, never cut. The member is read at its width, zero-extended, and a bitfield gives its own bits (F3). A pointer member reads as its address.
2. `Pointer(m)`: the member must be a pointer whose level below is a plain name (F1, F4): a pointer to a pointer or array, or to no named type, is refused. The value is read at the table's pointer width (F2). Zero is `ErrNullPointer`, wrapped with the member and address. Otherwise the result is an `Object` of the named type at that address, with the same reader and table. The address is not checked as mapped.
3. `Struct(m)`: the member must be a record held in place (F4); a pointer is refused (follow it with `Pointer`). The result is an `Object` of that record at the member's address.
4. `Bytes(m, n)`: when the table gives the member a width above 0, `n` above it is refused. A width of 0, a trailing array (F1), bounds nothing. `n` 0 gives no bytes without a read. A read shorter than `n` is an error.

### 4.2 `profiles`

`WindowsX64Profile` is `windows-x64`, OS `windows`; `LinuxX64Profile` is `linux-x64`, OS `linux`. Both have pointer size 8 (P1 to P3).

### 4.3 `cli.Text`

Each character of the input becomes one piece:

1. A byte that does not start valid UTF-8 is `\xHH`.
2. A space that is the first or last byte is `\x20`.
3. A `<` that starts a suffix equal to one of the six markers (7.4) is `\x3c`.
4. Tab, line feed and carriage return are `\t`, `\n`, `\r` (T2).
5. 0x20..0x7E is itself (T1).
6. Any other character below 0x80 is `\xHH`; up to U+FFFF `\uHHHH`; above it `\UHHHHHHHH` (T2).

Then each piece that is a lone backslash is doubled when the text of the pieces after it starts with `\`, `t`, `n` or `r`, or with `x`, `u` or `U` followed by 2, 4 or 8 hex digits. Elsewhere a backslash stands for itself, so `C:\Windows` prints as it is.

The reading this promises: `\\`, `\t`, `\n`, `\r`, `\xHH` (one byte), `\uHHHH` and `\UHHHHHHHH` (one character) are escapes, and any other backslash is itself. The output is printable ASCII, reads back to the input, and never ends in a marker.

`Cell(s, unreadable)`: `Text(s)`; unreadable and empty is `<unreadable>`; unreadable with text is the text then `<rest unreadable>`. `Decimal` and `Hex` print the value or `<unreadable>`. `Time` prints RFC 3339 in UTC with whole seconds (T3), `-` for no time, or `<unreadable>`.

### 4.4 `cli` flags and session

`Flags.Register` adds `-os` (default `windows`), `-symbols`, `-cr3`, `-offline`, `-strict` and `-verbose`. `Config` maps them to `OpenConfig` and always sets `CollectDiagnostics`: a diagnostic is the only sign that a table is partial. `Parse` reads the command line, requires exactly one image path after the flags, and on a bad command line prints the reason and the usage and exits with status 2. `WithOptions` returns a context whose option map is a copy of the session's with the given keys added. `PrintDiagnostics` prints each diagnostic through `Text` with `-verbose`, and otherwise only their count.

### 4.5 The programs

Each program parses its flags, opens one session, prints its tables to standard output and its diagnostics to standard error, and exits non-zero on an error. Options a tool needs come in through `OpenConfig.PID` and `OpenConfig.ToolOptions` when every tool of the run shares them, and through `cli.WithOptions` when only some do.

| Program | Steps |
|---|---|
| `processlist` | `AnalyzeMemory` with the one name `any.process.list`, so the tool runs by name; the result is asserted to `[]processlist.Process`. One row per process: PID, parent PID, name, object address, creation time. A Linux row takes PPID and creation time from its Linux columns. |
| `processes` | `any.process.tree`, flattened in tree order, each row joined to `any.process.read_arguments` by object address (two processes can share a PID). Then the kernel's modules: `windows.module.list` or `linux.module.list`. With `-pid`, on a context narrowed to that PID: `windows.library.list` and `windows.thread.list`, or `linux.library.list`. |
| `memory` | Requires `-pid`; refuses `-out` on Linux before opening the image. `any.memory.list` with the session's PID. With `-out` on Windows, `windows.process.dump` and `windows.memory.dump` into that directory. |
| `registry` | Windows only, refused before opening the image otherwise. `windows.registry.read_key` with the hive, key and recurse options; rows grouped by hive address, one heading per hive. |
| `network` | Windows: `windows.network.list` then `windows.network.scan`; a failure of one is printed under its heading and the other still runs, and the program then exits with the failure. Linux: `linux.socket.list`, IPv4 and IPv6 only unless `-all`. |
| `timeline` | `any.timeline.list`, with `-tools` split on commas into the filter words and `-out` asking for a body file. |
| `triage` | Windows: `any.memory.find_code`, `windows.process.compare`, `windows.library.compare`, each failure printed under its heading while the others run. Without `-all` only the tool's `Hidden` rows and the images on exactly one of the load-order and memory-order lists print; images on neither list and images whose loader lists gave nothing (R2) are counted. Linux: `any.memory.find_code` only. |

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Integer read at the member's width, never wider or cut | F3: bytes past a member belong to the next one | error |
| Arrays and records are not integers | F1 | error |
| `Pointer` only through a pointer to a named type | F1, F4 | error |
| Zero pointer | no object at address 0 | `ErrNullPointer` |
| `Bytes` within a member of known width | F1 | error |
| Text output printable ASCII and reversible | T1, T2 | not applicable (always) |
| A Windows range's empty file is `N/A`, not `<unreadable>` | R1 | — |

## 6. Failure modes

| Case | Message |
|---|---|
| No reader or table | `objects: <type>.<member>: objects: no reader or no symbol table` |
| Member missing | `objects: <type>.<member>: symbols: type "<type>" has no field "<member>"` |
| Member address wraps | `objects: <type>.<member>: offset 0x… past the end of the address space` |
| Wrong kind of member | `objects: <type>.<member> at 0x…: an array, not an integer; read it with Bytes`, `…: a record, not an integer; reach it with Struct`, `…: not a pointer`, `…: points to no named type`, `…: a pointer; follow it with Pointer`, `…: not a record held in place` |
| Too wide | `objects: <type>.<member> at 0x…: N bytes wide, more than 4` (or 8); `…: N bytes asked of a W-byte member` |
| Read failures | `objects: <type>.<member> at 0x…: unreadable: %w`, `…: width unknown: %w`, `…: n of m bytes read`, `…: read past the end of the address space` |
| Zero pointer | `objects: <type>.<member> at 0x…: reads 0: objects: null pointer` (`errors.Is(err, ErrNullPointer)`) |
| Bad command line | the reason, the usage text, exit status 2 |
| Tool failure | `<tool name>: <tool error>`, exit status 1 |

## 7. Result schema

### 7.1 `objects`

`Object{Reader, Symbols, TypeName, Offset}`; `Offset` is the record's address in the reader's space. `ErrNullPointer` is the sentinel.

### 7.2 `profiles`

`Profile{Name() string; OS() string; PointerSize() uint8}`.

### 7.3 Program flags

Every program: `-os`, `-symbols`, `-cr3`, `-offline`, `-strict`, `-verbose`. Then `processes -pid`, `memory -pid -out`, `registry -hive -key -recurse`, `network -all`, `timeline -tools -out`, `triage -all`, `processlist -process-list-sanity -process-list-active-only -process-list-cross-check-csv`. Flags come before the image.

### 7.4 Output

Tables are aligned columns (two spaces between), each under a heading line `== <title>`. Addresses are `0x` lower-case hex; times RFC 3339 UTC. Markers: `<unreadable>`, `<rest unreadable>`, `<empty>` (a command line that read empty), `<no name>` (a hive with no path), `<unbacked>`, `<not listed>` (a tree process with no arguments row). `N/A` is a column that does not apply; `-` a value not given.

| Program | Columns |
|---|---|
| `processlist` | PID, PPID, Name, Object, Created |
| `processes` | tree: PID, PPID, Name (indented by `. ` per level), Command line; modules: Base, Size, Name; DLLs: Base, Size, Loaded, Path; threads: TID, State, Created, Start, Start file; Linux libraries: Base, Route (`linker list` or `mapped image`, S61 4.10), Path |
| `memory` | ranges: Start, End (inclusive), Protection, Type, File; minidump: File, Bytes, Modules, Threads, Regions, From image, Zero-filled, Not written because; range files: Start, End, File, Bytes, From image, Not written because |
| `registry` | per hive `<path>, hive at 0x…`: Last written, Key, Name (indented by depth), Type, Data |
| `network` | Windows: count line, then Protocol, Family, Local, Remote, State, PID, Process, Created; Linux: PID, Process, FD, Family, Type, Protocol, Local, Remote, State |
| `timeline` | heading with the count; Time, Event, Tool, Field, Subject |
| `triage` | code: count line, then PID, Process, Start, End, Protection, Rule, Header, First bytes (Linux: File in place of Header); process views: PID, Name, Active list, Kernel list, Session, Pool scan, Thread owner, CSRSS handle, Exit time, Verdict, then `N of M processes shown`; loader lists: PID, Process, Base, Load order, Init order, Memory order, Mapped file, then the shown and counted lines |

## 8. Limits

None. `Bytes` is bounded by the member's width when the table gives one, else by the caller's length. The programs print the first 16 bytes of a code region (`previewBytes`), enough for an instruction or a header magic.

## 9. Acceptance

### 9.1 Tests

- `objects`: integers of 1, 2, 4 and 8 bytes at their own width with 0xEE filler around them; a bitfield; a pointer as an integer; `Uint32` refusing 8-byte members; arrays, records and missing members refused; `Pointer` to a named type, refused for `**T`, `*`, scalars and records; zero pointer; 4-byte pointers; `Struct` in place and refused for pointers, scalars and arrays; `Bytes` within, past, of a trailing array, of 0 bytes, and a short read; no reader, no table, wrap and past the image. The example walks a two-task parent chain to `ErrNullPointer`. Fuzz target `FuzzObjectReads`.
- `profiles`: names, systems and pointer sizes; the example.
- `cli`: flag mapping, one-image rule, quiet and verbose diagnostics, `WithOptions` copying; `Text` on 18 fixed cases, five pairs that must differ, and fuzz target `FuzzText` (printable, reads back by the 4.3 reading, never ends in a marker); `Cell`, `Decimal`, `Hex`, `Time`.
- Each program: its print functions on rows built in the test (command lines joined by object address, missing command lines, thread start files, Windows and Linux range files, dump gaps, endpoint cells, socket filter, hive grouping, depth indents, timeline options and words, triage filters and counts, first bytes), and its flag checks.

### 9.2 Runs on captures (M4)

Built binaries, symbols from the cache, 2026-11-12. Times are wall clock for the whole program, opening included. Linux sessions spend about 2 s assembling the symbol table from the capture.

| Program | mem2 (Windows 10) | mem3 (Ubuntu 6.17) |
|---|---|---|
| `processlist` | 153 rows, 0.1 s | 203 rows, 1.7 s |
| `processes -pid` | 153 tree rows, 195 modules, PID 552: 2 DLLs, 2 threads; 1.4 s | 203 tree rows, 63 modules, PID 1: 24 libraries (mapped-image route, S61 4.10 step 5; re-run 2026-11-12 after S61 O6), 3.3 s (PID 729: 18 libraries, 2.4 s) |
| `memory -pid` | PID 552: 18 ranges; with `-out` one minidump (668,976 bytes, 2 modules, 2 threads, 150 regions, 0 zero-filled) and the range files; 0.4 s | PID 1: 144 ranges, 2.8 s |
| `registry` | 1 hive, 2 values; 0.2 s | not applicable |
| `network` | list 54, scan 66 endpoints; 3.8 s | `-all` 1,011 sockets (17 IPv4 or IPv6); 5.8 s |
| `timeline` | 412,048 entries and a body file; 50.1 s | 98,841 entries; 13.8 s |
| `triage` | 165 regions; 0 of 169 processes; 0 of 8,315 images, 46 on neither list, 235 not compared; 47.7 s | 61 regions; 15.6 s |

Every run exited 0.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Behaviour changes in `objects` from 0.1.0: `Uint32` and `Uint64` read the member at its width (zero-extended, bitfields cut out) instead of always 4 or 8 bytes, and refuse arrays, records and wider members. `Pointer` refuses pointers to pointers, arrays or unnamed types. `Struct` refuses members that are not records. `Bytes` refuses a length past a member of known width. `ErrNullPointer` now arrives wrapped with the member and address. Exported names are unchanged. | Owner decision |
| O2 | `objects` cannot see whether a scalar is a float or big-endian: the `SymbolTable` interface does not expose scalar kinds, so such a member reads as a little-endian integer. | Owner decision: extend the interface, or accept |
| O3 | `profiles` keeps the names `windows-x64` and `linux-x64` and the type names from 0.1.0. | Owner decision (Q2) |
| O4 | Output changes a user sees: `processlist` gains PPID and Created columns, names the address column Object, and takes `-offline`; `processes` lists Linux kernel modules with `linux.module.list` (0.1.0 called `windows.module.list` on Linux too) and indents the tree with `. `; `memory` names the column File, prints `N/A` for a Windows range with no file name (R1) and `<unreadable>` only for a Linux one, and renames dump columns; `network` splits Kind into Protocol and Family and prints `not listed: <reason>` for a failed list; `registry` heading `<path>, hive at 0x…` and indented names; `timeline` count in the heading; `triage` prints Rule and Header before First bytes, Rule for Linux findings, an exit time instead of a yes/no, `not checked: <reason>`, and leaves out and counts images whose loader lists gave nothing (R2). Headings are reworded. Usage text is `usage: <synopsis>` on standard error. | Owner decision |
| O5 | The examples README (`examples/README.md`) still describes 0.1.0 output in places (processes on Linux, column names). It is outside this spec's files. | README update. Owner decision 2026-11-12: schedule now. Done: examples/README.md describes each program's headings, columns and markers as printed on mem2_win10 and mem4_fedora40 (and `network` on mem5_server2016): usage and exit status, tree indent, `N/A` and `<unreadable>` in `memory`, `-out` refused on Linux, the registry heading and indent, Protocol and Family and `not listed:`, the timeline count and body file name, triage's Rule, Header, exit time, uncompared images and `not checked:`, processlist's columns and `-offline`, the showcase skips (S78 O8) and the hidden TrueCrypt and old LSA values. |
| O6 | `linux.library.list` gave no libraries for PID 1 on mem3 while PID 729 gave several. The program prints what the tool returns. | S61 follow-up. Owner decision 2026-11-12: schedule now. Done in S61 (O6, 4.10 steps 5 to 7, M21a to M21d): PID 1's executable area on mem3 reads but does not begin with an ELF header, so no `DT_DEBUG` list is found; the second route lists the 24 ELF images PID 1 maps from file offset 0 (`libc.so.6`, `libsystemd-shared-255.so`, `ld-linux-x86-64.so.2` and others), and `processes -pid 1` now prints them (9.2). |
| O7 | `cli.Text` doubles a backslash before `n`, so `\Windows\System32\ntdll.dll` prints as `\Windows\System32\\ntdll.dll`. This is the reversible rule of 4.3, kept from 0.1.0. | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept |
| O2 | Accept the gap |
| O3 | Keep |
| O4 | Accept |
| O5 | Schedule now |
| O6 | Schedule now |
| O7 | Keep reversible rule |

## 11. Provenance

Written from the project's symbol-table format (S58, `symbols/FORMAT.md`), Microsoft Learn "Abstract Data Models", the Linux headers named in P2 at the five tags, RFC 20, RFC 3339, the Go language specification, the tool specifications named in 3.4, and the project's measurements (`objectfacts` and the program runs of 9.2). The old files were read only for exported names, flags and callers. Every rule rests on the sources and measurements above.
