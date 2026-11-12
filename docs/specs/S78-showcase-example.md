# S78: Showcase example program

Version 1, 2026-11-12.

## 1. Purpose

A reader new to the library wants to see what every tool gives on one capture, and where each one fails, without writing code. The showcase program opens a capture once, runs every tool registered for the capture's platform by name, and prints one section per tool: its description, its run time, its rows or its error, and the diagnostics it added. It writes the same text to a report file and a short summary next to it.

This specification defines the program `examples/showcase`: its flags, which tools it runs, how a result of any type becomes a table, what is hidden by default, and the files it writes. It reads nothing from the capture itself; the root package and the tools do. The program is a demonstration, not a test fixture, and it must stay short and plain.

## 2. Inputs

| Input | Meaning |
|---|---|
| Image path | One positional argument after the flags. |
| Root package | `libvapour.OpenMemory`, `Session.Execute`, `Session.Diagnostics`, `Session.Close`, `OpenConfig` (S76, exported API frozen). |
| Tool registry | `tools.List`, `tools.Get` (S70 4.9). |
| Tool packages | Each tool's result type, read by reflection. Four credential row types by name (4.6). |
| Shared printing | `examples/internal/cli`: `Text`, `Cell`, `Time`, `Image`, `NewTable` and the markers `Unreadable`, `RestUnreadable` (S77). |
| Limits | None of its own. The session's defaults apply (`OpenConfig.Limits` is left zero). |

Flags, all kept from release 0.1.0 with their names and defaults (section 10, O1):

| Flag | Default | Effect |
|---|---|---|
| `-os` | `windows` | Platform passed to `OpenMemory`, and the default selection (4.2). |
| `-symbols`, `-cr3`, `-strict`, `-offline`, `-pid` | empty, 0, false, false, 0 | `OpenConfig.SymbolsPath`, `KernelCR3`, `Strict`, `OfflineOnly`, `PID`. |
| `-process-list-sanity`, `-process-list-active-only`, `-process-list-cross-check-csv` | false, false, empty | The matching `OpenConfig` fields. |
| `-network-scan-include-corrupt` | false | `OpenConfig.NetworkScanIncludeCorrupt`. |
| `-pagefiles` | empty | Comma-separated, trimmed, empty items dropped: `OpenConfig.PagefilePaths`. |
| `-opt key=value` | none | Repeatable. Key and value trimmed; an empty key or no `=` is refused. Values stay text: the tools' option readers parse text (S70 4.2). |
| `-tools` | empty | Comma-separated tool names, run in the order given. |
| `-max-rows` | 0 | Rows printed per table on stdout; 0 prints all. The report file always holds every row (4.4). |
| `-out` | `showcase_report.txt` | Report file. |
| `-summary`, `-summary-out` | true, empty | Write the summary; its path (4.7). |
| `-timings` | true | End the report with a timing table. |
| `-reveal-secrets` | false | Print the credential fields of 4.6. |

`OpenConfig.CollectDiagnostics` is always set: diagnostics are the only sign that a table is partial.

## 3. Facts from the sources

| # | Fact | Source |
|---|---|---|
| F1 | Flag parsing stops just before the first non-flag argument, so a flag after the image path is an argument, not a flag. A boolean flag takes its value only in the `-flag=false` form. | Go standard library documentation, package `flag`, Go 1.26. |
| F2 | A tab-terminated cell is a column cell to `text/tabwriter`; a tab or newline inside a value would split it. | Go documentation, package `text/tabwriter`, Go 1.26. |
| F3 | `cli.Text` renders any string as printable ASCII, reversibly, escaping tab, CR and LF; `cli.Cell` marks an unreadable value `<unreadable>` and a partly read one with `<rest unreadable>`; `cli.Time` prints UTC RFC 3339, or `-` for the zero time. | S77, `examples/internal/cli`. |
| F4 | `reflect.StructField.IsExported` and `Anonymous` tell exported and embedded fields; `Value.FieldByIndexErr` returns an error, not a panic, when the path passes a nil embedded pointer; `Value.IsZero` reports a zero value. | Go documentation, package `reflect`, Go 1.26. |
| F5 | A package's `init` functions run only when the package is part of the program. A tool registers itself in its package's `init`, so a program runs by name only the tools whose packages it links. | The Go Programming Language Specification, "Package initialization", Go 1.26; S70 4.9 step 1. |
| F6 | `tools.List` returns every registered spec sorted by name. Names have three dot-separated parts, `platform.subject.verb`. `tools.Execute` of an unregistered name returns `ErrToolNotFound`. | S70 4.9, F12. |
| F7 | `Session.Diagnostics` returns a copy of the session's sink, which the session and every tool only append to; the session's own lines come first. | Root package, `session.go` (S76). |
| F8 | Result fields follow one naming contract: `...Address` for virtual addresses, `...Physical` for physical ones, `...Size` in bytes; times are `time.Time` in UTC. Kernel object fields named after the type (`EPROCESS`, `ETHREAD`) hold the object's address. | Rewrite plan, section 4 (owner decision 2026-11-10); the tools' specs. |
| F9 | The zero `netip.Addr` prints as `invalid IP`. | Go documentation, package `net/netip`, `Addr.String`, Go 1.26. |
| F10 | The README states that the showcase skips `any.memory.list_pages` unless `-pid` or `-tools` asks for it, because across every process it gives millions of page runs, that it also skips `any.timeline.list` and `linux.kernel.list_symbols` unless `-tools` names them, and that the report header names each skip. | README.md, "Examples". |
| F11 | The README states that credentials print as `[redacted]`, sizes included, on stdout and in the report, unless `-reveal-secrets` is given; then an LSA secret prints as its size and first 32 bytes in hex. | README.md and examples/README.md, "Credentials". |
| F12 | Files the example programs write are readable by their user alone, on Windows and Unix. `ownerfile.Create` and `ownerfile.MkdirAll` make them so. | examples/README.md, "Files the programs write"; `internal/ownerfile`. |
| F13 | The credential row types: `credentiallocal.Entry` carries `LMHash` and `NTHash`; `credentialcached.Entry` carries `Verifier`; `credentiallsasecrets.Entry` carries `CurrentValue` and `OldValue`; `credentialtruecrypt.Passphrase` carries `Password` and its `Length`. | The tools' packages (S20, S21, S22, S66). |

### Measurements

M1 to M3 come from the program itself, built from this specification and run on 2026-11-12 with its defaults and `-max-rows 3`, on mem2_win10 (Windows 10, build 19045) and mem4_fedora40 (Linux 6.14). Times are wall-clock on the project's workstation, with the image on a local disk.

| # | Measured |
|---|---|
| M1 | The program links 130 tool packages, which register 142 tools: 12 `any`, 89 `windows`, 41 `linux`. The default selection is 100 tools on Windows and 52 on Linux; `any.memory.list_pages` is skipped on both. |
| M2 | mem2_win10: the run took 2 min 10 s (tools 2 min 9.4 s). 88 tools gave rows, 11 of them none; 12 failed, every one for a reason other than the capture: 6 need `output_dir` (`any.image.dump_layers`, `windows.file.dump`, `windows.memory.dump`, `windows.pe.dump`, `windows.process.dump`, `windows.registry.dump_hives`), 4 need an option naming what to look for (`windows.image.map_strings`, `windows.kernel.find_pattern`, `windows.memory.find_pattern`, `windows.pe.resolve_symbols`), `windows.image.read_crash_header` refuses a raw image, and `windows.execution.read_compat_cache` found its value data not resident. The slowest were `any.timeline.list` (14.2 s), `any.memory.find_code` (14.2 s), `windows.syscall.find_direct` (6.3 s) and `windows.pool.scan` (6.0 s). 716,236 rows; report 299,773,148 bytes, of which `any.timeline.list` (412,048 rows) is 152,761,133; summary 9,188 bytes; stdout 232,270 bytes. 5 session diagnostics (M6). |
| M3 | mem4_fedora40: the run took 36.8 s (tools 36.75 s). 47 tools gave rows, 8 of them none; 5 failed, each needing an option: `any.image.dump_layers` and `linux.pagecache.dump_files` (`output_dir`), `linux.memory.find_pattern` (a pattern), `linux.module.dump` (a module address), `linux.pagecache.list_pages` (an inode or a name). The slowest were `any.memory.find_code` (8.8 s), `any.memory.list` (4.8 s) and `any.timeline.list` (2.6 s). 471,049 rows; report 173,945,486 bytes, of which `linux.kernel.list_symbols` (275,758 rows) is 110,047,249; summary 4,565 bytes; stdout 49,815 bytes. 3 session diagnostics (M6). |
| M4 | On both captures, `any.process.list` printed only its own platform's column group (4.5 step 6): the Windows rows have no `Linux.` columns and the Linux rows no `Threads`, `Handles` or `CreateTime` columns. The credential sections on mem2 printed `[redacted]` for every hidden field (5 `windows.credential.read_local` rows). |
| M5 | After the O8 decision, same flags, 2026-11-12: the default selection is 99 tools on Windows and 50 on Linux. mem2_win10: 304,188 rows (M2 less `any.timeline.list`'s 412,048), report 151,179,737 bytes, summary 9,160, stdout 212,192; mem4_fedora40: 100,226 rows, report 30,636,281 bytes, summary 4,627, stdout 49,259. Run times (4 min 0.6 s and 1 min 18.4 s) were taken while other builds ran on the host and are not comparable with M2 and M3. |
| M6 | Session diagnostics, rerun 2026-11-12 with `-tools any.process.list`: 5 on mem2_win10 (the capture provider's open note, S71 and S76 O5; the kernel's PDB identity from the processor start page, its page-table root and the paging mode, S76 4.2; the kernel base confirmed by its codeview record, S76 4.3) and 3 on mem4_fedora40 (the open note; the table assembled from the capture, S76 4.5 step 4; the release, VMCOREINFO offset, root, paging mode and shift, S76 4.5 step 6). Each is a session note those specifications define; none is a failure. The 2 of the first run predate those notes. |

## 4. Algorithm

### 4.1 Start

1. Parse the flags (section 2). Exactly one argument must remain (`cli.Image`); `-max-rows` below 0 is refused. A refusal prints the reason and exits with status 2; a bad flag or argument count also prints the usage.
2. Create the report file (4.7) before opening the image, so a bad `-out` fails before a long run.

### 4.2 Selection

1. With `-tools`, run exactly the names given, in that order. A name that is not registered runs and reports `ErrToolNotFound` in its section (F6).
2. Otherwise take `tools.List()` in its name order (F6) and keep each tool whose first name part is `any` or the lowercased, trimmed `-os` value. A tool of the other platform would only fail on this capture.
3. From that set, leave out the tools whose output is most of the report (M2, M3; O8): `any.memory.list_pages` unless `-pid` is not 0 or an `-opt pid=` is given (F10), and `any.timeline.list` and `linux.kernel.list_symbols` always; a pid filter does not make those two small. `-tools` runs any of the three. The report header names each skipped tool and its reason.
4. The program links every package that registers a tool (F5), so every registered tool can be selected. A test checks the import list against the registering packages.

### 4.3 Run

1. Open the image with `OpenMemory(image, -os, config)`. A failure is written to the report as `error: <text>`, and the program exits with status 1.
2. Print the session's diagnostics (F7) under `[session]`.
3. For each selected tool, in order: note the diagnostic count, time `Session.Execute(name)`, and take the diagnostics added during the run as the tool's own (F7). Tabulate the result (4.5) and write the section (4.4) at once, then drop the table, so one result is held at a time.
4. A tool's error does not stop the run.
5. Close the session; write the timing table (with `-timings`), the summary (with `-summary`), and the saved paths.

### 4.4 Report layout

```
libvapour showcase report
generated: <UTC RFC 3339>
image: <path>
os: <-os>
tools: <n> (every any and <os> tool)      or      tools: <n> named by -tools
skipped: <tool> (<reason>)                 (once per skipped tool)
<80 '='>

[session]
diagnostics: <n>
- <diagnostic>

[<tool>]
<description>
time: <duration, ms>
rows: <n>                                  or      error: <text>
hidden: <fields> (pass -reveal-secrets to show them)
<table>
(<n> more rows in the report file)         (stdout only, with -max-rows)
diagnostics: <n>
- <diagnostic>

[timings]
total: <duration>
Tool  Status  Time                         (slowest first)
```

Lines with nothing to say are left out: no `[session]` without diagnostics, no `hidden:` without hidden fields, no table without rows. Every text from the image, a tool or the system passes through `cli.Text` (F3). Stdout gets the same text as the file; with `-max-rows`, its tables are cut and say so.

### 4.5 From a result to a table

1. Follow pointers and interfaces to the value; nil gives `rows: 0`.
2. A slice or array (not of bytes) is a list of rows. A map gives `Key`, `Value` rows sorted by the rendered key. A struct gives one row. Anything else gives one `Value` cell.
3. When the list's element (after pointers) is a struct that is not a leaf (step 7), its exported fields are the columns, in declaration order. Embedded struct fields add their own fields without a prefix; a named struct field adds its fields as `Field.Inner`, to four levels.
4. A field of the row's own type, as `[]T` or `[]*T`, holds child rows. They follow their parent depth-first, and the field is not a column. A row already printed is not printed again, so a loop in a tree read from the image ends (F4).
5. A bool field named `<X>Unreadable` beside a field `<X>` is not a column: where it is true, `<X>` prints as `cli.Cell` of its text for a string, else `<unreadable>` (F3).
6. A group of columns from one struct field (step 3) is left out when that field is zero in every row. One row type can carry a group per platform; the other platform's group would print only zeros.
7. Leaves: `time.Time` prints by `cli.Time`; a value with `Error` or `String` prints that text; a zero struct leaf prints `-` (F9). Nil pointers, nil errors and absent fields print `-`.
8. Integers print in decimal, except an unsigned one whose field name ends in `Address`, `Addr`, `Physical`, `Offset`, `Base`, `Start`, `End`, `Size`, `Flags`, `Mask`, `EPROCESS` or `ETHREAD`, which prints as `0x` hex (F8). Floats print in Go's shortest form; bools as `true` or `false`.
9. A byte slice or array prints as `<n> bytes` and its first 32 bytes in hex, then `...` if longer (F11). Other slices print `[a, b]`, maps `{k=v, ...}` sorted, nested structs `{Name=value ...}`, to four levels and then `...`.
10. Strings pass through `cli.Text`, so no cell holds a tab or line break (F2, F3).

### 4.6 Hidden fields

Without `-reveal-secrets`, these columns print `[redacted]` and the section names them on its `hidden:` line (F11, F13):

| Tool | Fields |
|---|---|
| `windows.credential.read_local` | `LMHash`, `NTHash` |
| `windows.credential.read_cached` | `Verifier` |
| `windows.credential.read_lsa_secrets` | `CurrentValue`, `OldValue` |
| `windows.credential.find_truecrypt` | `Password`, `Length` |

A secret's size is hidden with it: a length narrows the search for the value. The fields are named as text, so a test tabulates each tool's row type and fails if a name no longer matches a field.

### 4.7 Files

1. The report goes to `-out`, or `showcase_report.txt` when `-out` is empty. A missing directory is created. Both are created with `ownerfile` (F12). An existing file is replaced.
2. The summary goes to `-summary-out`, else to the report path with `_summary` before its extension. It holds the header, `status: ok=<n> error=<n>`, the total time, the session diagnostic count, a table of every tool in run order (`Tool`, `Status`, `Rows`, `Diagnostics`, `Time`; `-` rows for a failed tool), and `[errors]` with each failed tool's error.
3. After writing, stdout gets `report saved: <path>` and `summary saved: <path>`.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| One image argument, after the flags | F1 | Usage, status 2 |
| `-opt` has `=` and a non-empty key | A key is what a tool looks up | Usage, status 2 |
| `-max-rows` at least 0 | A negative count has no meaning | Message, status 2 |
| A tool is selected by default only for its own platform or `any` | F6; the other platform's tools fail on this capture | Not run |

## 6. Failure modes

| Condition | Result |
|---|---|
| Bad command line | Usage, status 2 |
| Report or summary not created or not written | `showcase: create <path>: ...`, `showcase: write report: ...`, `showcase: write summary: ...`; status 1 |
| Image does not open | `error:` line in the report; `showcase: open image: ...`; status 1 |
| Tool fails or is unknown | `error:` in its section and the summary; the run goes on |
| Session close fails | `showcase: close image: ...` after the files are written; status 1 |

## 7. Result schema

The output is text (4.4, 4.7). Column names are the tools' Go field names, so the tables follow each tool's own result schema.

## 8. Limits

The program sets no Limits; the session's defaults apply to every tool. It holds one tool's result and table at a time (4.3 step 3). It never truncates the report file.

## 9. Acceptance

1. A run of every default tool on one Windows and one Linux capture completes, with the counts and times of M1 to M4. Every failed tool fails for want of an option or for a reason its own section states.
2. Flag tests: defaults; every flag reaching its `OpenConfig` field or setting; `-opt` without `=` or key, a negative `-max-rows`, no image, two images and a flag after the image refused.
3. Selection tests over a synthetic spec list: platform filter, case and spaces in `-os`, the three skips, `-pid` and `-opt pid=` lifting only the list-pages skip, `-tools` taken as given; every skipped tool is registered.
4. Every registered tool's name starts with `any`, `windows` or `linux`; every package under `tools/` that registers a tool is imported, and no other.
5. Table tests: column order, embedded and named groups, the `Unreadable` fold, hex and decimal, leaves and `-`, byte prefix, all-zero groups left out, child rows once each with a loop, maps, scalars, nil.
6. Each credential row type, with a secret in every hidden field, prints no part of it, nor its length; with `-reveal-secrets` nothing is hidden.
7. Report and summary layout tests; a missing image leaves a private report with its `error:` line.
8. Fuzz targets: `-opt` text (accepted exactly when it has `=` and a key, and stored trimmed), and table cells from arbitrary strings, bytes and maps (printable ASCII only).

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | Flag names, defaults and the report's file names are kept from release 0.1.0. | Owner decision Q2. |
| O2 | Output changes from release 0.1.0: every tool is now printed by one reflective table (column names are field names) instead of hand-written tables for some tools and `no table printer` for the rest; headers are lowercase; `count:` became `rows:`; diagnostics print in the section of the tool that added them, and session diagnostics under `[session]`, instead of one list at the end; the summary lists every tool instead of the five slowest. | Owner decision. |
| O3 | Default selection: tools of the other platform are no longer run, and every registering package is now linked, so Linux tools run on Linux captures (before, only the 48 packages the program printed were linked). | Owner decision. |
| O4 | `-max-rows` now cuts stdout tables. In release 0.1.0 it was accepted and ignored. | Owner decision. |
| O5 | `windows.credential.find_truecrypt` passphrases and their lengths, and LSA secrets' old values, are now hidden by default and shown by `-reveal-secrets`. Release 0.1.0 did not print that tool's rows nor old values at all. Other tools whose rows can hold typed secrets (shell history, console buffers, process environments, registry values) are not hidden. | Owner decision: which tools count as credential tools. |
| O6 | The stderr spinner is gone; sections stream to stdout as each tool ends. The `-summary-out` special case that dropped the flag when no value followed is gone: Go's flag rules apply (F1). | Owner decision. |
| O7 | The hex rule (4.5 step 8) reads field names. A field that holds an address under another name prints in decimal. | Tools follow the naming contract of F8; owner decision Q2 on field names. |
| O8 | Every result is now printed in full, so the report is large: 300 MB on mem2 and 174 MB on mem4 (M2, M3), half of it one tool. | Owner decision: keep, skip `any.timeline.list` and `linux.kernel.list_symbols` by default as `any.memory.list_pages` is, or cut the report file too. Owner decision 2026-11-12: skip those two by default. Done: both are skipped by default with their reasons in the header, `-tools` runs them (there is no separate include flag; `-pid` lifts only the list-pages skip), 4.2 step 3; the report is 151 MB on mem2 and 31 MB on mem4 (M5); examples/showcase/main.go, main_test.go. The README names the two skips (F10). |
| O9 | M2 and M3 gave 2 session diagnostics each; the run of the w12 sweep gave 5 on mem2 and 3 on mem4. Owner decision 2026-11-12: check, then refresh S78 counts. Done: rerun with the program (M6); each note is one S71 or S76 defines, so the program is right and M2, M3 now give 5 and 3. No code change. | Closed. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep |
| O2 | Accept |
| O3 | Yes |
| O4 | Cut tables |
| O5 | Truecrypt and LSA secrets old values |
| O6 | Removed |
| O7 | Keep name rule |
| O8 | Skip those two by default |

## 11. Provenance

Author: the project, 2026-11-12. Sources: as cited in section 3 (Go 1.26 documentation and language specification, the project's README files, S70, S76, S77 and the credential tools' specs), accessed 2026-11-12. Measurements: the program itself, run on the captures named in section 3. Every rule rests on the sources and measurements above.
