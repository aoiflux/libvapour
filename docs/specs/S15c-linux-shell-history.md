# S15c: Linux shell history

Version 1, 2026-11-12.

## 1. Purpose

An interactive Bash shell keeps the commands typed into it in memory, as a history list, and writes them to the history file only when it exits, if at all. A memory image can therefore hold commands that no file on disk shows, including those of a shell that unset its history file. Other programs that use the GNU History Library keep the same list. An examiner needs, for each such process, the commands on its history list, in order, with their time stamps.

This specification defines which processes are searched, which of their memory is searched, and how a history list is recognised in it. The tool is `linux.shell.read_history`.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel objects | `linuxobj.Kernel` | Task fields and the process address space of a task. |
| Task walk | S01 (`linuxwalk.Reader.Tasks`) | The processes, without threads, with the session's PID filter. |
| VMA walk | `memoryranges.LinuxWalker.TaskVMAs` | A process's memory areas. |
| Symbol table | symbols | `task_struct.comm`, `task_struct.mm`, `mm_struct.exe_file`, `vm_area_struct.vm_flags` and `vm_file`. |
| File names | `memoryranges.LinuxWalker.OpenFileName` and `AreaName` | The executable's path as `/proc/<pid>/exe` shows it (S61 I1) and each mapped file's path as the maps file shows it (S39 4.7). |
| Limits | effective `limits.Limits` | Section 8. |
| Options | the session PID filter | No options of the tool's own. |

## 3. Facts from the sources

Kernel tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17.

The shell structures rest on the published documentation, "GNU History Library" (the manual for History 8.3, linked from gnu.org/software/readline and served from the maintainer's site, tiswww.cwru.edu/php/chet/readline/history.html) and "The GNU Bash Reference Manual", Edition 5.3, 18 May 2025 (gnu.org/software/bash/manual/bash.html), and, from the owner decision of section 10 O1, on the GNU source releases from ftp.gnu.org: Readline 8.3 (`history.h`, `history.c`, `histexpand.c`, `histfile.c`, `shlib/Makefile.in`, `support/shobj-conf`), with `history.c` and `histexpand.c` also read at Readline 5.2, 6.3, 7.0, 8.1 and 8.2, and Bash 5.3 (`bashhist.c`, `variables.c`, `configure.ac`, and its copy of the library in `lib/readline`, which matches Readline 8.3's `history.c` and `history.h`). All were read on 2026-11-12 for facts only; no code was copied.

| # | Fact | Source |
|---|---|---|
| K1 | At exec, the kernel sets `task_struct.comm` from the base name of the executable's path (`__set_task_comm(..., kbasename(bprm->filename), true)`), cut to `TASK_COMM_LEN` − 1 bytes; `TASK_COMM_LEN` is 16. | `fs/exec.c` and `include/linux/sched.h`, every tag. |
| K2 | `VM_WRITE` is 0x2 and `VM_SHARED` is 0x8 in `vm_area_struct.vm_flags`. | `include/linux/mm.h`, every tag. |
| H1 | "The history list is an array of history entries." A history entry is `typedef struct _hist_entry { char *line; char *timestamp; histdata_t data; } HIST_ENTRY;` with `typedef void *histdata_t;`. The source declares the same structure. | GNU History Library, 2.2 History Storage; `history.h`, Readline 8.3 and Bash 5.3. |
| H2 | `history_list` returns "a NULL terminated array of `HIST_ENTRY *`". In the source it returns `the_history`; `add_history` stores the new entry at index `length - 1` and a null pointer at index `length`, and growing the list zeroes the slots past the last entry. With the list capped (stifled), dropping the oldest entry moves `the_history` one slot up inside a larger array, so the slot below the list can still hold the address of the entry just freed. | GNU History Library, 2.3.3; `history.c` (`history_list`, `add_history`, `history_list_resize`, `advance_history`), Readline 8.3. |
| H3 | `add_history` adds a string "to the end of the history list". So the list is in the order the commands were entered. | GNU History Library, 2.3.2 History List Management; `history.c`, Readline 8.3. |
| H4 | Each entry, its line and its time stamp are separate heap allocations (`xmalloc` of the entry, `savestring` of the line and of the stamp), and the list is `xrealloc`ed: all are in the process's private writable memory, and an entry's line and stamp are never the same string. | `history.c` (`alloc_history_entry`, `hist_inittime`, `history_list_resize`), Readline 8.3. |
| H5 | `add_history` gives every entry a time stamp at once, from `hist_inittime`: the history comment character followed by the current time printed as an unsigned long in decimal. `add_history_time` replaces it with a caller's string, which `read_history` takes from the history file's time stamp line (H6). `history_get_time` returns 0 unless the stamp begins with the comment character, and otherwise the rest read with `strtol`, 0 when out of range. The same `add_history` and `hist_inittime` are in Readline 5.2, 6.3, 7.0, 8.1, 8.2 and 8.3. | `history.c` and `histfile.c` at those releases; GNU History Library, 2.3.2 and 2.3.3. |
| H6 | The library's own comment character, `history_comment_char`, is NUL. Bash sets it to `#` at start, and to the third character of `histchars` when that variable has one; setting `HISTTIMEFORMAT` changes it from NUL to `#`. In the history file a time stamp line is the comment character followed immediately by a digit (`HIST_TIMESTAMP_START`). `HISTTIMEFORMAT` decides only whether stamps are written to the file. | `histexpand.c` (Readline 5.2 to 8.3), `histfile.c` (Readline 8.3); `variables.c` (`sv_histchars`, `sv_histtimefmt`) and `bashhist.c` (`bash_initialize_history`), Bash 5.3; Bash Reference Manual, 5.2 and 9.1. |
| H7 | Bash may be invoked with the name `sh`; it then "tries to mimic the startup behavior of historical versions of sh". | Bash Reference Manual, 6.2 Bash Startup Files. |
| H8 | Bash builds with its own copy of the library (`lib/readline`) linked in, unless configured `--with-installed-readline` (`opt_with_installed_readline=no` by default). So a Bash process holds the library either inside its executable or as a mapped shared library. | `configure.ac`, Bash 5.3. |
| H9 | The shared libraries are `libreadline.so.<version>` and `libhistory.so.<version>` on Linux (`SHARED_READLINE`, `SHARED_HISTORY`, with `SHLIB_LIBVERSION` `so.<major>[.<minor>]`). | `shlib/Makefile.in` and `support/shobj-conf`, Readline 8.3. |
| X1 | A structure that holds pointers is aligned to the pointer size. | System V x86-64 psABI, "Fundamental Types" and "Aggregates and Unions". |
| X2 | `time_t` counts seconds since the Epoch. | POSIX.1-2017, Base Definitions 4.16 "Seconds Since the Epoch"; `<sys/types.h>` (`time_t`). |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Processes whose executable is named `bash` or `sh`: none on either capture, and none by `comm` either. The interactive shells on both are `fish` (2 on mem3_ubuntu24, 3 on mem4_fedora40), by executable and by `comm`. | `tracinghistoryfacts`, 2026-11-12. |
| M2 | Rows per capture. | Section 9 table. |
| M3 | Processes that map `libreadline.so.8.2`: `gnome-shell` and three `gjs` on mem3_ubuntu24, `gnome-shell` and two `gjs` on mem4_fedora40. Before 4.3 step 3 limited the comment character to `#` and NUL, the search found one false single-entry list in each `gnome-shell` (stamps `e1` and `:0`); with the limit it finds none. | `tracinghistoryfacts`, 2026-11-12. |
| M4 | mem8_fedora40 (6.14), a ground-truth capture of 2026-11-12: two interactive `bash --norc --noprofile -i` shells (pids 2100 and 2109, children of the tmux panes' first processes 2096 and 2104), shell B with `HISTTIMEFORMAT`; the commands typed, and `history` printed after the capture. Rows: shell A 12 of 12, in order and text as `history` prints them (a repeated line, a line with two leading spaces, a UTF-8 line); shell B 4 of 5, each time the second `history` prints. Both shells store every stamp as `#` and the seconds in decimal (`#1794491140`), with `HISTTIMEFORMAT` and without. Shell B's first list slot holds an entry whose line reads and whose stamp pointer lands in a heap page the process's page tables do not map, so 4.3 step 3 takes no entry there. No other process gives rows: a non-interactive `bash` running a script (pid 2300), three `fish`, and the three readline users of M3. | `tracinghistoryfacts -rows`, `-entries 2109`; ground-truth gate `TestLinuxShellHistoryMatchesTheCapturesGroundTruth`. |

## 4. Algorithm

### 4.1 Processes

1. Walk the processes with the S01 task walk, without threads, applying the session PID filter.
2. Walk each process's memory areas. A process with no `mm` is skipped.
3. Keep a process when its executable file (`mm_struct.exe_file`, its path as `/proc/<pid>/exe` shows it, S61 I1, without the ` (deleted)` mark) has the base name `bash` or `sh` (H7, H8), or else when one of its mapped files, its path as the maps file shows it, has a base name that begins `libreadline.so` or `libhistory.so` (H9). `comm` is not used: a process can change it (K1). Names that do not read are counted, and the process is chosen by the names that do.
4. Take the kept process's address space from its `mm`. One whose address space cannot be built is skipped and counted, with a diagnostic. When `ProcessLayer` refuses the task with no reason (it takes the task for a kernel thread, or reads a null `mm`), the process is skipped silently: it is not counted, gives no diagnostic and does not fail strict mode (O7).

### 4.2 Memory searched

1. Walk the process's memory areas. Keep those whose `vm_flags` has `VM_WRITE` and not `VM_SHARED` (K2): private writable memory (H4).
2. Read each kept area page by page (4096 bytes). Pages that do not read are counted and left out.
3. Stop adding pages at `MaxRegionScanBytes` for the process, with a diagnostic.

### 4.3 Entries

An address E, aligned to the pointer width (X1), is an **entry** when:

1. The pointer-width words at E and E + w (w the pointer width) read from the searched pages, as do the bytes up to E + 3w (H1).
2. The word at E (`line`) points into the searched pages at a **command text**: the bytes before a NUL, between 1 and `MaxTextBytes` long, every byte a tab, a newline, or a byte of value 0x20 or more other than 0x7F.
3. The word at E + w (`timestamp`) is not 0, is not the word at E (H4), and points into the searched pages at a **stamp**: the comment character, `#` or NUL (H6), then 1 to 20 decimal digits (H5), then a NUL. The comment character set through `histchars` can be any character, but accepting any byte there found false lists on the captures (M3), so other comment characters are not recognised.

The third word (`data`) is not checked: it belongs to the application (H1).

### 4.4 The history list

1. An **entry array** is a run of one or more consecutive pointer-aligned words in the searched pages, each holding the address of an entry, followed by a word holding 0 (H1, H2), and not preceded by a word holding the address of an entry. The slot below a capped list can hold a freed entry's address (H2); the freed entry is an entry only if its memory still passes 4.3.
2. The process's history list is its longest entry array; between arrays of equal length, the one at the lowest address. Other arrays are counted in a diagnostic.
3. The rows are the list's entries, in array order (H3), with their index from 0.

### 4.5 Time stamps

A stamp's digits are a **time** when the number fits a signed 64-bit integer, as `strtol` reads it (H5). The time is that many seconds after the Epoch, in UTC (X2). A number past that range leaves the time absent. The row shows the stamp as stored: `#` and the digits, or the digits alone when the comment character is NUL.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| The entry, its command and its stamp lie in searched pages | H4 | Not an entry |
| The stamp is `#` or NUL, then 1 to 20 digits; it is a different string from the command | H4, H5, H6 | Not an entry |
| Entries are pointer-aligned | X1 | Not an entry |
| Command text is non-empty and has no control byte other than tab and newline | Decision (O2): history lines are typed input | Not an entry |
| An array ends with a null word | H2 | Not an array |
| One list per process, the longest array | H1: one history list | Others counted |

## 6. Failure modes

| Case | Result |
|---|---|
| Profile is not Linux | Error |
| Task walk fails, or the memory-area layout is not in the symbol table | Error |
| A task's `comm` or `pid` does not read | Skipped; diagnostic `<tool>: process <pid> at 0x<task>: <member> does not read: <err>` |
| A task's memory areas cannot be walked from its `mm` | Skipped; diagnostic `<tool>: process <pid> at 0x<task>: memory areas not walked: <err>` |
| The executable or a mapped file name does not read, or the table has no `mm_struct.exe_file` | The process is chosen by the names that read; one diagnostic for the run, `<tool>: <n> processes whose executable or mapped file names do not all read were chosen by the names that read, first: <why>` |
| Address space cannot be built | Skipped; diagnostic `<tool>: process <pid> at 0x<task>: no address space: <err>` |
| Address space refused with no reason | Skipped silently; not counted, no diagnostic, not a strict-mode error (O7) |
| The kernel layer cannot translate addresses | Error |
| Memory areas cannot be walked or their flags do not read | The areas read so far are used; one diagnostic per process |
| Pages do not read | Counted, one diagnostic for the run |
| `MaxRegionScanBytes` reached | Diagnostic `<tool>: process <pid> at 0x<task>: search stops at Limits.MaxRegionScanBytes` |
| Strict mode | Skipped tasks, unwalked memory areas and the scan cap are an error. Pages that do not read are not, because user pages are often not resident. |

Errors are package sentinels with the prefix `shellhistory:`.

## 7. Result schema

`Command`, in process walk order, then list order:

| Field | Type | Meaning |
|---|---|---|
| `PID` | int64 | The process ID (`task_struct.pid` of the group leader) |
| `Process` | string | `comm` |
| `Executable` | string | The executable's path (4.1 step 3); empty when it does not read |
| `Library` | string | The mapped GNU Readline or History library that chose the process; empty when the executable chose it |
| `EntryAddress` | uint64 | The entry's address in the process's address space |
| `Index` | int | Position in the history list, from 0 |
| `Command` | string | The command text, newlines kept |
| `Timestamp` | string | The stamp as stored (4.5) |
| `CommandTime` | `time.Time` | 4.5, UTC |
| `CommandTimeOK` | bool | The time is present |

## 8. Limits

- `MaxRegionScanBytes`: memory searched per process.
- `MaxTextBytes`: command text.
- `MaxListEntries`: the task walk (S01).

## 9. Acceptance

- Synthetic fixtures: a history list of three entries, a shorter decoy array, an entry whose command is not text, an array with no null end, an entry whose stamp points outside the searched pages, the `#` and NUL stamp forms, stamps with another comment character, no digits, letters, 21 digits or no stamp, an entry whose command and stamp are one string, a stamp too large for 64 bits; end to end, processes chosen by executable (`bash`, `sh`, a renamed `bash`, a deleted `bash`) and by a mapped `libreadline.so` or `libhistory.so`, a `fish` process, a `bash` lookalike by `comm`, a library whose name only starts alike, and a shared memory area passed over, a table without `mm_struct.exe_file`, the PID filter, and the scan cap in normal and strict mode.
- Fuzz targets over the entry and array search (`FuzzHistorySearch`) and over the stamp parser (`FuzzStampParser`) on arbitrary bytes.
- On both captures:

| Capture | Executable `bash` or `sh` | Mapping a history library (M3) | Other shells | Rows |
|---|---|---|---|---|
| mem3_ubuntu24 | 0 | 4 | `fish` 2 | 0 |
| mem4_fedora40 | 0 | 3 | `fish` 3 | 0 |
| mem8_fedora40 | 3 (one non-interactive) | 3 | `fish` 3 | 16 (M4) |

Measured with `tracinghistoryfacts`, 2026-11-12. The tool takes 15.1 s on mem3_ubuntu24 and 6.8 s on mem4_fedora40 (`btffacts -only`), most of it in the `gnome-shell` heaps. Its diagnostics are the count of searched pages that do not read (84001 and 94702) and, on mem4_fedora40, the S01 task-walk reports (the backward task walk ends after one task) and one `gnome-shell` memory-area walk that kept 1510 of 1517 areas.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | **Owner decision (Q9).** The structure facts H1 to H7 rest on the published GNU History Library and Bash manuals only, pending the owner's answer on whether GNU Bash source counts as an allowed source. No Bash or Readline source was read. Owner decision 2026-11-12: allow GNU Bash source. Done: H1 to H7 checked against Readline 8.3 and Bash 5.3 (section 3). H1, H3 and H7 hold as written. H2, H4, H5 and H6 now state the source's facts, and H8 and H9 are new. The in-memory stamp is the comment character and decimal digits, given to every entry (H5), and the library's own comment character is NUL (H6). So 4.3 step 3 now requires a stamp, 4.5 drops the digits-only form, and the `Timestamp` field shows the digits for a NUL comment character. `tools/linux/shellhistory/search.go`, `search_test.go`, `fuzz_test.go`. | Owner decision Q9 |
| O2 | The in-memory form of the time stamp string is not documented. 4.5 accepts the history-file form (H6) and bare digits. Neither capture runs Bash, so no stamp has been measured. Owner decision 2026-11-12 (follow-up N2): closed by the mem8 ground truth (M4): the stamp in memory is the history-file form, `#` and the digits, with and without `HISTTIMEFORMAT`; the times equal the ones `history` prints. | Closed |
| O3 | Neither capture has a Bash process, so the list rule (4.4) is checked by fixtures only. A single-entry array elsewhere in memory could be taken for the list of a shell whose history is empty, and the rate of such arrays in real process memory is not measured. Owner decision 2026-11-12 (follow-up N2): closed by M4: on a capture with two interactive shells the list rule picks each shell's history list and no other array; one entry is left out because its stamp's page does not read, counted in the ground-truth gate. | Closed |
| O4 | Shells are chosen by `comm`, which a process can change. A Bash renamed through `prctl` is missed, and a process that takes the name is searched. Owner decision 2026-11-12: choose by executable file. Done: 4.1 step 3 chooses by the base name of `mm_struct.exe_file`'s path, and the new field `Executable` gives that path. `tools/linux/shellhistory/read_history.go`, `read_history_test.go`. | Owner decision: select by the executable file instead |
| O5 | Other programs that use the GNU History Library keep the same lists. They are not searched. Owner decision 2026-11-12: search other programs too. Done: 4.1 step 3 also keeps a process that maps `libreadline.so*` or `libhistory.so*` (H9); a statically linked Bash is kept by its executable (H8). The new field `Library` names the library. On the captures this adds 4 and 3 processes and no rows (M3). `tools/linux/shellhistory/read_history.go`, `read_history_test.go`. Owner decision 2026-11-12 (follow-up D7): accept that only `#` and NUL are comment characters (4.3 step 3) and that every entry needs a stamp (O2, O3); any byte gave false lists in `gnome-shell`. Done: recorded; no change. | Owner decision |
| O6 | `read_history` gives 0 rows on mem3 and mem4: no Bash runs on either. Owner decision 2026-11-12 (follow-up D6): take a ground-truth capture with a scripted Bash session. Owner decision 2026-11-12 (follow-up N2): use it. Done: mem8_fedora40 (M4); the gate `TestLinuxShellHistoryMatchesTheCapturesGroundTruth` (integration, ground-truth directory) compares each shell's rows with `history` minus its last line: order, text, and shell B's times; the one entry left out is a counted excuse (4.3 step 3). No library change. | Closed |
| O7 | `reader.task` (`tools/linux/shellhistory/read_history.go`) skips a kept process silently when `ProcessLayer` refuses it with a nil reason: no count, no diagnostic, no strict-mode error. Owner decision 2026-11-12: kept for v0.1.0; count the process and report it in a diagnostic in v0.2.0. | v0.2.0 |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Allow GNU Bash source (overrides the recommendation) |
| O2 | Accept history-file form and bare digits |
| O3 | Keep fixture-only checks |
| O4 | By executable file |
| O5 | Search other programs too (overrides the recommendation) |

## 11. Provenance

Written from the kernel sources at the tags in section 3, the published GNU History Library and Bash manuals, the GNU Readline and Bash source releases named in section 3 (facts only), the x86-64 psABI, POSIX, and the project's measurements. Every rule rests on the sources and measurements above.
