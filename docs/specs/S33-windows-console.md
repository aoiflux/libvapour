# S33: Windows console host state: screens, command histories, titles

Version 1, 2026-11-12.

## 1. Purpose

A console window keeps more than a terminal shows. Its host process, `conhost.exe`, holds the console's title and original title, the text of each screen buffer (thousands of rows of scrollback), which client processes are attached, the aliases defined for each executable, and one command history buffer per application: the commands typed at a `cmd.exe` prompt, in order. An examiner wants that state back from a memory capture, including histories whose console has gone.

`conhost.exe` is a C++ program and keeps this state in standard-library containers inside its own heap and data section. No public type information describes them. This specification defines how the state is found by searching the host's memory, the checks that keep a chance byte pattern from passing for a console or a history, and how each part is decoded. Two tools share it: `windows.console.list` reads whole consoles, `windows.console.scan_history` searches for history buffers on their own.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory and symbols | The process list (`processlist`, frozen), each process's VADs (`memoryranges`, frozen; S24) and its present pages (`memoryranges.PageLister`), and the build (`winkernel.ReadBuild`; S03). |
| Process memory | `conhost.exe` user memory through `tools.Context.ProcessSpace`. |
| Registry | Every hive that opens through `registryhive.OpenEveryHive` and has a `Console` key. |
| Layout | `tools/windows/consolelist/layouts.go` and `layout.go`: measured member offsets, re-derived from the captures in S67 (section 3, Layout). |
| Options | `windows.console.list.no_registry`, `.max_history`, `.max_buffers`; `windows.console.scan_history.no_registry`, `.max_history`; `pid`, `strict`. |
| Limits | `MaxRegionScanBytes`, `MaxMatchesPerChunk`, `MaxListEntries`, `MaxRowsPerObject`, `MaxTextBytes` (section 8). |

## 3. Facts from the sources

### Documentation

All Microsoft Learn pages accessed 2026-11-12.

| # | Fact | Source |
|---|---|---|
| F1 | `conhost.exe`, the console host, serves every Windows Console API call and also provides the classic window in which command-line programs run. | "Windows Console and Terminal Definitions", ms.date 2018-07-12 |
| F2 | A screen buffer is a two-dimensional grid of characters and their colours shown in a console window. One console may own several of them; the one on display is called active. Every screen buffer has its own grid of character records, each giving a character and its colours (`CHAR_INFO`). Its properties include its size in rows and columns, and a window: the part of the buffer currently shown. | "Console Screen Buffers", ms.date 2018-07-12 |
| F3 | The library's `list` keeps its elements as a doubly linked sequence, so each element can be reached from both neighbours. | "list Class" (C++ Standard Library), ms.date 2016-11-04 |
| F4 | A string's capacity is the storage it has reserved for its characters, and is never below its size. | "basic_string Class", ms.date 2023-07-11 |
| F5 | A `vector` keeps its elements in one linear run with random access; its capacity is how many elements fit before it must reserve more storage, so the count never exceeds it. | "vector class", ms.date 2023-08-25 |
| F6 | (Derived from F4 and the measured layout.) A string object holds its characters itself while they and the closing NUL fit in the bytes before its length member; the layout puts the length 16 bytes in, so 8 UTF-16 units fit and the in-object capacity is 7. | F4, layout `text.*`, M3 |
| F7 | A console has a current title and an original title, each read through its own call (`GetConsoleTitle`, `GetConsoleOriginalTitle`); the title's length is counted in characters. | "GetConsoleTitle function", ms.date 2018-07-12 |
| F8 | `COORD` holds two `SHORT` members: `X` is the column and `Y` the row of a cell in a screen buffer. A screen buffer may not be made smaller than its window in either direction (`SetConsoleScreenBufferSize`). | "COORD structure", "SetConsoleScreenBufferSize function", ms.date 2018-07-12 |
| F9 | An alias maps a source string to a target string. Aliases belong to one executable within one console: copies of that executable in the same console share them, other executables and other consoles do not. | "Console Aliases", ms.date 2018-07-12 |
| F10 | `CONSOLE_HISTORY_INFO` has four 32-bit members: `cbSize`, `HistoryBufferSize` (how many commands each history buffer keeps), `NumberOfHistoryBuffers` (how many buffers the console keeps for its processes) and `dwFlags`. | "CONSOLE_HISTORY_INFO structure", ms.date 2018-07-12 |
| F11 | Doskey keeps a separate history of typed commands per program; its `/listsize` switch sets the largest number of commands a history holds; the arrow keys step back and forward through earlier commands. | "doskey", ms.date 2017-10-16 |
| F12 | A console always has one or more processes attached, which is why `GetConsoleProcessList` returning zero signals failure. | "GetConsoleProcessList function", ms.date 2018-07-12 |
| F13 | Per-user console settings live under the `Console` key of `HKEY_CURRENT_USER`; the documented example reads `HistoryBufferSize` there as a DWORD. The shell-link console block stores screen buffer and window sizes as pairs of 16-bit signed values and both history settings as 32-bit unsigned values. | "WMI Tasks: Registry" (ms.date 2018-05-31); [MS-SHLLINK] 2.5.1 ConsoleDataBlock |

### conhost.exe symbol tables

The project's symbol cache holds three conhost tables (`symbols/windows/10/conhost-<GUID>-1.vsym`). `consolefacts -tables` on 2026-11-12:

| # | Fact |
|---|---|
| P1 | F020B0E2… (the mem2 conhost, 19045): 0 records, 0 enumerations, 6,693 addresses. 7DA5C6F1… (mem5, 14393): 0, 0, 156. 26487ED4… (no capture of this set): 0, 0, 7,834. The public PDBs give function and data names but no types, so no member offset in this specification has a type source. |

### Layout (kept, measured)

`layouts.go` holds one layout, keyed by `winkernel.FileSetBuild` 19041, which serves builds 19041 to 19045. 14393 and 26100 have no layout (S67 M14, M15). Member offsets used, in bytes, with the member names the layout file gives (owner question Q3):

| Group | Members (19041 to 19045) |
|---|---|
| List node | `next` 0, previous 8 (next + pointer), value from 16 |
| String | characters inline at 0 or `pointer` at 0, `length` 16 (8 bytes), `capacity` 24 (8), size 32 |
| Vector | `begin` 0, `end` 8, `capacityEnd` 16 |
| History node | `commands` 16 (vector of strings), `capacity` 40 (8 bytes), `application` 48 (string), `process` 80 (pointer), `lastDisplayed` 92 (2 bytes, signed), size 96 |
| Attached-process record | `pid` 28 (4 bytes); a `handle` at 48 is not in the layout |
| Console | `screenWidth` 32, `screenHeight` 34 (2 bytes each), `historySize` 144, `historyMax` 148 (4 bytes each), `processList` 1368 with `processCount` 1376, `screenList` 1392, `title` 1688, `originalTitle` 1752, `activeScreen` 1816, `aliases` 8976 (list head, size 8 later), `historyList` 9064 with `historyCount` 9072 |
| Console parts | process node: record pointer at 16; alias entry: `name` 16, inner list at 56; alias: `source` 16, `target` 48; screen: `textBuffer` 56, `next` 64; text buffer: `rows` 8 (array of row pointers), `rowCount` 32 (8 bytes), `firstRow` 88 (2 bytes, signed); row: `cells` 8, `width` 80 (8 bytes) |

### Measurements

M1 to M9 come from `consolefacts` on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100).

| # | Measured |
|---|---|
| M1 | Registry: 43 `Console` keys and subkeys across the five captures (4 on mem1, 8 on mem2, 9 on mem5, 11 on mem6, 11 on mem7), 17 of them the `Console` key itself. The 11 that set `HistoryBufferSize` set 50 and `NumberOfHistoryBuffers` 4; no key sets other values. `ScreenBufferSize` is 0x23290078 under `Console` (low word 120, high word 9001) and 0x0bb80078 under the two PowerShell subkeys (120, 3000); `WindowSize` is 0x001e0078 and 0x00320078. |
| M2 | `conhost.exe` processes: none on mem1 and mem7; one each on mem2 (PID 3804), mem5 (5944) and mem6 (6780). Their VADs reserve about 2 TB each (2,203,486,965,760 bytes on mem2), of which the page tables map 5,705, 2,934 and 2,430 pages; every mapped page reads. |
| M3 | Strings: the 2 titles of the mem2 console and the 1 history application name have capacities above 7, live behind the pointer, and have a NUL after the last character. No inline string was met on the captures. |
| M4 | mem2 console search, sizes 50 and 4: 1 candidate, accepted. It lies in the `conhost.exe` image (a data-section global), at an address ≡ 8 mod 16, so the settings pair is 8-aligned. Its process list (size 1), history list (size 1) and alias list (size 0) each close on the head with the size member's count; 4 bytes before the alias list head read 1.0 as a 32-bit float. |
| M5 | The mem2 console: title "Windows PowerShell", original title the `powershell.exe` path, screen buffer 120 × 3000, history settings 50 and 4. The screen buffer size equals `ScreenBufferSize` of both PowerShell subkeys (low word columns, high word rows). One attached process, PID 8400, listed by the kernel. One screen buffer, the active one, on the screen list. |
| M6 | Screen rows (mem2): `rowCount` 3000 equals the console's rows; 3000 distinct row pointers; each row's cell vector (begin at `cells`, end 8 bytes later) spans exactly 3 bytes per column, and every row is printable when read at a stride of 3 (first two bytes a UTF-16 unit). Row `width` is 135 in every row, wider than the console's 120 columns. `firstRow` is 0. The two words after the row pointer array's pointer are 4096 and 0. |
| M7 | Histories (mem2): the console's one history has buffer size 50 (equal to the console's `HistoryBufferSize`), application "powershell.exe", recall position −1, 0 commands, and its `process` member names the attached record of PID 8400. |
| M8 | History search: mem2, 102 candidates with 50 at `capacity`; 1 accepted (the console's history, found both ways), 101 rejected by H1, and every one of those 101 also fails H3. mem6 (26100), 253 candidates, all rejected by H1 and H3; searching the host for UTF-16 the capture program's image name, "cmd.exe" and "powershell.exe" finds only environment blocks and stack copies, so this host holds no history to measure. |
| M9 | mem5 (14393) has no measured layout; both tools refuse it. |

## 4. Algorithm

### 4.1 Layout

1. Read the build (S03). A 32-bit kernel, a version other than 10.0, or a build whose file set (`winkernel.FileSetBuild`) has no layout is refused with `ErrUnsupportedVersion`.
2. `windows.console.list` also refuses a layout without console members, quoting the layout's reason. No current layout lacks them; 26100 has no layout at all and is refused by step 1 (S67).

### 4.2 Finding consoles

1. **Sizes.** The `max_history` option's values, or 50 when it is absent (M1); then every `HistoryBufferSize` a `Console` key or subkey sets, unless `no_registry` (F10, F13). The same for `NumberOfHistoryBuffers` with `max_buffers`, default 4 (M1). A console keeps the size it was created with, so a registry value changed later still finds the consoles made before it.
2. **Hosts.** Every process named `conhost.exe` (F1, case-insensitive) that the `pid` option keeps. Its regions are its VADs; the search reads only the pages its page tables map, clipped to the VADs (M2). When the page lister does not build (`NewPageLister` fails), every VAD page is read, with no diagnostic (O11). When it builds but a host's pages do not list, every VAD page of that host is read, with a diagnostic.
3. **Search.** For every size pair, the 8 bytes `HistoryBufferSize | NumberOfHistoryBuffers << 32` at 8-byte-aligned addresses: the two settings are adjacent UINT members (F10, layout), and the measured console puts them 8-aligned (M4).
4. Each hit, less the offset of `historySize`, is a candidate. It is accepted when it passes C1 to C5 (section 5).

### 4.3 Finding histories

1. **Sizes** as 4.2 step 1, history buffer sizes only.
2. **Search.** Each size as a value of the layout's `capacity` width (8 bytes on 19041), aligned to that width.
3. Each hit, less the `capacity` offset, is a candidate node, accepted when it passes H1 to H6 with the searched size.

### 4.4 Reading a console

1. **Settings.** Screen buffer columns and rows from `screenWidth` and `screenHeight` read as a `COORD` (signed, F8); `HistoryBufferSize` and `NumberOfHistoryBuffers` from `historySize` and `historyMax` (F10).
2. **Titles.** `title` and `originalTitle` as strings (4.6.1; F7).
3. **Attached processes.** Walk `processList` (4.6.2). Each node's record pointer leads to the record; its `pid` is the process ID. Each PID is marked when the kernel's process list holds it (M5).
4. **Command histories.** Walk `historyList`; each node that passes H1 to H6 (any nonzero buffer size) is read as 4.5.
5. **Aliases.** Walk the list at `aliases` (size one pointer after the head; M4). Each entry is one executable: `name` is its name, and the list at the entry's inner offset holds that executable's aliases, each a `source` and a `target` string (F9).
6. **Screen buffers.** From `screenList`, follow each buffer's `next` until null, a repeat, or `MaxListEntries`. The one equal to `activeScreen` is marked active; if none is, the screens part is incomplete (F2).
7. **Screen text.** For each buffer: its text buffer, the row pointer array at `rows`, `rowCount` rows and `firstRow`. Row *j* of the screen is stored at index (`firstRow` + *j*) mod `rowCount` (M6, O3). Each row has `width` cells of 3 bytes, the first two a UTF-16 unit (F2, M6). A row's text is its units decoded and cut at the last character that is not a space or NUL; rows that are empty after that are left out.
8. Each part that does not read whole is listed in `Incomplete` with its reason; the rest of the console is still read.

### 4.5 Reading a history

1. `capacity` is the buffer size, `lastDisplayed` the recall position (−1 when nothing is recalled; F11, O4).
2. `application` is the application name (F11).
3. `process` points to the owner's attached-process record; its `pid` is the owner's PID (M7).
4. `commands` is a vector of strings (F5); each string is one command, oldest first. A command that does not read is kept, marked unreadable. More than `MaxRowsPerObject` commands are cut.

### 4.6 Containers

1. **String.** Read `length` and `capacity`; they must be non-negative with `capacity` ≥ 7 and `length` ≤ `capacity` (F4, F6). With `capacity` ≤ 7 the characters are in the object; otherwise behind `pointer`, which must hold `capacity` + 1 units inside one region. `length` × 2 bytes past `MaxTextBytes` is not read.
2. **List.** Read the head pointer and the size. The head node must read. Walk `next` from the head: each node's previous pointer must name the node walked before it; the walk ends at the head, whose previous pointer must name the last node; the node count must equal the size (F3). `MaxListEntries` stops the walk.
3. **Vector.** `begin` ≤ `end` ≤ `capacityEnd`, both spans whole elements, and a nonempty span inside one region (F5). Three nulls are an empty vector.
4. **Pointers.** Every pointer followed must land, with the bytes read from it, inside one VAD of the host.

## 5. Validity rules

| Rule | Check | Justification | On failure |
|---|---|---|---|
| P1 | A pointer and its bytes lie inside one VAD | VADs describe the reserved user space (S24) | `ErrOutside` |
| C1 | Screen buffer columns and rows above 0, read as `SHORT` | F8 | Candidate rejected, `ErrScreenBufferSize` |
| C2 | The attached-process list walks (4.6.2) and holds at least one node | F3, F12, M4 | Rejected; `ErrListLink`, `ErrListCount`, `ErrNoProcess` |
| C3 | The history list walks | F3, M4 | Rejected |
| C4 | Both titles have a string's shape | F4, F6, M3 | Rejected, `ErrStringShape` |
| C5 | No more histories than `NumberOfHistoryBuffers` | F10, M7 | Rejected, `ErrTooManyBuffers` |
| H1 | The node's next node names it as previous, and its previous node names it as next | F3 | Rejected, `ErrListLink` |
| H2 | Buffer size nonzero and, for a searched candidate, the size searched for | F10 | Rejected, `ErrCapacity` |
| H3 | The commands are a vector of whole strings | F5 | Rejected, `ErrVectorShape` |
| H4 | No more commands than the buffer size | F10, F11 | Rejected, `ErrHistoryFull` |
| H5 | The application name is a string with at least one character | F11, M7 | Rejected, `ErrNoApplication` |
| H6 | Recall position −1, or below the command count (0 when there are none) | F11, M7 | Rejected, `ErrRecallPosition` |
| S1 | `rowCount` above 0 and within `MaxRowsPerObject`, `firstRow` in 0 to `rowCount` − 1 | M6 | The screen has no rows; part incomplete (`ErrRowShape`) |
| S2 | Row width above 0 and its text within `MaxTextBytes` | M6 | That row is left out; screen marked incomplete |
| S3 | The active screen is on the screen list | F2, M5 | Screens part incomplete (`ErrNoActiveScreen`) |

## 6. Failure modes

| Case | Result |
|---|---|
| Not a Windows profile | `<tool>: unsupported profile os "<os>"` |
| Option of the wrong type | `<tool>: tools: option value of the wrong form: "<key>" is …; want …` |
| A size of 0 or above 2^32 − 1 | `<tool>: option "<key>": tools: option value of the wrong form: <n> is not a 32-bit count above zero` |
| Build unreadable | The `winkernel` error |
| No layout, or no console members for the list tool | `ErrUnsupportedVersion` |
| Process list fails | `<tool>: process list: <error>` |
| A host's address space or VADs do not build | Diagnostic `<tool>: process <pid> at 0x<eprocess>: address space not built: …` or `VADs not read: …`; the host is skipped |
| Page lister does not build | Every VAD is searched; no diagnostic (O11) |
| A host's pages do not list | Diagnostic `<tool>: process <pid> at 0x<eprocess>: present pages not listed, every VAD is searched: …` |
| `MaxRegionScanBytes` or `MaxMatchesPerChunk` reached | Diagnostic `… search cut short: consolelist: …`; the candidates found so far are checked |
| Rejected candidates | One diagnostic per host: `<tool>: process <pid> at 0x<eprocess>: <n> candidates rejected: <rule> <count>, …` |
| No console in a host | Diagnostic `windows.console.list: process <pid> at 0x<eprocess>: no console state found` |
| Part of a console does not read | Row kept with `Incomplete`; diagnostic `windows.console.list: console at 0x<addr>: <part>: <error>`; in strict mode the rows and `ErrIncomplete` |
| A history's commands or name do not read | Row kept, commands marked; diagnostic `windows.console.scan_history: history at 0x<addr>: not every command read`; strict mode as above |

## 7. Result schema

`windows.console.list` returns `[]consolelist.Console`, sorted by host PID, then address:

| Field | Type | Meaning |
|---|---|---|
| `PID`, `Process` | uint64, string | The host |
| `Address` | uint64 | The console state in the host |
| `Title`, `TitleUnreadable`, `OriginalTitle`, `OriginalTitleUnreadable` | string, bool | F7 |
| `ScreenBufferColumns`, `ScreenBufferRows` | int | F8 |
| `HistoryBufferSize`, `NumberOfHistoryBuffers` | uint32 | F10 |
| `AttachedProcesses` | `[]AttachedProcess{Record, PID, InProcessList}` | List order |
| `Aliases` | `[]Alias{Address, Executable, Source, Target}` | List order |
| `Histories` | `[]History` | List order |
| `Screens` | `[]Screen{Address, Active, Columns, RowCount, Rows []ScreenRow{Row, Text}, Incomplete}` | Chain order; `Columns` is the widest row read |
| `Incomplete` | []string | One entry per part that did not read whole |

`History`: `Address` (the node), `Application`, `ApplicationUnreadable`, `BufferSize`, `RecallPosition` (int64, −1 none), `OwnerRecord`, `OwnerPID`, `OwnerPIDKnown`, `Commands []Command{Index, Address, Text, Unreadable}` (oldest first), `CommandsIncomplete`.

`windows.console.scan_history` returns `[]consolehistory.FoundHistory`: `PID`, `Process` and the embedded `History`, sorted by host PID, then node address.

Both tools emit nothing for an empty part: a console with no aliases has a nil `Aliases`. An unread value is marked by its flag, never by a placeholder string.

## 8. Limits

- `MaxRegionScanBytes`: bytes searched per host, counted in pages. The default (1 GiB) is far above the 5,705 pages measured (M2).
- `MaxMatchesPerChunk`: candidates per host search.
- `MaxListEntries`: nodes per list walk, and screen buffers per chain.
- `MaxRowsPerObject`: commands per history and rows per screen buffer (3000 measured, M6).
- `MaxTextBytes`: bytes of one string or one row's text.

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/consolelist/s33_fixture_test.go`, on the 19041 layout and a history-only copy of it): a whole console with titles, a process, a history with commands, aliases and two screens with a wrapped row ring; each of C1 to C5 and H1 to H6 broken alone; an empty history; an unreadable command and row; the limits; inline and heap strings and their refusals; the search's alignment, page skipping and budgets; `Run` end to end on a process fixture, its refusals, options and strict mode. `consolehistory` tests build their heap from `Layout.Members()` only.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzReadConsole` (arbitrary console object and heap; an accepted console keeps C1, C2, C5, row order and limits): 302,768 executions. `FuzzReadHistory` (the 19041 layout, arbitrary heap and node; accepted histories keep H2, H4, H6 and command indices): 2,074,067. `FuzzWideString` (arbitrary string object; length ≤ capacity, capacity ≥ 7, inline exactly when capacity ≤ 7): 1,892,738.
3. On the captures, `consolefacts`, 2026-11-12:

| Capture | Build | Hosts | Pages searched | Consoles (accepted / rejected) | Screens (rows, non-blank) | Histories via console | History candidates (accepted / rejected H1) | Commands |
|---|---|---|---|---|---|---|---|---|
| mem1_win11 | 26100 | 0 | — | refused | — | — | — | — |
| mem2_win10 | 19045 | 1 | 5,705 | 1 / 0 | 1 (3000, 9) | 1 | 1 / 101 | 0 |
| mem5_server2016 | 14393 | 1 | — | refused | — | — | refused | — |
| mem6_server2025 | 26100 | 1 | 2,430 | refused | — | — | 0 / 253 (measured before 26100 was refused (S67); the tool now refuses this capture) | — |
| mem7_server2025 | 26100 | 0 | — | refused | — | — | — | — |

4. Layout members checked by `consolefacts`:

| Confirmed on mem2 (19045) | Evidence |
|---|---|
| List node `next`, previous, value at 16 | Process, history and alias lists close on their heads with their sizes (M4); H1 on the history |
| String `pointer`, `length`, `capacity` (heap form) | Titles and application read, NUL after the last character (M3) |
| Vector `begin`, `end`, `capacityEnd` | Cell vectors span 3 bytes per column for 3000 rows (M6); the empty command vector |
| History `capacity`, `application`, `process` | 50, "powershell.exe", the attached record (M7) |
| Record `pid` | 8400, a listed process (M5) |
| Console `screenWidth`, `screenHeight` | Equal the PowerShell `ScreenBufferSize` (M5) |
| Console `historySize`, `historyMax` | The search pair (M4) and the registry (M1) |
| Console `processList`/`processCount`, `historyList`/`historyCount`, `title`, `originalTitle`, `activeScreen`, `screenList`, process node record | M4, M5 |
| Screen `textBuffer`; text buffer `rows`, `rowCount`; row `cells`, `width` | M6 |

| Not confirmed | Why |
|---|---|
| String inline form | No inline string on the captures (M3); the form follows from F6 |
| History `commands` element reading, `lastDisplayed` beyond −1 | The only history holds no commands (M7) |
| Alias entry `name`, inner list, alias `source` and `target` | The only console has no aliases (M4) |
| Screen `next` past the first buffer; text buffer `firstRow` other than 0 | One screen buffer, `firstRow` 0 (M6) |
| 26100 members (no 26100 layout) | No 26100 host holds a history (M8); S67 M15 |
| Record `handle` | Not read by either tool |

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Only one console and one history on one capture confirm the 19041 layout; the 26100 history members are unmeasured (M8) and 14393 has no layout. | Owner decision; captures with `cmd.exe` sessions holding commands and `doskey` aliases on 19045, 26100 and 14393 (Q-captures) |
| O2 | The defaults 50 and 4 rest on the registry values of every capture (M1); no Learn page states the defaults. | Owner decision on measured defaults |
| O3 | Screen row order from `firstRow` as a ring start, and the two words after the row array pointer (4096 and 0, M6), are inferred, not confirmed: `firstRow` is 0 on the only screen. The reader does not use the second word; if it is a start offset it would rotate the rows. | A capture whose screen has scrolled past its buffer size |
| O4 | The recall position's meaning (the index of the command last recalled, −1 for none) follows F11's description of recall, not a member definition. It is reported raw. | Owner decision; a capture with recalled commands |
| O5 | Row width (135) differs from the console's screen buffer columns (120) on the only screen (M6). `Screen.Columns` reports the row width. | A capture after a known resize |
| O6 | Row field names (Q2) are new: `Console`, `AttachedProcess`, `Alias`, `Screen`, `ScreenRow`, `History`, `Command`, `FoundHistory` replace the flat `Row` of both tools. The registered tool names and option keys are unchanged. | Owner decision (Q2) |
| O7 | The private member names in `layout.go` and `layouts.go` (`historySize`, `historyMax`, `lastDisplayed`, `firstRow` and the rest) are kept as they were (Q3); their full re-measurement is a later step. | Owner decision (Q3), the layout re-measurement step |
| O8 | Microsoft publishes the console host's source; it was not used, being outside this wave's allowed sources. It could confirm or replace every measured offset. | Owner decision on that source |
| O9 | The settings-pair alignment (8 bytes) rests on one console (M4); a console placed at 4 mod 8 would be missed. | More captures; or a 4-byte step at about twice the candidates |
| O10 | Follow-up R8: the O6 rows hold no member addresses; a console's or history's own address is the only address in its rows. A history names its attached process record (4.5 step 3); the record's handle is not read. Owner decision 2026-11-12: keep these rows. Done: no row field changed. | Closed |
| O11 | `FindHosts` (`tools/windows/consolelist/host.go`) drops the error of `NewPageLister`: when the page lister does not build, every VAD of every host is searched and nothing is reported. Only a failed `Pages` call for one host gives a diagnostic. Owner decision 2026-11-12: kept for v0.1.0; a diagnostic when the page lister does not build in v0.2.0. | v0.2.0 |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Supply the three captures |
| O2 | Keep 50 and 4 |
| O3 | Defer; keep inferred order |
| O4 | Report raw |
| O5 | Defer; report row width |
| O6 | Accept the new names |
| O7 | Keep until re-measurement |
| O8 | Keep measurement only |
| O9 | Keep 8-byte alignment |

## 11. Provenance

Written from Microsoft Learn's Windows Console and C++ Standard Library documentation, [MS-SHLLINK], the project's conhost symbol tables (which hold no types), the kept measured layout, and the project's measurements. Every rule rests on the sources and measurements above. The pre-rewrite measurement script `conhost` was not read beyond the call sites fixed to keep it compiling.
