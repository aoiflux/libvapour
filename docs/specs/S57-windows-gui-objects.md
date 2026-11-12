# S57: Windows GUI objects: window stations, desktops and windows

Version 1, 2026-11-12.

## 1. Purpose

Every interactive Windows session has a window station, `WinSta0`, holding desktops, and every desktop holds windows that belong to threads of some process. Services get window stations of their own. An examiner wants to see, from a memory capture, which window stations and desktops existed in each session, which processes had threads attached to each desktop, and which windows each desktop held, with their text, their window procedure and their owning process. Window stations and desktops are executive objects, so they can also be found in pool memory after they have left their lists.

The structures behind this belong to `win32kbase.sys` and `win32kfull.sys`. Their public symbol files carry no types for them. This specification defines how their member offsets were measured on the captures and confirmed by disassembly, how the objects are found (a pool scan for window stations and desktops; lists from there), the checks that keep a wrong pointer from passing for an object, and the rows the four tools return: `windows.gui.scan_stations`, `windows.gui.list_desktops`, `windows.gui.scan_desktops` and `windows.gui.list_windows`.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory and symbols | The kernel's own table (`_OBJECT_HEADER`, `_OBJECT_TYPE`, `_ETHREAD.Cid`, `_CLIENT_ID`, `_EPROCESS`, `ObTypeIndexTable`, `ObHeaderCookie`), and the module list (`modulelist`, frozen). |
| Physical memory | The pool scan's address space (S31), through the `physical_memory` option the session sets; also the frame a prototype entry gives for `win32kbase.sys`'s header (4.1). |
| Session spaces | One process address space per session (`processlist`, frozen; `tools.Context.ProcessSpace`). |
| Layout | `tools/gui/layouts.go`: the measured member offsets of section 3, one layout per `win32kbase.sys` build. |
| Options | None of the tools' own; `strict` and `diagnostics` from `tools.Context`. The registered tool names are kept. |
| Limits | `MaxListEntries`, `MaxRecursionDepth`, `MaxTextBytes`, `Workers` (section 8). |

The image is untrusted: every member can hold anything.

## 3. Facts from the sources

### Documentation

Microsoft Learn pages, accessed 2026-11-12.

| # | Fact | Source |
|---|---|---|
| F1 | A window station holds a clipboard, an atom table and one or more desktops; it is a securable object; a new one is assigned to the current session. The interactive window station is always named "WinSta0", and each Remote Desktop session has its own WinSta0. | "Window Stations", ms.date 2018-05-31 |
| F2 | A desktop holds windows, menus and hooks; it is a securable object and belongs to the window station of the process that created it. The interactive window station has three desktops by default: Default, ScreenSaver and Winlogon. | "Desktops", ms.date 2018-05-31 |
| F3 | Window station names are case-insensitive and cannot contain backslash characters. | "CreateWindowStationW function", ms.date 2018-12-05 |
| F4 | Desktop names are case-insensitive and may not contain backslash characters. Desktops store their resources in the desktop heap; the `SharedSection` registry value sets its size per desktop. | "CreateDesktopW function", ms.date 2018-12-05 |
| F5 | A service without its own window station gets one named from its logon session, `Service-0x0-3e7$` for LocalSystem, with a desktop named default. | "Window Station and Desktop Creation", ms.date 2018-05-31 |
| F6 | The system assigns a desktop to each thread that connects to a window station. | "Thread Connection to a Desktop", ms.date 2018-05-31 |
| F7 | A 64-bit process's user space is 0x000'00000000 through 0x7FFF'FFFFFFFF; all kernel-mode code shares one system space. | "Virtual Address Spaces" (Windows drivers), ms.date 2024-06-28 |
| F8 | The desktop window is the base of every window shown; a window with a parent is a child window; a top-level window has no parent or has the desktop window as its parent; every window has a window name and a window class whose chief part is the window procedure. | "About Windows", ms.date 2025-07-14 |
| F9 | `GWLP_WNDPROC` is −4 and sets a new address for the window procedure. A window can have a parent or an owner, never both. | "SetWindowLongPtrW function", ms.date 2018-12-05 |
| F10 | `WS_CHILD` is 0x40000000 and `WS_POPUP` is 0x80000000; the two cannot be combined. | "Window Styles", ms.date 2025-07-14 |
| F11 | Session zero hosts services; the first user to log on uses session one, the next session two. | "Kernel object namespaces", ms.date 2018-05-31 |

### Symbol tables

`guifacts -tables` over the project's symbol cache, 2026-11-12. The captures' own PDBs were fetched through `tools.Context.LoadPDB`.

| # | Fact |
|---|---|
| P1 | No `win32kbase.pdb` (7F11BE3D…, A8A69A7F…, 9E281667…, 9424C46D…) and no `win32kfull.pdb` table has a record; they hold addresses only (10,012 to 14,890). The `win32k.pdb` tables of the 26100 captures (31ABB602…, DD5462F9…) have none either. No table has a `tagWND`, `tagDESKTOP`, `tagWINDOWSTATION` or `tagTHREADINFO` record. |
| P2 | The `win32k.pdb` tables of 14393 (262CBFD4…, 376 records) and 19045 (B8F07CAE…, 444 records) type the base parts: `_W32PROCESS.Process` (`_EPROCESS*`) at 0 (width 288 and 296), `_W32THREAD.pEThread` (`_ETHREAD*`) at 0 (width 360 and 392), and `_W32THREADNONPAGED.pW32Thread` (`_W32THREAD*`) at 0 (width 24 and 56). |
| P3 | The kernel tables give `_KTHREAD.Win32Thread`, `_EPROCESS.Win32Process`, `_ETHREAD.Cid` with `_CLIENT_ID.UniqueThread`, `_EPROCESS.UniqueProcessId` and `ImageFileName`, and the `_OBJECT_HEADER`, `_OBJECT_TYPE` and `ObTypeIndexTable` facts of S31 (T2 to T7). `ObTypeIndexTable` names `WindowStation` and `Desktop` types whose pool tags are `Wind` and `Desk` (S31 M1). |
| P4 | The kernel tables give `_MMPTE_PROTOTYPE.ProtoAddress` as a signed 48-bit member at bits 63:16 on every build (S53 W4). |

### Disassembly

`guifacts -routines` decodes the captured `win32kfull.sys` code through the project's `disasm` package, located by the PDB's public addresses. Offsets in hex.

| # | Routine (rva per capture) | What the code shows |
|---|---|---|
| D1 | `_GetDesktopWindow` (19045 0x70420; 14393 0x8774c; 26100 server 0x37e30; 26100 client 0x52050) | From a window: the pointer at +18 (the window's desktop), from it the pointer at +8 (desktop information), from that the pointer at +18 (+10 on 14393): the desktop window. |
| D2 | `_GetParent` (19045 0xd3424; 14393 0xdf1bc; 26100 0x1bd23c, 0x16dbcc) | Reads the style's top byte (shadow +1f on 19045 and 26100, after loading the shadow from window +28; window +37 on 14393), masks 0xc0: with `WS_CHILD` (F10) returns the pointer at window +68 (+58 on 14393), the parent; with `WS_POPUP` the one at +78 (+68), the owner (F9). |
| D3 | `_GetThreadDesktop` (19045 0x104134) | Reads the thread information's +1a8 and compares it with the current process's information: the process information member. |
| D4 | `NtUserInternalGetWindowText` with `getStrName` and `DesktopVerifyHeapLargeUnicodeString` (19045 0xfce00, 0xfcf38, 0xfcf9c; 14393 0xee660; 26100 server 0x1af650; client 0x162180) | 19045 and 26100: the text buffer is the pointer at window +b8; its length is the 32-bit value at shadow +b8 and its maximum the one at shadow +bc, masked with 0x7fffffff. The text is refused when the length or the maximum is odd or the length is not below the maximum, and when the buffer and its maximum are not inside the desktop heap: base the pointer at desktop +80 (19045), +78 (14393, 26100 server), +88 (26100 client); size the 32-bit value 8 bytes later. 14393: the whole counted string is at window +d8 (length, maximum, buffer at +e0). |
| D5 | `xxxSetWindowLongPtr` (14393 0x9eea4) | On index −4 (`GWLP_WNDPROC`, F9) writes window +90: the window procedure. On 19045 and 26100 the routine dispatches through a table and was not followed (O4). |

### Measurements

M1 to M9 come from `guifacts -discover` and `-tools`, M10 from `guifacts -prototype` and `-tools`, and M11 from `guifacts -object`, on 2026-11-12 over mem1_win11 (26100 client, win32kbase 9424C46D…), mem2_win10 (19045, A8A69A7F…), mem5_server2016 (14393, 7F11BE3D…), mem6_server2025 and mem7_server2025 (26100 server, 9E281667…). The oracles are the kernel's own objects: each thread's `_KTHREAD.Win32Thread`, each process's `_EPROCESS.Win32Process`, and object types decoded from the `_OBJECT_HEADER` in front of a pointer (S31 M2).

| # | Measured |
|---|---|
| M1 | `Win32Thread` never points to the thread information itself; its first pointer does (252 of 253, 437 of 445, 302 of 302, 356 of 360, 237 of 244 threads), matching P2's nonpaged block. That thread information's first pointer is the thread (P2). |
| M2 | Thread information members, by the values they must hold (counts of the threads above): process information (`Win32Process` of the owner) at 1d0 (242, 343, 224 on mem1, mem6, mem7), 1a8 (426 on mem2), 170 (302 on mem5); a `Desktop` object at 1f0 (228, 327, 209), 1c8 (410), 190 (283); a list entry pointing to another thread information at the same offset at 308 (220, 320, 195), 2e8 (398), 288 (271). |
| M3 | Desktops (from M2's desktop member: 6, 9, 10, 8, 9 desktops, every one readable through the kernel's own space): the pointer shared with every thread's information at desktop +8 (thread +1f8, +1d0, +198); a `WindowStation` object at +28 (+18 on 14393) for every desktop; another `Desktop` or null at +20 (+10); the thread list head, a ring whose first entry links back, at +b0 (mem1, 5 of 6), +a8 (mem2, 9 of 9), +a0 (mem5 10 of 10, mem6 8 of 8, mem7 7 of 9). |
| M4 | Window stations (from M3: 5, 7, 7, 6, 6): the 32-bit value at +0 equals the session of the desktop's threads for every one; +10 points to a desktop whose station member names it back for every one; +8 is null or another `WindowStation`. The pool scan of section 4.3 places every scanned station at a kernel address (5, 8, 7, 6, 7). |
| M5 | Desktop thread lists: of the threads whose desktop member names a reached desktop (228, 410, 283, 327, 209), a forward walk that does not check back links reaches 73, 347, 282, 304, 78, and 1, 2, 0, 1, 4 walks break on an unreadable or repeated link. A walk that stops at the first back link that does not match reached 74 rows on mem1 and 106 on mem2; the walk of 4.6 reaches 239 and 422. |
| M6 | Windows: the desktop information's pointer at +18 (+10 on 14393) leads to an object whose +10 is a thread information, +18 the desktop and +20 its own address (6, 9, 10, 8, 9 desktops). Following every pointer from there that leads to such an object reaches 400, 482, 346, 489, 284 windows. Among them +58 (+48) leads to a window whose +60 (+50) points back (340, 406, 232, 388, 227) and whose +68 (+58) is the same (340, 407, 233, 388, 227): next and previous sibling, parent; +70 (+60) leads to a window whose +68 (+58) points back (53, 63, 22, 93, 47): first child. |
| M7 | Shadow copy (19045, 26100): the pointer at window +28 leads to an object whose first word equals the window's (400 of 400, 482 of 482, 489 of 489, 280 of 284); 0 of 346 on 14393. The value at window +30 is the shadow's offset from the desktop heap base (4.8). In the shadow, the pointer at +78 lies inside an image mapped in the owner's process (387, 400, 426, 96) and the one at +20 is an image's base (358, 372, 379); on 14393 the window's own +90 lies inside an image (238) and +38 is a base (229). A counted UTF-16 string at shadow +b8 decodes (172, 228, 210, 124 heap-relative); on 14393 at window +d8 (129). |
| M8 | Session-space addresses repeat across sessions: windows of sessions 1 and 2 on mem2 share virtual addresses, and a walk keyed by address alone reached 44 or 410 windows depending on visiting order. Every object below a station is therefore read through its station's session space. |
| M9 | `win32kbase.sys`'s header page reads through some process of each capture except mem7, where no process maps it (a prototype page, M10). The image sizes (`SizeOfImage` from the module list) are 0x332000 and 0x40e000 (mem1), 0x2d6000 and 0x3b4000 (mem2), 0x180000 and 0x388000 (mem5), 0x343000 and 0x402000 (mem6 and mem7) for `win32kbase.sys` and `win32kfull.sys`. |
| M10 | mem7, kernel leaf entries over `win32kbase.sys` (835 pages): 407 present, 424 prototype, 4 other. Every prototype entry names an 8-byte-aligned system-space entry (P4) that reads: 76 transition entries and 348 that are not resident. The header page's leaf 0xDF09603560000408 names 0xFFFFDF0960356000, which holds the transition entry 0x625C5820; frame 0x625C5000 holds a PE header whose `SizeOfImage` (0x343000) equals the module list's, and its CodeView record names the 26100 server `win32kbase.pdb` (9E281667…). `win32kfull.sys` (405 prototype leaves) and `win32k.sys` (127) have their header targets not resident. On mem1, mem2, mem5 and mem6 no prototype leaf covers the header: it is present in kernel memory (mem1, mem6) or in session space (mem2, mem5). |
| M11 | mem1, the address 0xFFFF9E0405FBB958 read as a window station body: its object header would be at 0xFFFF9E0405FBB928, 8 bytes off a 16-byte boundary (S31 D1, M3). The nearest "Wind" bytes, at 0xFFFF9E0405FBB87C, are bytes 12 to 15 of the 16-byte pool header of a "FOCX" allocation at 0xFFFF9E0405FBB870, not a pool tag. At the would-be header, `PointerCount` is 0 and `TypeIndex` names no object type; read as a station, its next member is 0x58434F46020300C5 (the bytes of a "FOCX" pool header) and its desktop list 0x98A08E85, both failing S2. |

### Layouts

`tools/gui/layouts.go`. Member names are this specification's (O3). Hex offsets.

| Member | 14393 | 19045 | 26100 server | 26100 client | Evidence |
|---|---|---|---|---|---|
| Station: session ID (4 bytes), next, desktop list | 0, 8, 10 | same | same | same | M4 |
| Desktop: information, next, station | 8, 10, 18 | 8, 20, 28 | 8, 20, 28 | 8, 20, 28 | M3, D1 |
| Desktop: thread list head | a0 | a8 | a0 | b0 | M3 |
| Desktop: heap base, heap size (4 bytes) | 78, 80 | 80, 88 | 78, 80 | 88, 90 | D4 |
| Desktop information: desktop window | 10 | 18 | 18 | 18 | M6, D1 |
| Thread information: thread, process information, desktop, desktop link | 0, 170, 190, 288 | 0, 1a8, 1c8, 2e8 | 0, 1d0, 1f0, 308 | 0, 1d0, 1f0, 308 | P2, M1, M2, D3 |
| Process information: process | 0 | 0 | 0 | 0 | P2, M2 |
| Window: thread, desktop, self | 10, 18, 20 | same | same | same | M6, D1 |
| Window: next sibling, parent, first child | 48, 58, 60 | 58, 68, 70 | 58, 68, 70 | 58, 68, 70 | M6, D2 |
| Window: shadow, shadow heap offset | none | 28, 30 | 28, 30 | 28, 30 | M7, D2 |
| Text: length, maximum, buffer | window d8, dc, e0 | shadow b8, bc; window b8 | same as 19045 | same as 19045 | D4, M7 |
| Procedure | window 90 | shadow 78 | shadow 78 | shadow 78 | D5, M7 |

## 4. Algorithm

### 4.1 Layout

1. The kernel table's pointer size must be 8; otherwise `ErrNot64Bit`.
2. Find `win32kbase.sys` in the module list (`ErrNoWin32kBase`). Read its debug directory's CodeView record (PE/COFF) through each session space (4.2) in session order, then kernel memory, then every session process's space in list order (M9). In kernel memory, a page whose leaf entry is a prototype entry is read from the frame of the entry it names (`layers.PrototypeEntryAddress`, S53 4.3), when that entry lies in system space and is valid or in transition (`layers.ResolveProtoPTE`); any other target leaves the page unread (M10). Physical memory must be known for this.
3. The layout is the one whose `win32kbase.pdb` GUID and age equal the record's.
4. When no reader yields the record, the capture is refused with `ErrNoDebugRecord`; a record that names no measured layout is `ErrUnsupportedVersion`. Image sizes and the kernel build do not choose a layout: two builds with equal sizes may differ in layout (O2).

### 4.2 Session spaces

For each session ID the process list holds, the first process (in list order) whose address space builds gives the session's reader (M8, F11). A session without one is read through kernel memory, with one diagnostic.

### 4.3 Window station scan

1. The S31 executive scan of tag `Wind`, object type `WindowStation`, any page type, the allocation large enough for the pool header, the object header and the station members.
2. Each body is read from physical memory: session ID, next and desktop list. Rule S2 holds.
3. The name comes from the object header's name information (S31 4.10); rule S1 holds.
4. The S31 placement gives the kernel address; rows keep S31's order.

### 4.4 Desktop list

1. From the station's desktop list member, follow each desktop's next member until null, through the station's session space.
2. Each desktop must be a `Desktop` object (rule D1), its pointers rule D2, its station member the station's address (rule D3). A station without a kernel address takes the address the first desktop names when the station there is a `WindowStation` object holding the same three members.
3. A repeat (D4), `MaxListEntries`, or a failed rule ends the walk with a diagnostic; strict mode returns the error.
4. The desktop's name comes from its object header.

### 4.5 Desktop scan

The S31 executive scan of tag `Desk`, object type `Desktop`. A body is kept when it passes D2, has a valid name (S1), and its station member leads, through kernel memory, to a `WindowStation` object whose members read (S2); that station gives the session and the station's name.

### 4.6 Desktop threads

1. Walk the thread list from the head forward with the S03 walker without back-link checks, then, when the forward walk broke, backward from the head's back link; entries met twice count once (M5).
2. Each entry less the desktop link offset is a thread information. Its thread pointer must be a `Thread` object (rule T1); its desktop member must name this desktop (T2; counted otherwise). The thread ID is `_ETHREAD.Cid.UniqueThread`.
3. The owner: the process information member, then its process pointer, which must be a `Process` object (T3); PID and image name from `_EPROCESS`. An owner that does not read leaves the thread row flagged.

### 4.7 Windows

1. The desktop information's desktop window is the root, depth 0.
2. Visit a window, then each child: the first child member, then each child's next sibling, depth first (F8, M6, D2).
3. A window must name itself (W1) and this desktop (W2); a child must name its parent (W3); its child member must be null or in system space. A window that fails is counted by reason and left out with its subtree, and its sibling chain ends there, since its links cannot be trusted.
4. A window met twice (W4), depth above `MaxRecursionDepth`, or `MaxListEntries` windows on the desktop end the walk with a diagnostic; strict mode returns the error.
5. The owner thread comes from the window's thread member as in 4.6 steps 2 and 3; a window with none has an empty owner.

### 4.8 Window text and procedure

1. With a shadow layout: the shadow is the pointer at the window's shadow member; it must lie in the desktop heap, and its distance from the heap base must equal the window's shadow offset member (W5, M7). Otherwise text and procedure are unread.
2. The text: length and maximum from their places (window or shadow), maximum masked with 0x7fffffff; the buffer from the window (D4). A null buffer or a length of 0 is an empty text. Otherwise rule W6, then the length's bytes decode as UTF-16LE.
3. The procedure: the 8-byte value at its place, reported as read (F9, D5).

## 5. Validity rules

| Rule | Check | Justification | On failure |
|---|---|---|---|
| S1 | Object name present, readable, nonempty, no backslash, no control character, no U+FFFD replacement character | F3, F4 | Station or desktop not reported |
| S2 | Station next and desktop list pointers null or in system space | F7, M4 | Not reported (`ErrNotSystemSpace`) |
| D1 | A listed desktop is a `Desktop` object | S31 M2, M3 | Walk ends (`ErrWrongType`) |
| D2 | Desktop information, next and station null or in system space | F7, M3 | Walk ends, or a scanned desktop is not reported |
| D3 | A listed desktop names its station | F2, M4 | Walk ends (`ErrOtherStation`) |
| D4 | No desktop twice, at most `MaxListEntries` | | Walk ends (`ErrListRepeats`, `ErrListLimit`) |
| T1 | A thread information's thread is a `Thread` object | P2, M1 | Thread left out with a diagnostic |
| T2 | The thread names the desktop whose list holds it | F6, M2 | Thread left out, counted (`ErrOtherDesktop`) |
| T3 | The owner's process is a `Process` object | P2, M2 | Row kept, owner unreadable |
| W1 | The window's self member is its address | M6 | Window and subtree left out (`ErrNotSelf`) |
| W2 | The window names the walked desktop | D1, M6 | Left out (`ErrOtherDesktop`) |
| W3 | A child names its parent | F8, D2, M6 | Left out (`ErrOtherParent`) |
| W4 | No window twice; depth and count within limits | | Walk ends (`ErrListRepeats`, `ErrTreeDepth`, `ErrTooManyWindow`) |
| W5 | The shadow lies in the desktop heap at its recorded offset | D2, M7 | Text and procedure unread (`ErrOutsideHeap`) |
| W6 | Even length and maximum, length below maximum, whole maximum in the desktop heap, length within `MaxTextBytes` | D4 | Text unread (`ErrTextShape`, `ErrOutsideHeap`) |

## 6. Failure modes

| Case | Result |
|---|---|
| Not a Windows profile | `<tool>: unsupported profile os "<os>"` |
| 32-bit kernel | `<tool>: gui: 64-bit kernels only` |
| No `win32kbase.sys`, no record, or an unmeasured record | `<tool>: gui: win32kbase.sys is not in the module list`; `gui: win32kbase.sys debug record does not read: image at 0x<base>: …`, ending for a prototype page in `prototype entry at 0x<entry>: …` or `prototype frame 0x<frame>: …`; `gui: no measured layout for this win32kbase.sys: …` |
| Kernel table lacks a type or `ObTypeIndexTable` lacks a type | `<tool>: gui: kernel table lacks a type the objects are read with: …` |
| No physical memory | `<tool>: gui: no physical memory to scan` |
| Pool scan | S31's errors and diagnostics; one summary diagnostic `<tool>: pool tag "<tag>": <n> objects from <m> tag hits (<stats>)` |
| Process list fails | Diagnostic `<tool>: process list: …; session objects are read through kernel memory` |
| A list walk stops | Diagnostic `<tool>: <object> at 0x<addr>: list walk stopped: <error>`; strict mode returns it |
| Thread list breaks | The S03 walker's diagnostic, `<tool>: desktop at 0x<addr>: thread list forward|backward …` |
| Threads left out | `<tool>: thread info at 0x<addr>: …`; `<tool>: desktop at 0x<addr>: <n> threads on its list are left out: gui: object names another desktop` |
| Windows left out | `windows.gui.list_windows: desktop at 0x<addr>: windows left out with their subtrees: <reason> <n>, …` |

## 7. Result schema

`windows.gui.scan_stations` returns `[]guistations.Station` in S31 order: `Address` (kernel address of the body, 0 when unplaced), `Physical`, `Name`, `SessionID` (uint32), `OtherCopy` (S31's other mapped body, 0 for none).

`windows.gui.list_desktops` returns `[]guidesktops.Desktop`, station by station in scan order, desktops in list order, threads in walk order; `ByStation` returns them grouped (`StationRows{Station, Desktops, Rows}`). Fields: `Address`, `SessionID`, `Station` (name), `Name`, `NameUnreadable`, `Threadless` (one row for a desktop with no thread), `TID`, `PID`, `Process`, `ProcessUnreadable`, `OtherCopy` (scan only).

`windows.gui.scan_desktops` returns the same rows for each scanned desktop, in S31 order.

`windows.gui.list_windows` returns `[]guiwindows.Window` in tree order per desktop, desktops as above, and `ByStation`: `Address`, `SessionID`, `Station`, `Desktop`, `DesktopAddress`, `DesktopUnreadable`, `Parent` (0 for the desktop window), `Depth`, `Text`, `TextUnreadable`, `Procedure`, `ProcedureUnreadable`, `TID`, `PID`, `Process`, `ProcessUnreadable`.

An unread value is flagged, never replaced by a placeholder. Addresses below a station are session-space addresses of the row's `SessionID` (M8).

## 8. Limits

- `MaxListEntries`: desktops per station, entries per thread-list walk, windows per desktop.
- `MaxRecursionDepth`: window tree depth (the deepest measured is 10).
- `MaxTextBytes`: one window text.
- `Workers`: the pool sweep (S31).

## 9. Acceptance

1. Synthetic fixtures (`tools/gui/guitest/s57_fixture.go`: real x64 page tables, pool and object headers, every object laid out by a `gui.Layout`): every layout reads two stations, three desktops, two threads and a five-window tree; a `win32kbase.sys` header and debug directory on prototype pages (transition and valid targets) identified by record, a record read that way naming no layout, a target not resident, a target outside system space, and no physical memory (`s57_prototype_test.go`, on the S64 fixture); each of S1, S2, D1 to D4, T1 to T3, W1 to W6 broken alone; desktop and sibling loops; `MaxListEntries` and `MaxRecursionDepth`; strict mode; layout choice by record; a `win32kbase.sys` without a readable record refused even when its sizes equal a measured layout's; refusals; each tool's rows and its registration.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzStationAndDesktopMembers` (an accepted station or desktop has every pointer null or in system space): 3,782,112 executions. `FuzzWindowText` (accepted text obeys W6 and the limit): 3,721,405. `FuzzWindowWalk` (arbitrary window memory: no window twice, every parent before its child, depth and count within limits): 3,416,188. `FuzzPrototypeHeaderEntries` (arbitrary leaf and target entries for the header page: no panic, and a prototype entry outside system space is never followed): 1,487,478.
3. On the captures, `guifacts -tools`, 2026-11-12:

| Capture | Layout | Stations (sessions 0/1/2) | Desktops | Thread rows | Threadless desktops | Scanned desktops (rows) | Windows | With text | Text unread | Deepest |
|---|---|---|---|---|---|---|---|---|---|---|
| mem1_win11 | 26100 client, by record | 5 (4/1/–) | 9 | 239 | 3 | 9 (242) | 245 | 101 | 0 | 10 |
| mem2_win10 | 19045, by record | 8 (5/1/2) | 14 | 422 | 5 | 14 (427) | 308 | 128 | 3 | 10 |
| mem5_server2016 | 14393, by record | 7 (4/1/2) | 13 | 310 | 3 | 13 (313) | 250 | 99 | 0 | 9 |
| mem6_server2025 | 26100 server, by record | 6 (4/1/1) | 12 | 323 | 4 | 12 (327) | 311 | 121 | 3 | 9 |
| mem7_server2025 | 26100 server, by record through the prototype entry (M10) | 7 (5/1/1) | 13 | 213 | 3 | 13 (216) | 187 | 78 | 3 | 9 |

   - Every scanned station has a kernel address, and every desktop on a station's list is found again by the desktop scan.
   - Station names: `WinSta0` in every session, `Service-0x0-3e7$`, `Service-0x0-3e4$`, `Service-0x0-3e5$` in session 0 (F1, F5), plus per-capture service and sandbox stations; desktops `Default`, `Winlogon`, `Disconnect` on every `WinSta0`.
   - Every procedure that reads is nonzero; the three windows per capture with unread text are the same three with unread procedure (W5).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Only four `win32kbase.sys` builds are measured; any other is refused. The two 26100 layouts differ in three desktop members (M3, D4), so a third 26100 revision may differ again. | Owner decision; more captures, and the `guifacts -discover` run on each |
| O2 | When the debug record does not read, the layout is chosen by kernel build and two image sizes (mem7). Two builds with equal sizes and different layouts would be told apart wrongly. Owner decision 2026-11-12: refuse such captures. Done: 4.1 step 4, 6, 9; `LayoutForImages` and `Layout.BaseImageSize`/`FullImageSize` removed (`tools/gui/layout.go`, `layouts.go`, `env.go`), test `TestAWin32kBaseWithoutADebugRecordIsRefusedWhateverItsSizes`. Measured 2026-11-12: mem1, mem2, mem5 and mem6 still identify by record with unchanged rows; mem7 is refused by all four tools (its `win32kbase.sys` header is a prototype page no process maps, M9). Remains: reading that header through its prototype PTE would let mem7 identify by record. Owner decision 2026-11-12 (follow-up D13): read through the prototype PTE before release. Done: 4.1 step 2, P4, M10, 9; `tools/gui/prototype.go` (new), `tools/gui/env.go`, `layers.PrototypeEntryAddress` (S53 4.3, O11), `testsupport.AddressSpace.SetEntry`; tests in `tools/gui/s57_prototype_test.go`. mem7 now identifies by record and gives 7 stations and 187 windows, as before O2; mem1, mem2, mem5 and mem6 do not use the new path (M10). | Owner decision |
| O3 | Member names (`Info`, `Threads`, `Link`, `Shadow`, `ShadowOffset` and the rest) are this specification's, from what the measurement shows (Q3). | Owner decision (Q3) |
| O4 | The procedure's place on 19045 and 26100 (shadow +78) rests on measurement (M7) only; the routine that writes it was not followed (D5). | Disassembly of the dispatch in `xxxSetWindowLongPtr`, or a capture with a known subclassed window |
| O5 | The thread walk skips back-link checks and judges entries by content (4.6, M5). This finds about three times the threads the strict walk finds on smeared captures, at the cost of trusting forward links. | Owner decision on the walk rule |
| O6 | Row fields are new (Q2): `Offset` became `Address`; stations gain `Physical`; desktop rows renamed `WindowStation` to `Station`, `Session` to `SessionID`, `Desktop` to `Name`, `DesktopUnreadable` to `NameUnreadable`, and gained `Threadless`, `TID`, `ProcessUnreadable`; window rows renamed `Window`/`WindowNotAvailable` to `Text`/`TextUnreadable`, `ProcedureNotAvailable` to `ProcedureUnreadable`, `DesktopOffset` to `DesktopAddress`, `Session` to `SessionID`, and gained `Parent`, `Depth`, `TID`, `ProcessUnreadable`. Tool names unchanged; the tools have no options. | Owner decision (Q2) |
| O7 | A desktop with no thread now gets one row with `Threadless` set; window rows take their session from the station, not the owner process. Owner decision 2026-11-12 (follow-up R6): keep threadless desktops. No code change. | Owner decision |
| O8 | A rejected window ends its sibling chain (4.7 step 3), so a single bad link hides its later siblings. | Owner decision |
| O9 | The window procedure is reported raw; whether it lies in an image of the owner, or in a kernel module for server-side windows, is not checked or attributed. | A later attribution step |
| O10 | mem1: the address 0xFFFF9E0405FBB958 read as a window station body (M11). Owner decision 2026-11-12 (follow-up R7): probe. Result: not a bug. It has no 16-byte aligned object header in front of it and its "Wind" bytes lie inside another allocation's pool header (M11), so S31 4.2 step 1 refuses it and S2 would too. No library change. | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Refuse other builds |
| O2 | Refuse such captures |
| O3 | Accept names |
| O4 | Defer to v0.2.0 |
| O5 | Skip back-links, judge content |
| O6 | Accept |
| O7 | Threadless row, station session |
| O8 | End the chain |
| O9 | Defer to v0.2.0 |
| O10 | Probe (follow-up R7): not a bug |

## 11. Provenance

Written from Microsoft Learn's window station, desktop and window documentation, the PE/COFF debug directory, the kernel and `win32k*.pdb` tables of the captures through the project's symbol cache, disassembly of the captured `win32kfull.sys` through the project's `disasm` package, S31 and S03, and the project's measurements with `guifacts`. Every rule rests on the sources and measurements above. The pre-rewrite `tools/gui` files were read only for exported names, callers and tool names; the pre-rewrite GUI measure script was not read, and `guifacts` replaced it.
