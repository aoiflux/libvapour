# S03: Windows list entries and the kernel build

Version 1, 2026-11-11.

## 1. Purpose

Windows keeps most of its kernel and loader inventories in doubly linked lists of `LIST_ENTRY`: the active processes, each process's loader lists, the bug-check and registry callbacks. Several tools also pick a structure layout by the Windows build. Each of those tools had its own list walker and its own build reader, with different rules for a broken link, a loop, a cap and a missing field.

This specification defines one list walker and one build reader. Both are only readers. Each tool keeps its own decisions: what a list entry holds, which entries it keeps, and which builds it supports.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Memory | memory reader | The address space that holds the list or the kernel's data: the kernel space, or a process's user space for a loader list. |
| Layout | width 4 or 8; Flink and Blink offsets | The `LIST_ENTRY` shape in that space (section 4.1). |
| Head | address | The list head, a `LIST_ENTRY` that is not an entry. |
| Label | string | Names the list in a diagnostic, such as `PsActiveProcessHead`. |
| Tool | string | The tool's name, the first word of every diagnostic. |
| Limit | integer | `Limits.MaxListEntries` from the tool's `Bounds()`. |
| Strict | boolean | The tool context's strict mode. |
| Symbols | kernel symbol table | For the build reader: the `_KUSER_SHARED_DATA` type, the `NtBuildNumber` symbol, and the pointer size. |

All of these come from the image or from the caller. The image is untrusted: every pointer in it can hold any value.

## 3. Facts from the sources

| # | Fact | Source |
|---|---|---|
| L1 | A `LIST_ENTRY` is `{ Flink; Blink }`, two pointers to `LIST_ENTRY`. | Microsoft Learn, "LIST_ENTRY structure (ntdef.h)". |
| L2 | In the head, Flink points to the first entry and Blink to the last. In an empty list both point to the head. `InitializeListHead` sets `ListHead->Flink = ListHead->Blink = ListHead`. | Microsoft Learn, "LIST_ENTRY structure"; Microsoft Learn, "Singly and Doubly Linked Lists"; WDK 10.0.28000.0 `km/wdm.h`, `InitializeListHead`. |
| L3 | In an entry, Flink points to the next entry or to the head, and Blink to the previous entry or to the head. | Microsoft Learn, "LIST_ENTRY structure". |
| L4 | So for every entry E, `E->Flink->Blink == E` and `E->Blink->Flink == E`. `RtlpCheckListEntry` tests exactly this. `RemoveEntryList`, `RemoveHeadList` and `InsertTailList` test the links they touch, and call `FatalListEntryError`, which raises `RtlFailFast(FAST_FAIL_CORRUPT_LIST_ENTRY)`, when a test fails. Windows does not operate on an entry that fails. | WDK 10.0.28000.0 `km/wdm.h`, `RtlpCheckListEntry`, `RemoveEntryList`, `RemoveHeadList`, `InsertTailList`, `FatalListEntryError`. |
| L5 | `LIST_ENTRY32` is `{ ULONG Flink; ULONG Blink; }` and `LIST_ENTRY64` is `{ ULONGLONG Flink; ULONGLONG Blink; }`. | WDK 10.0.28000.0 `shared/ntdef.h`. |
| L6 | The kernel PDB describes `_LIST_ENTRY` (Flink at 0, Blink at 8, size 16 on x64), `LIST_ENTRY32` (Flink at 0, Blink at 4) and `LIST_ENTRY64`. | Measured 2026-11-11 in the four ntkrnlmp tables in the project's symbol cache (GUIDs 0D960CE1, 3DFC5F72, 953A8DE8, F57E740B). |
| L7 | `CONTAINING_RECORD(address, type, field)` returns the base of the structure that holds `field` at `address`: the address minus the field's offset. | Microsoft Learn, "CONTAINING_RECORD macro (ntdef.h)". |
| L8 | Windows on ARM32 and ARM64 runs little-endian. x86 and x64 processors are little-endian. | Microsoft Learn, "Overview of ARM64 ABI conventions", section "Endianness"; Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 1, 1.3.1. |
| B1 | `KUSER_SHARED_DATA` is mapped at `KI_USER_SHARED_DATA`. In kernel mode this is `0xFFFFF78000000000` on AMD64 and ARM64, `0xffdf0000` on x86 and `0xFFFF9000` on ARM32. | WDK 10.0.28000.0 `km/wdm.h`, `KI_USER_SHARED_DATA`; Microsoft Learn, "KUSER_SHARED_DATA structure (ntddk.h)". |
| B2 | The same header has a `RELOCATABLE_USER_SHARED_DATA` build, in which `KI_USER_SHARED_DATA` is the address of a variable `ki_user_shared_data`. | WDK 10.0.28000.0 `km/wdm.h`. Measured: none of the four kernel tables has a `ki_user_shared_data` symbol. |
| B3 | `KUSER_SHARED_DATA` has `ULONG NtBuildNumber`, "the shared collective build number undecorated with C or F", and `ULONG NtMajorVersion` and `ULONG NtMinorVersion`, "the NT major version" and "the NT minor version". | Microsoft Learn, "KUSER_SHARED_DATA structure (ntddk.h)". |
| B4 | The kernel PDB places these members at 0x260, 0x26c and 0x270 in all four tables. `ntddk.h` asserts the offset 0x260 of `NtBuildNumber`. A table for a kernel older than Windows 10 has no `NtBuildNumber` member. | Measured in the four tables (L6); WDK 10.0.28000.0 `km/ntddk.h`, `C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtBuildNumber) == 0x260)`. |
| B5 | The kernel PDB has a global symbol `NtBuildNumber`. The tables record its address but not its type. None of the four tables has a global `NtMajorVersion` or `NtMinorVersion`. | Measured in the four tables (L6). |
| B6 | `ULONG` is an unsigned 32-bit integer. | Microsoft Learn, "Windows Data Types". |
| B7 | Windows 10 versions 2004, 20H2, 21H1, 21H2 and 22H2 have OS builds 19041, 19042, 19043, 19044 and 19045. | Microsoft Learn, "Windows 10 release information" (release health), accessed 2026-11-11. |
| B8 | Windows 10 versions 2004, 20H2, 21H1, 21H2 and 22H2 "share a common core operating system with an identical set of system files". | Microsoft Support, KB5015684, "Featured update to Windows 10, version 22H2 by using an enablement package", accessed 2026-11-11. |

## 4. Algorithm

### 4.1 Layout

1. The caller names the type and the width. A list in the kernel's own space uses `_LIST_ENTRY` and the symbol table's pointer size. A 32-bit list inside a 64-bit space uses `LIST_ENTRY32` and width 4 (L5).
2. The Flink offset comes from the type's `Flink` member. A table without it gives no layout, and the caller gets an error.
3. The Blink offset comes from the type's `Blink` member. Every kernel PDB measured describes it (L6). A table without it, such as a hand-built test table, gives a layout without Blink. Section 4.3 says what that changes.
4. The width is 4 or 8. Any other width is an error. Each pointer is read as an unsigned little-endian integer of that width (L1, L5, L8).

### 4.2 Reading an entry

One read covers both links: the bytes from the entry's address to the end of the later of the two members. A read that fails, returns fewer bytes or would pass the end of a 64-bit address space makes the entry unreadable.

### 4.3 The forward walk

1. Read the head. If it does not read, the walk does not start. The caller gets an error in every mode, because there is no partial result to give.
2. Start with `prev` = the head. Repeat:
   1. `next` = `prev.Flink`.
   2. If `next` is the head, the list is complete. With a Blink, the head's Blink must be `prev`, the last entry walked (L2). If it is not, the walk ends with a back-link break at the head. A list ended this way still lists every entry walked.
   3. If `next` is 0, the walk ends with a null-link break. No list routine in L2 to L4 writes a null link.
   4. If `next` was walked before, the walk ends with a cycle break. In a well-formed list only the head is reached twice (L2, L3).
   5. If `next` does not read (4.2), the walk ends with an unreadable break.
   6. With a Blink, `next.Blink` must be `prev` (L4). If it is not, the walk ends with a back-link break, and `next` is not listed. Windows itself refuses to work on such an entry (L4). In a capture the cause is smear or tampering, and an entry that the list does not link back cannot be shown to belong to it.
   7. If the walk has already listed `Limit` entries, it ends with a limit break.
   8. List `next`, and set `prev` = `next`.
3. The result lists the address of each `LIST_ENTRY` walked, in walk order, without the head.

The order of the tests in step 2 decides which break a malformed list reports. A link back to an earlier entry is reported as a cycle, not as a back-link break, because the cycle is the more specific fact.

Without a Blink, steps 2.2 and 2.6 are skipped. The walk then relies on the cycle test, the null test, the unreadable test and the limit.

### 4.4 The recovering walk

The walker offers a second mode for callers that want every entry still reachable from the head.

1. Walk forward (4.3). If that walk is complete, stop.
2. If it ended at the limit, or the layout has no Blink, stop.
3. Otherwise walk backward from the head with the same steps, using Blink as the way on and Flink as the back-link (L2, L3, L4). An entry already walked is a cycle break, except an entry that the forward walk listed. Reaching one of those means that the two walks met, and the backward walk ends without a break, without the back-link test: the forward walk already listed that entry.
4. The result lists the forward entries, then the backward entries in backward order, and says how many entries came from the backward walk. The limit counts the entries of both walks together.

When the backward walk also breaks, an entry between the two breaks is not listed. The result keeps both breaks so that the caller can say so.

### 4.5 Breaks, strict mode and diagnostics

1. A break is an error value of the form `<tool>: <label> <head or entry> at 0x<address>: <what failed>: <sentinel>`, and wraps the sentinel of section 6.
2. In strict mode the first break is returned as the walk's error, and the walk returns no entries.
3. Otherwise every break is reported once through the caller's diagnostic sink, and the walk returns the entries listed before it, with the break in the result.

### 4.6 Container

`Container(entry, offset)` is `entry - offset` (L7). If `entry` is smaller than `offset`, there is no container, and the caller decides what to do.

### 4.7 The build reader

1. **Shared data address.** `0xFFFFF78000000000` for a symbol table with 8-byte pointers, and `0xFFDF0000` for 4-byte pointers (B1). A 4-byte table is read as an x86 kernel. ARM32 and the relocatable build are out of scope (section 10).
2. **NT version.** Read `NtMajorVersion` and `NtMinorVersion` as 4-byte unsigned little-endian values (B3, B6, L8), at the shared data address plus the member offsets from the table's `_KUSER_SHARED_DATA` (B4). If either member is missing or does not read, the NT version is not read, and both values are 0.
3. **Shared build.** Read `NtBuildNumber` from the same structure in the same way. A table without the member (B4) gives no shared build. Learn calls this value undecorated (B3), so it is used as read.
4. **Kernel build.** Look up the global symbol `NtBuildNumber` (B5) and read 4 bytes at its address. The tables do not record its type (B5), so the width is that of the `KUSER_SHARED_DATA` member of the same name (B3). The top 4 bits are the decoration, and the low 28 bits are the kernel build (open point O1).
5. The reader does not judge whether a value is plausible. A zero or out-of-range value is returned as read. Each caller decides what it accepts.

### 4.9 File-set build

`FileSetBuild` maps a kernel build to the build whose system files it ships. Builds 19042 to 19045 map to 19041, because B7 and B8 give those five releases one set of system files. Every other build maps to itself. A layout measured on any build in the range serves the whole range. Callers that key layouts by kernel build look them up by the file-set build.

### 4.8 Caller decisions that stay with the caller

| Caller | Walk or read | The caller's own decision |
|---|---|---|
| `any.process.list` | Recovering walk of `PsActiveProcessHead`, member `ActiveProcessLinks`. | An unreadable head is an error. An entry with no `_EPROCESS` around it that reads is skipped with a diagnostic. |
| `windows.library.list`, and `windows.library.compare` through it | Recovering walk of each of the three loader lists. | A loader record found on any list is kept once, with the lists it was found on. |
| `windows.callback.list` | Forward walk of the bug-check and registry callback lists. | A head that does not read gives no rows for that list, with a diagnostic. |
| `windows.execution.list_compat_cache` | Recovering walk of the cache list. | Gives each entry its position from the head, and from the tail when the forward walk closed; an entry only the backward walk found has a position from the tail only. |
| Pool scans (`tools.Context.RequirePoolScanBuild`) | NT version, else kernel build. | Refuses NT versions below 6.2, and kernel builds below 9200. |
| `windows.console.list` | NT version and kernel build. | Layouts per file-set build (4.9). |
| `windows.callback.list`, `windows.service.scan`, `windows.service.list`, `windows.service.compare` | Kernel build. | Layouts per file-set build (4.9). |
| Network scan symbols | Kernel build, else shared build when the NT version is 10.0. | Only the builds of a measured tcpip layout: 14393, 19041 to 19045, and 26100. |

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Every listed entry `E` has `E.Blink` equal to the entry before it, when the layout has a Blink. | L4 | Back-link break; `E` is not listed. |
| The head's Blink is the last entry walked, when the walk returns to the head. | L2 | Back-link break at the head; the entries walked stay listed. |
| No entry is listed twice. | L2, L3 | Cycle break. |
| No link is null. | L2 to L4 | Null-link break. |
| Every listed entry reads whole. | 4.2 | Unreadable break; the entry is not listed. |
| At most `Limit` entries are listed. | Section 8 | Limit break. |
| The width is 4 or 8. | L1, L5 | Layout error before any read. |

## 6. Failure modes

| Sentinel | Meaning |
|---|---|
| `ErrListUnreadable` | The head or an entry does not read. For the head, the walk does not start. |
| `ErrListNull` | A link is 0. |
| `ErrListCycle` | A link returns to an entry already walked. |
| `ErrListBackLink` | An entry, or the head at the end, does not link back to the entry before it. |
| `ErrListLimit` | The list is longer than `Limit`. |
| `ErrListLayout` | The layout's width is not 4 or 8. |
| `ErrBuildUnread` | A version member or the `NtBuildNumber` symbol is missing or does not read. |

Each error names the tool, the list label or structure member, and the address. A missing Flink member in the symbol table is returned by the layout constructor as an error that wraps the symbol table's own error.

## 7. Result schema

`ListWalk`:

| Field | Type | Meaning |
|---|---|---|
| `Entries` | list of addresses | Each `LIST_ENTRY` walked, head excluded: the forward entries, then the backward ones. |
| `Backward` | integer | How many of the last `Entries` came from the backward walk. |
| `Forward` | error or none | Why the forward walk stopped short; none when it returned to the head. |
| `Back` | error or none | Why the backward walk stopped short; none when it met the forward walk, returned to the head, or did not run. |

`Build`:

| Field | Type | Meaning |
|---|---|---|
| `Major`, `Minor` | 32-bit unsigned | `KUSER_SHARED_DATA.NtMajorVersion` and `NtMinorVersion`. |
| `VersionErr` | error or none | Why the NT version was not read. |
| `Kernel` | 32-bit unsigned | The low 28 bits of the kernel's `NtBuildNumber`. |
| `Decoration` | 4 bits | The top 4 bits of the kernel's `NtBuildNumber`. |
| `KernelErr` | error or none | Why the kernel build was not read. |
| `Shared` | 32-bit unsigned | `KUSER_SHARED_DATA.NtBuildNumber`. |
| `SharedErr` | error or none | Why the shared build was not read. |

## 8. Limits

- Entries per walk: the caller's `Limits.MaxListEntries` from `Bounds()`. A value of 0 or below means the project default, `limits.DefaultMaxListEntries`.
- Memory per walk: one address set and one result list, each at most `Limit` entries.
- Bytes per read: the later member offset plus one pointer, 16 bytes for `_LIST_ENTRY` on x64.

## 9. Acceptance

- Table tests on synthetic lists, 4-byte and 8-byte: an intact list, an empty list, a back-link mismatch on an entry and at the head, a cycle, a null link, an unreadable entry, an unreadable head, the limit, strict mode, and a layout without Blink.
- Recovering walk: a forward break recovered completely by the backward walk; two breaks with an entry between them missed; a limit break that does not start a backward walk.
- `Container` at, below and above the member offset.
- Build reader tests: every value read; each member missing; each read failing; a 4-byte table read at `0xFFDF0000`; the decoration split.
- A fuzz target over arbitrary memory contents: the walk never lists an entry twice, never lists more than `Limit` entries, never lists the head, and in strict mode returns entries only when it has no error.

## 10. Open points

- **O1. Decoration bits.** Learn says the shared build is "undecorated with C or F" (B3). The reader takes the letter to be a hex digit in the top 4 bits of the kernel's variable. No Microsoft document states that position. Measured 2026-11-12 with `buildfacts` on five captures (builds 14393, 19045, 26100 three times): the top 4 bits are 0xF on every one, and the low 28 bits equal the shared build every time. The position stays an inference for builds not measured.
- **O2. Kernel build of the Windows 10 22H2 capture.** Measured 2026-11-12 with the same script: the kernel's `NtBuildNumber` reads 19045, as the shared copy does. The console, callback and service layouts were measured on that capture, so the owner decided on 2026-11-11 to key them by file-set build (4.9). Builds 19041 to 19044 have no capture of their own; they rest on B8 alone.
- **O3. Relocatable shared data and ARM32.** B1 and B2 are out of scope: no measured kernel uses them, and the project supports no ARM32 profile.
- **O4. Entries between two breaks.** The timer lists of the captures break in both directions on dozens of lists, and a reference timer listing held seven timer rows on mem2 that the recovering walk does not give. Owner decision 2026-11-12: probe the walk. Result: not a bug. Measured with `timerwalkfacts` on mem1, mem2, mem5 and mem7 (S64 T9): every entry a Flink walk without the back-link test reaches past a recovering walk's break lies past a link that does not point back, and the seven mem2 rows are five timers reached that way only. Step 2.6 stops there by design: Windows does not operate on such an entry (L4), and it cannot be shown to belong to the list. Section 4.4's statement that an entry between two breaks is not listed stands. Done: no walker change; the finding is S64 T9 and O16, and the real-image timer gate counts these rows.

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept the measured inference |
| O2 | Key by file-set build |
| O3 | Keep out of scope |
| O4 | Probe the walk |

## 11. Provenance

Sources: as cited in section 3, accessed 2026-11-11. The WDK headers are those of WDK 10.0.28000.0. Measurements: `buildfacts`, and `timerwalkfacts` for O4. Author: the project.
