# S23: Windows Kerberos crypto-system check

Version 1, 2026-11-12.

## 1. Purpose

Kerberos in the LSA process encrypts and decrypts tickets through one routine set per encryption type. cryptdll.dll keeps those sets in a table in its own data, one entry per registered type. An implant that wants a second, master password accepted can overwrite routine pointers in that table so that calls go to its own code. The table then points outside the module that registered the entry.

An examiner needs to know, for each lsass.exe in the capture, which encryption types are registered and whether any routine pointer of any entry lands outside the module that registered the entry. This specification defines where the table is found, how an entry is read, and what counts as redirected.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory and symbol table | The ntoskrnl tables, used by the process list (S25) and the VAD walk (S24). The pointer size must be 8 (8.). |
| Process list | `tools/any/processlist`; processes whose image name is `lsass.exe`, compared without case (F4). |
| Process memory | The process's address space from its `DirectoryTableBase`. |
| Mappings | The VAD walk of S24 through `memoryranges.Decoder`: start, end, kind (image, mapped, private, unknown), file path and VAD address of each view. |
| Prototype PTEs | `subsection.Resolver.ResolveVA` and the image's physical memory, used only as 4.2 allows. Optional. |
| PDB loader | `tools.Context.LoadPDB`, which returns the project's symbol table for a CodeView fingerprint (S32). Optional. |
| Options | `pid` (the PID set), `strict`, `diagnostics`. The tool has no options of its own. |
| Limits | `MaxNameBytes` for the entry name (8.). |

The image is untrusted. Every value can be anything.

## 3. Structures read

### Facts from public sources

| # | Fact | Source |
|---|---|---|
| F1 | Encryption type numbers are signed 32-bit values. 17 is aes128-cts-hmac-sha1-96, 18 aes256-cts-hmac-sha1-96, 23 rc4-hmac, 24 rc4-hmac-exp, 1 des-cbc-crc, 3 des-cbc-md5. "Negative values are for private use; local and experimental algorithms should use these values. Zero is reserved". | IANA, "Kerberos Parameters", registry "Kerberos Encryption Type Numbers", updated 2024-12-06, https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xml, accessed 2026-11-12. RFC 3961 section 8; RFC 3962 section 7; RFC 4757 section 5 (`KERB_ETYPE_RC4_HMAC 23`, `KERB_ETYPE_RC4_HMAC_EXP 24`). |
| F2 | An encryption system profile defines string-to-key, random-to-key, an initial cipher state, encrypt, decrypt and pseudo-random operations. | RFC 3961 section 3, https://www.rfc-editor.org/rfc/rfc3961.txt, accessed 2026-11-12. |
| F3 | PRF+ is defined from pseudo-random by concatenating its outputs over a counter. | RFC 6113 section 5.1, https://www.rfc-editor.org/rfc/rfc6113.txt, accessed 2026-11-12. |
| F4 | The LSA includes the Local Security Authority Server Service process, `LSASS.exe`. Plug-ins, among them "cryptographic plug-ins", load into the LSA. | Microsoft Learn, "Configure added LSA protection", page dated 2025-03-25, accessed 2026-11-12. |
| F5 | The PE debug directory's CodeView entry names the PDB, its GUID and age. The export directory maps names to RVAs. | Microsoft Learn, "PE Format", as used by S18; `pe.ReadCodeView`, `pe.ParseExports`. |

### Facts from the captures' own modules

The facts below come from `kerberosfacts`, run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 and mem7_server2025 (26100). It reads cryptdll.dll in each lsass.exe, its PDB through the project's tables (BuilderVersion 10), its exports, and the disassembly of its routines through the `disasm` package.

| # | Fact | Evidence |
|---|---|---|
| M1 | cryptdll.pdb has the publics `CSystems` (the table), `cCSystems` (the count), `CDLocateCSystem` and `CDRegisterCSystem`. kerberos.pdb has only the import slots `__imp_CDLocateCSystem` and `__imp_CDLocateCheckSum` (and, on 14393, `__imp_CDFindCommonCSystemWithKey`); it names no table. kdcsvc.dll is mapped in no measured lsass.exe. | mem1: cryptdll.pdb 3EBCDA59109ED8EFB1B19A2DBA7355BD age 1, RVAs 0xf1e0, 0xeb00, 0x3150, 0x3460. mem2: cryptdll.pdb 8CDC194B53A3F978BF1C6CD923C5E47E age 1, RVAs 0x101a0, 0xfac0, 0x15d0, 0x1220. On mem5 the CodeView record is not resident; the exports give `CDLocateCSystem` 0x2760 and `CDRegisterCSystem` 0x1270. On mem6 and mem7 no page of the cryptdll.dll view reads. kerberos.pdb read on mem1 (5B729E2EF89405989B49B4B14767BF9F), mem5 (D536EEADB9F04816B4EA8425149DFA2F) and mem6 (08B85E9395BAC3832F9A26048C2CB3E4). |
| M2 | `CDLocateCSystem` loads the count with a RIP-relative 32-bit `mov`, takes the table with a RIP-relative `lea`, scales the index with `shl …, 0x7`, compares the 32-bit value at the start of each entry with its first argument, and returns. The routine is 0x2e bytes on mem1, 0x2d on mem2 and 0x2a on mem5. The `mov` target is `cCSystems` and the `lea` target is `CSystems` on both builds with a PDB. | mem1 +0x00 `mov eax, dword ptr [rip+0xb9aa]` (RVA 0xeb00), +0x06 `lea r10, ptr [rip+0xc083]` (0xf1e0), +0x1c `shl rcx, 0x7`, +0x23 `cmp dword ptr [rcx], r9d`. mem2 +0x00 `mov r8d, dword ptr [rip+0xe4e9]` (0xfac0), +0x0c `lea r9, ptr [rip+0xebbd]` (0x101a0), +0x16 `shl rax, 0x7`, +0x1d `cmp dword ptr [r9], ecx`. mem5 +0x00 `mov eax, dword ptr [rip+0xe616]` (0x10d7c), +0x0a `lea r9, ptr [rip+0xcd8f]` (0xf500), +0x16 `shl r8, 0x7`, +0x1a `cmp dword ptr [r8+r9], ecx`. |
| M3 | `CDRegisterCSystem` loads the count, forms count + 1, refuses the call when that is at or above 0x18, stores count + 1, and copies 0x80 bytes from its first argument to table + count × 0x80, as eight 16-byte `movups` pairs at 0x00, 0x10, …, 0x70. The same 0x70-byte instruction sequence appears on mem1, mem2 and mem5; only the displacements differ. | mem1 +0x00 `mov eax, dword ptr [rip+0xb69a]` (0xeb00), +0x06 `lea edx, ptr [rax+0x1]`, +0x09 `cmp edx, 0x18`, +0x0c `jnb`, +0x11 `shl rax, 0x7`, +0x15 `lea r8, ptr [rip+0xbd64]` (0xf1e0), +0x1c `mov dword ptr [rip+0xb67e], edx`, +0x22 to +0x67 `movups xmmword ptr [rax+r8+0x00…0x70]`. mem2 the same with RVAs 0xfac0 and 0x101a0; mem5 the same with 0x10d7c and 0xf500, its `jnb` displacement 0x62 where the others have 0x63. |
| M4 | Every entry's quadword at 0x20 points into cryptdll.dll at a public whose name is a wide string literal, and the bytes there are NUL-terminated UTF-16 text such as "Kerberos AES256-CTS-HMAC-SHA1-96" and "RSADSI RC4-HMAC". | 29 entries on mem1 and mem2. |
| M5 | Each quadword from 0x28 to 0x78 is either 0 or the address of a cryptdll.dll public whose name ends in the same word for every entry: 0x28 `…Initialize`, 0x30 `…Encrypt`, 0x38 `…Decrypt`, 0x40 `…Finish` or `…FinishOld`, 0x48 `…HashPassword`, 0x50 `…RandomKey` or `…RandomKeyOld`, 0x58 `…Control` or `…ControlOld`, 0x60 `…Encrypt`, 0x68 `…Decrypt`, 0x70 `…PRF`, 0x78 `…PRFPlus`. 0x60 and 0x68 are set only in the two entries whose 0x30 and 0x38 are 0. No quadword in 0x28 to 0x78 is outside cryptdll.dll or on an address without a public. | mem1 13 entries, mem2 16 entries. On mem2 slot 0x28 alone has 12 distinct targets. |
| M6 | The 32-bit values at 0x04 to 0x1c differ between entries; none is a pointer. | mem1, mem2. This specification does not interpret them. |
| M7 | The code pages and read-only data of the cryptdll.dll view are partly reachable only through the view's prototype PTEs, with the process's leaf PTE reported as invalid. The pages that hold the count and the table read through the process's own page tables on every capture where the table is found. | Pages of the view (through page tables / with prototypes): mem1 23 (12 / 21), mem2 21 (11 / 12), mem5 21 (13 / 13), mem6 27 (0 / 0), mem7 27 (0 / 0). |

### Entry layout used

| Offset | Size | Meaning | Evidence |
|---|---|---|---|
| 0x00 | 4 | Encryption type, signed (F1) | M2 `cmp dword ptr [entry], etype` |
| 0x20 | 8 | Address of the entry's UTF-16 name | M4 |
| 0x28 | 8 | initialise (F2, initial cipher state) | M5 |
| 0x30 | 8 | encrypt (F2) | M5 |
| 0x38 | 8 | decrypt (F2) | M5 |
| 0x40 | 8 | finish | M5 |
| 0x48 | 8 | string-to-key (F2) | M5 |
| 0x50 | 8 | random-to-key (F2) | M5 |
| 0x58 | 8 | control | M5 |
| 0x60 | 8 | alternate encrypt | M5 |
| 0x68 | 8 | alternate decrypt | M5 |
| 0x70 | 8 | pseudo-random (F2) | M5 |
| 0x78 | 8 | pseudo-random plus (F3) | M5 |
| size | 0x80 | | M2 `shl 7`, M3 copy of eight 16-byte blocks |

The PDB has no type for the entry (M1). Every offset above rests on M2 to M5 only.

## 4. Algorithm

### 4.1 Processes

1. Refuse a symbol table whose pointer size is not 8.
2. List processes (S25). Keep those whose image name is `lsass.exe` without regard to case and whose PID is in the PID set.
3. For each kept process, read its mappings (S24) and take the views whose file path's last component is `cryptdll.dll`, without regard to case, in address order. Try each until one yields a table (4.3 to 4.5).

### 4.2 Reading the view

Image headers, the debug directory, the CodeView record, the export directory, the locate routine's code and the entry names are read page by page through the process's page tables. When that read fails with a page that the translation reports as invalid or as reachable through a prototype PTE, and a prototype resolver and physical memory are known, the page is read from the frame that the view's prototype PTE names (M7). A failure of any other kind, such as a paging-file PTE, is final: the page was private, and the prototype holds the file's bytes, not the process's.

The count and the table are read only through the process's page tables. `CDRegisterCSystem` writes both (M3), so their pages are the process's private copies. A prototype page would show the file's unregistered bytes.

### 4.3 Finding the table

1. Read the PE headers at the view's start.
2. **From symbols.** Read the CodeView record (F5) and load the PDB through `LoadPDB`. If the table has `CSystems` and `cCSystems` (M1), the table is at view start + `CSystems` RVA and the count at view start + `cCSystems` RVA. Source `symbols`.
3. **From code.** Otherwise read the export `CDLocateCSystem` (F5). Read up to 0x60 bytes of it, bounded by the view's end, and decode at most 32 instructions in 64-bit mode, stopping at the first `ret`. The count is the target of the first RIP-relative `mov` whose memory operand is a dword. The table is the target of the first RIP-relative `lea`. The scale is the immediate of the first `shl`. The result counts only if all three are found and the scale is 7 (M2). Source `code`.
4. If both fail, the table is not located (6.).

### 4.4 Reading the table

1. The count's 4 bytes and the first entry's 0x80 bytes must lie inside the view.
2. Read the count as an unsigned 32-bit value. It must be at most 0x17: `CDRegisterCSystem` refuses a call that would make it 0x18 (M3).
3. The table's count × 0x80 bytes must lie inside the view.
4. Read each entry's 0x80 bytes and decode it with the layout of section 3.

### 4.5 Judging an entry

1. **Home view.** If the name address lies in a view that has a file path, that view is the home view. Otherwise the home view is the cryptdll.dll view. `CDRegisterCSystem` copies the caller's entry (M3), so the name, a constant of the caller (M4), identifies the module that registered the entry. A routine overwrite leaves the name in place.
2. **Name.** Read UTF-16 code units from the name address until a NUL unit, at most `MaxNameBytes` bytes, through 4.2's view reader when the address is in a file view, otherwise through the page tables only. If no NUL is found or a read fails, the name is unread.
3. **Routines.** Each nonzero quadword from 0x28 to 0x78 is a routine pointer. It is **redirected** when it is outside the home view's first and last byte. It is reported with the file name and kind of the view that holds it, if any.
4. The entry is redirected when any of its routine pointers is.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Pointer size 8 | Section 3 is measured on 64-bit builds only | `ErrPointerSize`, the tool returns no rows |
| The code route needs a RIP-relative dword `mov`, a RIP-relative `lea` and `shl` by 7 before `ret` | M2 | The route fails; `ErrTableNotFound` if the symbol route failed too |
| Count and first entry inside the view | M1, M2: both are cryptdll.dll data | `ErrHeadOutsideView` |
| Count at most 0x17 | M3 | `ErrCountRange` |
| All entries inside the view | M3 | `ErrHeadOutsideView` |
| Entry reads as 0x80 bytes | M3 | `ErrEntryUnread` for that entry; the others are kept |
| Routine pointer inside the home view | M4, M5 | The routine and its entry are marked redirected; the row is kept |

## 6. Failure modes

| Sentinel | Meaning |
|---|---|
| `ErrPointerSize` | The symbol table's pointer size is not 8. |
| `ErrNoLSASS` | No lsass.exe in the process list and no PID set narrows the list. |
| `ErrMappingsUnread` | The VAD walk cannot start, or fails for this process. |
| `ErrNoTableModule` | No view of cryptdll.dll in the process. |
| `ErrTableNotFound` | Both routes of 4.3 failed; the message carries both reasons. |
| `ErrHeadOutsideView` | The count or table lies outside the view. |
| `ErrCountUnread` | The count does not read through the page tables. |
| `ErrCountRange` | The count is above 0x17. |
| `ErrEntryUnread` | An entry does not read. |

A failure for one process is a diagnostic of the form `<tool>: process <pid> at 0x<eprocess>: <what failed>: <sentinel>` or `<tool>: process <pid> <object> at 0x<address>: <what failed>: <sentinel>`, and the other processes are still read. In strict mode the first such failure ends the run with that error. A missing PDB or symbol is not a failure by itself; it only moves 4.3 to the code route.

## 7. Result schema

One row per entry read, sorted by PID, then `_EPROCESS` address, then index.

| Field | Type | Meaning |
|---|---|---|
| `PID` | uint64 | Process ID |
| `Process` | string | Image name from the process list |
| `EPROCESS` | uint64 | Kernel address of the process |
| `TableAddress` | uint64 | Table address in the process |
| `TableSource` | `Source` | `symbols` or `code` (4.3) |
| `Index` | int | Entry index in the table, from 0 |
| `EntryAddress` | uint64 | Address of the entry |
| `EncryptionType` | int32 | Encryption type (F1) |
| `EncryptionTypeName` | string | The IANA name for a registered type, without "(deprecated)"; empty for an unregistered or negative type |
| `Name` | string | The entry's name; empty when unread |
| `NameUnreadable` | bool | 4.5 step 2 failed |
| `RegisteredBy` | string | Last path component of the home view's file |
| `Routines` | []`Routine` | One per nonzero routine pointer, in offset order |
| `Redirected` | bool | Any routine is redirected |

`Routine` has `Slot` (`Slot`: `initialise`, `encrypt`, `decrypt`, `finish`, `string-to-key`, `random-to-key`, `control`, `alternate-encrypt`, `alternate-decrypt`, `pseudo-random`, `pseudo-random-plus`), `Address` (uint64), `Module` (last path component of the view's file, empty when the address is in no file view), `Kind` (the S24 kind of the view that holds the address, empty when no view does) and `Redirected` (bool).

## 8. Limits

| Bound | Value | Reason |
|---|---|---|
| Entries | 0x17 | M3; the count is refused above it, so no loop depends on unchecked image data |
| Locate code | 0x60 bytes and 32 instructions | M2: the measured routines end within 0x2e bytes and 15 instructions |
| Name | `MaxNameBytes` | The limit shared by name reads; the measured names are at most 39 UTF-16 units |
| Mappings | S24's own bounds | The VAD walk |

## 9. Acceptance

1. `kerberosfacts` on 2026-11-12:

   | Capture | lsass.exe | Source | Entries | Encryption types | Names read | Routine pointers | In cryptdll.dll | In kerberos.dll | Elsewhere |
   |---|---|---|---|---|---|---|---|---|---|
   | mem1 (26100) | PID 1844 | symbols | 13 | 18, 17, 23, −133, −128, −140, −141, 24, −135, −134, −136, −149, −148 | 13 | 99 | 99 | 0 | 0 |
   | mem2 (19045) | PID 916 | symbols | 16 | 18, 17, 23, −133, −128, 3, 1, −140, −141, 24, −135, −134, −136, −132, −149, −148 | 1 | 124 | 124 | 0 | 0 |
   | mem5 (14393) | PID 752 | code | 16 | as mem2 | 4 | 124 | 124 | 0 | 0 |
   | mem6 (26100) | PID 852 | none | 0 | | | | | | |
   | mem7 (26100) | PID 864 | none | 0 | | | | | | |

   On mem6 and mem7 no page of the cryptdll.dll view reads (M7), and the tool reports `ErrTableNotFound` as a diagnostic. With `LoadPDB` removed, mem1 and mem2 reach the same table address by the code route and give the same rows. No routine pointer is redirected on any capture, and every entry's home view is cryptdll.dll.
2. Synthetic fixtures: an lsass.exe with a cryptdll.dll view whose table is found by symbols and by code; a routine pointer in private memory, one in another module's view, one in no view; a name in another module's view, which moves the home view; a count of 0x18; a count past the view; an entry that does not read; no cryptdll.dll view; no lsass.exe; a PID set without lsass.exe; strict mode; a 4-byte pointer table; a non-Windows profile.
3. Decoder fixtures: the three measured `CDLocateCSystem` bodies (M2) give their count and table; a body with `shl` by another scale, without a `lea`, without a dword `mov`, or with `ret` first is refused.
4. Fuzz targets: entry decoding on arbitrary bytes (no panic; every routine is nonzero and in offset order), and the code route on arbitrary bytes (no panic; an accepted head came from RIP-relative operands within the window).

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | The routine offsets rest on PDB public names of the targets (M5), not on a call site that dispatches through them. | Decode the callers in kerberos.dll that call through an entry, on a build with its PDB. |
| O2 | An entry whose name and routines all lie in a module other than cryptdll.dll is reported with that module in `RegisteredBy` and is not redirected. Whether a registrant other than cryptdll.dll, kerberos.dll or kdcsvc.dll should itself be flagged is not decided. **Owner decision.** | Owner. A domain-controller capture with kdcsvc.dll would show which modules register entries. |
| O3 | Row and routine field names, the `Slot` values, and the tool name `check_kerberos_hook` are owner question Q2. The verb no longer says only "hook": the rows list every registered type. **Owner decision.** | Owner, Q2. |
| O4 | The names given to the entry offsets in section 3 (initialise, finish, control, alternate encrypt and decrypt) are this project's names for private members (Q3). **Owner decision.** | Owner, Q3. |
| O5 | 32-bit lsass.exe is not measured, and the tool refuses 4-byte tables. | A 32-bit capture, if the support matrix gains one (Q7). |
| O6 | On mem6 and mem7 lsass.exe's cryptdll.dll view is not resident at all, so the question cannot be answered there. A paging file would be needed. | Re-measure with the captures' paging files, if they exist. |
| O7 | kerberos.dll's import slot for `CDLocateCSystem` could itself be redirected. This check does not read it. | A separate check of lsass.exe import slots, if wanted. |
| O8 | The 32-bit values at 0x04 to 0x1c are not interpreted (M6). | Not needed for this check. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Defer to v0.2.0 |
| O2 | Report module, do not flag |
| O3 | Keep the names |
| O4 | Accept project names |
| O5 | Refuse 4-byte tables |
| O6 | Leave unanswered |
| O7 | Defer to v0.2.0 |
| O8 | Leave uninterpreted |

## 11. Provenance

Author: the project, 2026-11-12. Sources: as cited in section 3, with access dates: IANA Kerberos Parameters; RFC 3961, RFC 3962, RFC 4757 and RFC 6113 from rfc-editor.org; Microsoft Learn; the captures' own cryptdll.dll and kerberos.dll, their PDBs through the project's symbol tables, and their disassembly through the project's `disasm` package. Measurements: `kerberosfacts` on the five captures named in section 3. Every rule rests on the sources and measurements above.
