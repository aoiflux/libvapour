# S43: Windows process image consistency: hollowed images and ghosted image files

Version 1, 2026-11-12.

## 1. Purpose

When Windows creates a process from an image file, the kernel records that image in several places: the section the process was created from (`_EPROCESS.SectionObject`), the address where it mapped that section (`SectionBaseAddress`), the image file (`ImageFilePointer`), the full image name (`SeAuditProcessCreationInfo`) and the short name (`ImageFileName`). The process records where its image is in its own PEB (`ImageBaseAddress`), and the memory manager describes the mapped view with a VAD whose control area leads back to the file.

Two families of attack leave these records disagreeing or in an unusual state. In the first, the process's image is replaced after creation: the view is unmapped or never used, other code is put in private memory, and the PEB is pointed at it; or the mapped headers are overwritten. In the second, the process is created from an image section whose file was marked for deletion before the process started, so no file with that content remains on disk.

`windows.process.find_hollowing` answers: does what is mapped at the PEB's `ImageBaseAddress` disagree with the image the kernel recorded? `windows.process.find_ghosting` answers: is the file behind an image view, or behind the process's `ImageFilePointer`, delete pending, unnamed, or missing? This specification defines each comparison, what each finding means, and when a process is not examined.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | `_EPROCESS`, file objects, section object pointers, control areas, `_SECTION`, the audit name, VADs (through S24). |
| Process memory | The PEB and the page at `ImageBaseAddress`, through the process's own page tables (`tools.Context.ProcessSpace`). |
| Physical memory | The image section's header page, through its prototype PTE (S19). Optional: without it, rule H13 is not applied. |
| Symbol table | The ntoskrnl types of section 3.2. |
| Processes | From `any.process.list` (S25), kept by `pid`, and passed through the active filter of S17 (`processlist.ActiveProcessFilter`). |
| Ranges | `memoryranges.Decoder.Mappings` and `memoryranges.FileNames.Resolve` (S24): range, kind, protection, control area, file object, file name. |
| Options | `pid`, `strict`, `diagnostics`. No tool-specific option. |
| Limits | None of their own; the VAD walk applies `MaxListEntries` (S24 8) and the subsection walk applies it per control area (S19 8). |

## 3. Facts from the sources

### 3.1 Documentation

| # | Fact | Source |
|---|---|---|
| D1 | `FILE_OBJECT.DeletePending`: "If TRUE, a delete operation for the file associated with the file object exists. If FALSE, there currently is no pending delete operation for the file object." `FileName` "holds the name of the file opened on the volume"; "If the volume is being opened, the Length member … will be zero"; the name "is valid only during the initial processing of an IRP_MJ_CREATE request". `SectionObjectPointer` is "set only by file systems". `Flags` lists `FO_DELETE_ON_CLOSE` and `FO_TEMPORARY_FILE` without values. | Microsoft Learn, "FILE_OBJECT (wdm.h)", dated 2023-08-17, accessed 2026-11-12. |
| D2 | `FILE_DISPOSITION_INFORMATION.DeleteFile` "Indicates whether the operating system file should delete the file when the file is closed." "A file marked for deletion is not actually deleted until all open handles for the file object have been closed and the link count for the file is zero." | Microsoft Learn, "FILE_DISPOSITION_INFORMATION (ntddk.h)", dated 2018-04-30, accessed 2026-11-12. |
| D3 | `FILE_DISPOSITION_INFORMATION_EX.Flags`: `FILE_DISPOSITION_DO_NOT_DELETE` 0, `_DELETE` 0x1, `_POSIX_SEMANTICS` 0x2, `_FORCE_IMAGE_SECTION_CHECK` 0x4, `_ON_CLOSE` 0x8, `_IGNORE_READONLY_ATTRIBUTE` 0x10. With POSIX semantics "the link is removed from the visible namespace as soon as the POSIX delete handle has been closed, but the file's data streams remain accessible by other existing handles". "A return value of STATUS_CANNOT_DELETE indicates that either the file is read-only, or there is an existing mapped view to the file." | Microsoft Learn, "FILE_DISPOSITION_INFORMATION_EX (ntddk.h)", dated 2021-12-07, accessed 2026-11-12. |
| D4 | `SECTION_OBJECT_POINTERS.ImageSectionObject` is a `CONTROL_AREA` for the executable image; one `SECTION_OBJECT_POINTERS` per file stream, shared by every file object of the stream (S19 D2). | Microsoft Learn, "SECTION_OBJECT_POINTERS (wdm.h)", dated 2022-12-16, accessed 2026-11-12. |
| D5 | "Section objects also provide the mechanism by which a process can map a file into its memory address space." "A view of a section is a part of the section that is actually visible to a process." | Microsoft Learn, "Section Objects and Views", dated 2025-02-21, accessed 2026-11-12. |
| D6 | `MEM_IMAGE` memory is "mapped into the view of an image section"; `MEM_MAPPED` "into the view of a section"; `MEM_PRIVATE` is private (S24 D2). | Microsoft Learn, "MEMORY_BASIC_INFORMATION (winnt.h)", accessed 2026-11-12. |
| D7 | The documented `PEB` has `Reserved3[2]` where the tables place `ImageBaseAddress`, and the page warns "This structure may be altered in future versions of Windows." | Microsoft Learn, "PEB (winternl.h)", dated 2018-12-05, accessed 2026-11-12. |
| D8 | `SeLocateProcessImageName` "returns the full process image name for the specified process". | Microsoft Learn, "SeLocateProcessImageName", dated 2025-01-06, accessed 2026-11-12. |
| D9 | The file offset of the PE signature is at 0x3C; the signature is `PE\0\0`; the COFF file header is 20 bytes; the section table "immediately follows the optional header", located with `SizeOfOptionalHeader`. `ImageBase` is "The preferred address of the first byte of image when loaded into memory"; `SizeOfImage` is "The size (in bytes) of the image, including all headers, as the image is loaded in memory"; `SizeOfHeaders` is "The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment". | Microsoft Learn, "PE Format", dated 2026-09-10, accessed 2026-11-12. |
| D10 | "Use a backslash (\\) to separate the components of a path." "If a component of a path is a file name, it must be the last component." "Do not assume case sensitivity. For example, consider the names OSCAR, Oscar, and oscar to be the same". | Microsoft Learn, "Naming Files, Paths, and Namespaces", dated 2024-08-28, accessed 2026-11-12. |
| D11 | Pages are "typically 4 kilobytes" (S24 D3). | Microsoft Learn, "Virtual Address Spaces", accessed 2026-11-12. |

### 3.2 Kernel types

Read through the project's kernel tables with `imagefacts -types` for builds 26100 (mem1; GUID 0D960CE1…, and mem6 and mem7; 953A8DE8…), 19045 (mem2; F57E740B…) and 14393 (mem5; 3DFC5F72…).

| # | Fact |
|---|---|
| T1 | `_EPROCESS`: `SectionObject` (void *) 0x2a8, 0x518, 0x3b8; `SectionBaseAddress` (void *) 0x2b0, 0x520, 0x3c0; `Peb` 0x2e0, 0x550, 0x3f8; `ImageFilePointer` (`_FILE_OBJECT *`) 0x330, 0x5a0, 0x448; `ImageFileName` (unsigned char [15]) 0x338, 0x5a8, 0x450; `SeAuditProcessCreationInfo` (`_SE_AUDIT_PROCESS_CREATION_INFO`) 0x350, 0x5c0, 0x468 (26100, 19045, 14393). `VadCount` (unsigned long long) is 0x10 past `VadRoot` (S24 T1). |
| T2 | `_KPROCESS.SecureState` (an unnamed union the tables do not expand) at 0x170 (26100) and 0x3e0 (19045); 14393 has no `SecureState` and has `SecurePid` (unsigned long long) at 0x2d0. `_EPROCESS.Pcb` is the `_KPROCESS` at 0. |
| T3 | `_PEB.ImageBaseAddress` (void *) at 0x10 in all four (sizes 2000, 1992, 1952). |
| T4 | `_SE_AUDIT_PROCESS_CREATION_INFO` (8 bytes): `ImageFileName` (`_OBJECT_NAME_INFORMATION *`) at 0. `_OBJECT_NAME_INFORMATION` (16 bytes): `Name` (`_UNICODE_STRING`) at 0. |
| T5 | `_FILE_OBJECT` (216 bytes): `SectionObjectPointer` 0x28, `DeletePending` (unsigned char) 0x49, `DeleteAccess` 0x4c, `SharedDelete` 0x4f, `Flags` (unsigned int) 0x50, `FileName` (`_UNICODE_STRING`) 0x58 in all four. `_SECTION_OBJECT_POINTERS.ImageSectionObject` (void *) at 0x10. |
| T6 | `_CONTROL_AREA` (128 bytes): `u` 0x38 (unnamed union), `FilePointer` (`_EX_FAST_REF`) 0x40. `_MMSECTION_FLAGS` (4 bytes): `BeingDeleted` bit 0, `Image` bit 5, `File` bit 7, `DeleteOnClose` bit 18, `FilePointerNull` bit 19 in all four. |
| T7 | `_SECTION` (64 bytes): `u1` (unnamed union) at 0x28 in all four. No member of the tables names the control area of a `_SECTION`. |

### 3.3 Measurements

M1 to M11 come from `imagefacts` on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100). Counts are per capture in that order. "Active" means kept by the S17 active filter (not the system process, no exit time, at least one active thread).

| # | Measured |
|---|---|
| M1 | Processes listed: 83, 153, 71, 101, 90. Active: 77, 147, 67, 92, 80. Active with a nonzero `Peb`: 75, 145, 67, 91, 79 (the others are minimal processes such as Registry and MemCompression). `ImageBaseAddress` does not read through the process's page tables in 0, 1, 0, 3, 1 (the PEB page is paged out). |
| M2 | A range of the S24 walk holds `ImageBaseAddress` in every process whose `ImageBaseAddress` reads (74, 144, 66, 88, 78) except two: on mem1, LsaIso.exe, whose `SecureState` is nonzero; on mem5, msedge.exe (pid 5136), for which the walk kept 1 range while `VadCount` holds 211. Every such range starts at `ImageBaseAddress` and is of kind `image`. |
| M3 | `SectionBaseAddress` equals `ImageBaseAddress` in every process whose `ImageBaseAddress` reads (75, 144, 67, 88, 78), and an image view starts there in all but the two of M2. |
| M4 | `ImageFilePointer` is nonzero in every examined process. Its `SectionObjectPointer` → `ImageSectionObject` is the control area the image view reaches through `_MMVAD.Subsection` → `_SUBSECTION.ControlArea` in every one. It is the same file object as the control area's `FilePointer` in 0, 33, 31, 31, 26 processes and another file object of the same stream in 74, 111, 35, 57, 52. |
| M5 | The pointer at `_SECTION` + `u1` (T7) equals the image view's control area in every examined process (74, 144, 66, 88, 78); no other quadword in the first 0x40 bytes of the `_SECTION` does. |
| M6 | The last path component (D10) of the image view's file name, of `ImageFilePointer.FileName` and of the `SeAuditProcessCreationInfo` name agree, ignoring case, in every examined process. The full names do not: the audit name is `\Device\<volume>` followed by `ImageFilePointer.FileName` in every process, and on mem1 the view's file name is a `\VSMB-{…}\os\…` path for 73 of 74 processes. |
| M7 | `ImageFileName` equals the audit name's last component, ignoring case, in 67, 124, 61, 70, 65 processes and is its first 14 bytes in the other 7, 20, 5, 18, 13, whose components are longer than 14 bytes. 14 is the array length of T1 less one. |
| M8 | `SecureState` (or `SecurePid`) is nonzero in LsaIso.exe and lsass.exe on mem1 and LsaIso.exe on mem2, and zero elsewhere. LsaIso.exe on mem2 has an image view at `ImageBaseAddress`. |
| M9 | The page at `ImageBaseAddress` reads through the process's page tables in 74, 97, 65, 65, 36 processes and does not in 0, 47, 1, 23, 42 (not resident in the process's page tables). Every page that reads is a PE header except one on mem2 (rdpinput.exe), which is all zero; the image section's own header page is not PE either. In every other process the mapped bytes from 0 to the end of the section table equal the image section's header page (S19 4.3, file offset 0), and the header's `ImageBase` equals `ImageBaseAddress`. |
| M10 | The image view's size is at least `SizeOfImage` rounded up to the page in every process with a readable header; it is equal in 3, 96, 65, 7, 1 and exactly 0x3000 larger in 71, 0, 0, 58, 35 (26100 only). |
| M11 | No image view's file object has `DeletePending` set, on any capture, among 4,425, 8,310, 3,487, 4,856 and 4,487 image views of the active processes, and no `ImageFilePointer` has it. Every image view's control area has `File` and `Image` set and a nonzero `FilePointer`; every file object's `FileName` that reads has a nonzero length. `DeleteOnClose` is set in 24 image view control areas on mem1 only: three control areas, for three GPU driver libraries served from a `\VSMB-{…}` share, mapped in eight processes. `FilePointerNull` and `BeingDeleted` are never set. The main image file objects have `DeleteAccess` 0 and `SharedDelete` 1 in every process. |

## 4. Algorithm

### 4.1 Layout

Resolved once per run.

1. **Hollowing, required:** `_EPROCESS.Peb`, `_EPROCESS.SectionBaseAddress`, `_PEB.ImageBaseAddress` (T1, T3). Without one the run fails with `processhollowing.ErrLayout`.
2. **Hollowing, optional**, each turning off only the rules that need it: `_EPROCESS.ImageFilePointer`, `_FILE_OBJECT.SectionObjectPointer` and `_SECTION_OBJECT_POINTERS.ImageSectionObject` (H6); `_EPROCESS.SectionObject` and `_SECTION.u1` (H7); `_EPROCESS.SeAuditProcessCreationInfo`, `_SE_AUDIT_PROCESS_CREATION_INFO.ImageFileName` and `_OBJECT_NAME_INFORMATION.Name` (H8, H9); `_FILE_OBJECT.FileName` (H8); `_EPROCESS.ImageFileName` with its array length (H9); `_EPROCESS.VadCount` and `_KPROCESS.SecureState` or `.SecurePid` (4.2 step 6); `_CONTROL_AREA.u` with `_MMSECTION_FLAGS.Image` (4.3).
3. **Ghosting, required:** `_EPROCESS.SectionBaseAddress`, `_FILE_OBJECT.DeletePending`, `_FILE_OBJECT.FileName`, and the file-name chain of S24 4.6 (`memoryranges.ResolveFileNames`). Without one the run fails with `processghosting.ErrLayout`.
4. **Ghosting, optional:** `_EPROCESS.ImageFilePointer` (4.5 step 4); `_CONTROL_AREA.u` with `_MMSECTION_FLAGS.Image` and `.DeleteOnClose`.
5. Every member's offset comes from the table; bit fields inside `_CONTROL_AREA.u` are read at `u` plus their word (T6).

### 4.2 Hollowing: per process

For each process of the process list kept by `pid`:

1. A process the active filter rejects is not examined, counted as `system process`, `exited`, `no threads` or `failed the process check` (S17).
2. Read `Peb`. Zero: not examined (`no PEB`): the process has no user-mode image (M1). Unreadable: not examined, with a diagnostic.
3. Read `SectionBaseAddress` from kernel memory and `ImageBaseAddress` at `Peb` + 0x10 (T3) through the process's page tables. Unreadable: not examined, with a diagnostic (M1).
4. List the process's ranges with `Decoder.Mappings` (S24). Unreadable tree: not examined, with a diagnostic.
5. The **range at the image base** is the range whose start ≤ `ImageBaseAddress` ≤ end.
6. When there is none, the process is not examined when the walk is known to be short of the tree: kept ranges fewer than `VadCount` (`VAD tree incomplete`, M2), or a nonzero `SecureState`/`SecurePid` (`secure process without a view at ImageBaseAddress`, M2, M8). Otherwise H1 applies.
7. Apply H1 to H5 (section 5).
8. The **image view** is the range at the image base when it starts at `ImageBaseAddress` and is not known to be a non-image (4.3). Rules H6 to H13 apply only to it.

### 4.3 Image or not

A range is an image view when its kind is `image` (S24 4.5: `VadType` 2). A `private` range is not an image (D6). Every other range, of kind `mapped`, `unknown` or any other kind, takes the control-area check: when its `PrivateMemory` is known and clear, it is an image view when its control area's `_MMSECTION_FLAGS.Image` is set, and not one when it is clear (S24 M11 measures `Image` set exactly where `VadType` is 2). A range whose `PrivateMemory` is unknown or set, whose control area or flag does not read, or whose control area is not resolved (the table lacks the flag, or view file names were not read), is of unknown kind: H3 does not fire for it, and it counts as an image view for 4.2 step 8 and H5.

### 4.4 Hollowing: files and headers

For the image view:

1. `memoryranges.FileNames.Resolve` gives its control area, file object and file name (S24 4.6).
2. `ImageFilePointer` → `SectionObjectPointer` → `ImageSectionObject` is compared with the control area (H6; D4, M4).
3. `SectionObject` → `u1` is compared with the control area (H7; M5).
4. The last components of the view's file name, `ImageFilePointer.FileName` and the audit name (`SeAuditProcessCreationInfo.ImageFileName` → `Name`) are compared (H8; D8, D10, M6). Names that do not read or are empty take no part.
5. `ImageFileName` is compared with the last component of the audit name, or of the view's file name when there is no audit name (H9; M7).
6. The page at `ImageBaseAddress` (4 KB, D11) is read through the process's page tables. Unreadable: H10 to H13 are not applied, and the case is counted (M9).
7. The page is parsed as a PE header with `pe.ParseHeaders` (D9). It fails: H10.
8. Otherwise H11 and H12 apply, and when physical memory and the subsection walk are available, the page at file offset 0 of the control area's subsections (S19 4.3) is read from physical memory and compared (H13).

### 4.5 Ghosting: per process

For each process kept by `pid` and the active filter:

1. List the ranges with `Decoder.Mappings`. Unreadable tree: not examined, with a diagnostic; in strict mode the run fails.
2. Read `SectionBaseAddress`. Each image view (4.3) whose start equals it is the **main** view.
3. For each image view, `Resolve` gives its control area and file object. A view whose control area does not resolve is skipped; one of kind `image` is also counted. With a control area that gives no file object: G3. When the control area's `File` flag or `FilePointer` does not read, G3 is not applied and the view is counted as `image view file object` in the once-per-run diagnostic of section 6. With a file object: read `DeletePending` (one byte, T5) for G1 and `FileName` for G2. `DeleteOnClose` of the control area is read and reported (O5).
4. Read `ImageFilePointer` when `SectionBaseAddress` read and is nonzero. When it is nonzero and is not the main view's file object, it is checked by G1 and G2 as its own row (source `image_file_pointer`, main, `Base` = `SectionBaseAddress`).
5. A row is made for each file object with at least one finding.

## 5. Validity rules and findings

### 5.1 Hollowing

| Rule | Finding | Fires when | Meaning | Justification |
|---|---|---|---|---|
| H1 | `image_base_unmapped` | No range holds `ImageBaseAddress` (and 4.2 step 6 does not apply) | The PEB names an image base that the process does not have | M2 |
| H2 | `image_base_inside_range` | The range at the image base starts below `ImageBaseAddress` | The PEB points into the middle of an allocation | M2: every range starts there |
| H3 | `image_base_not_image` | The range at the image base is private, or a section view known not to be an image (4.3) | Code at the image base is not an image section view: the hollowing case | D5, D6, M2 |
| H4 | `section_base_differs` | `SectionBaseAddress` ≠ `ImageBaseAddress` | The PEB's image base is not where the kernel mapped the process's section | M3 |
| H5 | `section_base_unmapped` | H4, and no image view (or view of unknown kind) starts at `SectionBaseAddress`, and the kept ranges are not fewer than `VadCount` | The view the kernel created at process creation is gone | M3 |
| H6 | `control_area_differs` | `ImageFilePointer`'s `ImageSectionObject` ≠ the view's control area | The view maps another image section than the process's image file | D4, M4 |
| H7 | `section_object_differs` | `SectionObject` → `u1` ≠ the view's control area | The view maps another section than the one the process was created from | M5, O1 |
| H8 | `file_name_differs` | Two of the three last components (4.4 step 4) differ, ignoring case | The view's file, the image file and the audit name are not one file name | D10, M6 |
| H9 | `image_file_name_differs` | `ImageFileName` differs, ignoring ASCII case, from the reference component, or from its first *n* bytes when the component is longer than *n* = array length − 1 | The short name the kernel keeps does not match the image file | M7, O3 |
| H10 | `header_not_pe` | The mapped header page reads but is not a PE header, and the image section's own header page is resident and is one | The headers of the mapped image were overwritten in the process | D9, M9 |
| H11 | `header_image_base_differs` | The mapped header's `ImageBase` ≠ `ImageBaseAddress` | The headers at the image base describe an image based elsewhere | D9, M9 |
| H12 | `image_size_exceeds_range` | `SizeOfImage` rounded up to the page > the image view's size | The header claims more image than the view maps | D9, M10 |
| H13 | `header_differs_from_section` | The mapped bytes from 0 to the end of the section table differ from the image section's header page | The mapped headers are not the file's headers | D9, M9 |

H1 to H5 are applied in that order, then H6 to H13. A process gives at most one row per finding. When the mapped header page is all zero and so is the section's (M9), or the section's page is not resident or not PE, H10 is not applied and the case is counted.

### 5.2 Ghosting

| Rule | Finding | Fires when | Meaning | Justification |
|---|---|---|---|---|
| G1 | `file_delete_pending` | `_FILE_OBJECT.DeletePending` ≠ 0 | A delete operation exists for the image file; once its handles close and its link count is zero the file is gone (D2), and with POSIX semantics its name is gone at once (D3) | D1, D2, D3, M11 |
| G2 | `file_name_empty` | `FileName.Length` is 0 | The image file object names no file | D1, M11 |
| G3 | `section_without_file` | The image view's control area gives no file object (`File` clear, or `FilePointer` null with the fast-reference bits cleared) | The image section has no file behind it | T6, M11 |

A file object found delete pending may already be deleted; the file object does not say which (O4).

## 6. Failure modes

| Case | Result |
|---|---|
| Required member absent (4.1 steps 1, 3) | `processhollowing.ErrLayout` or `processghosting.ErrLayout`; the run fails |
| Profile not Windows | `<tool>: unsupported profile os "<os>"` |
| Process not examined for a state (inactive, no PEB, VAD tree incomplete, secure process) | Counted in `<tool>: <n> processes, <m> examined; not examined: <count> <reason>, …`; never an error |
| `Peb`, `SectionBaseAddress`, `ImageBaseAddress` or the VAD tree unreadable | `<tool>: pid <pid> _EPROCESS at 0x<addr>: not examined: <reason>: <error>`, counted as above; strict mode: the run fails with that error |
| A value a rule needs does not read (`ImageFilePointer`, its image section, `SectionObject`, the audit name, the header page, a file name, the file object of an image view's control area) | The rule is not applied; once per run: `windows.process.find_hollowing: comparisons not made because a value did not read: <what> <count>, …` or `windows.process.find_ghosting: values that did not read, their rules not applied: <what> <count>, …` |
| Section header pages | Once per run when the subsection walk is available: `windows.process.find_hollowing: <n> section header pages compared, <n> not resident or not read, <n> not a PE header` |
| No view file names, or no subsection walk | `windows.process.find_hollowing: view file names not read, file rules not applied: <error>` or `… section header pages not read, header_differs_from_section not applied: <error>` |
| Ghosting summary | `windows.process.find_ghosting: <n> processes, <m> examined, <v> image views, <d> with DeleteOnClose set in their control area; not examined: …` |
| VAD walk diagnostics | As S24 6, under the running tool's name |

## 7. Result schema

`processhollowing.Row`, one per finding, in process-list order, then rule order H1 to H13:

| Field | Type | Meaning |
|---|---|---|
| `PID`, `Process`, `EPROCESS` | uint64, string, uint64 | The process; `Process` is `ImageFileName` with invalid UTF-8 replaced |
| `Finding` | `Finding` (typed string) | One of the 13 values of 5.1 |
| `ImageBaseAddress` | uint64 | PEB value |
| `SectionBaseAddress` | uint64 | `_EPROCESS` value |
| `RangeStart`, `RangeEnd`, `RangeType`, `Protection`, `Path` | uint64, uint64, string, string, string | The range at the image base (S24 7); zero and empty when none |
| `Detail` | string | What differed: names, addresses or header fields as `<field> 0x<mapped>, section 0x<file>` |

`processghosting.Row`, one per file object with a finding, in process-list order, then range order, the `image_file_pointer` row last:

| Field | Type | Meaning |
|---|---|---|
| `PID`, `Process`, `EPROCESS` | uint64, string, uint64 | The process |
| `Source` | `Source` (typed string) | `image_view` or `image_file_pointer` |
| `Main` | bool | The view starts at `SectionBaseAddress`, or the row is `ImageFilePointer` |
| `Base`, `End` | uint64 | The view's range; for `image_file_pointer`, `SectionBaseAddress` and 0 |
| `ControlArea`, `FileObject` | uint64 | 0 when absent |
| `Path` | string | The view's file name (S24), or the file object's `FileName` |
| `DeletePending`, `DeleteOnClose`, `NameEmpty`, `NoFileObject` | bool | G1, the control area's `DeleteOnClose` (O5), G2, G3 |
| `Findings` | []`Finding` | G1 to G3, in that order |

## 8. Limits

No limit of their own. The VAD walk (S24 8) and the subsection walk (S19 8) apply theirs. One page is read at `ImageBaseAddress` and one header page per image view.

## 9. Acceptance

1. Synthetic fixtures (`internal/testsupport/s43_fixture.go`, the 26100 layout of T1 to T7 and S24; `tools/windows/processhollowing/*_test.go`, `tools/windows/processghosting/*_test.go`): a consistent process with no findings; each of H1 to H13 alone or with the findings it implies (a private range at the image base with the section view gone gives H3, H4 and H5); a 14-byte `ImageFileName`; case and prefix differences in file names; each not-examined state; an unreadable `ImageBaseAddress` in strict and lenient mode; an unreadable header page; a zero header page in both copies; each of G1 to G3; a delete-pending `ImageFilePointer` as its own row and checked once when it is the view's file object; `DeleteOnClose` counted, not found; `pid`; the system process; a table without a required member; a non-Windows profile.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzHeaderDifferences` (arbitrary mapped and section pages; no panic, a header never differs from itself, a difference list is never empty): 1,267,066 executions. `FuzzExamine` (arbitrary `ImageBaseAddress`, `SectionBaseAddress`, view size, header pages and `ImageFileName`; only findings of 5.1, each at most once): 646,354 executions. `FuzzFileObjectState` (arbitrary bytes over an image view's file object; G1 exactly when the `DeletePending` byte is nonzero, G2 exactly when `NameEmpty`): 1,521,216 executions.
3. On the captures, `imagefacts -tool`, 2026-11-12:

| Capture | Hollowing rows | Examined | Not examined (state) | Not examined (unread) | Header pages compared | Ghosting rows | Image views | `DeleteOnClose` views |
|---|---|---|---|---|---|---|---|---|
| mem1_win11 | 0 | 74 | 4 exited, 2 no PEB, 1 no threads, 1 secure, 1 system | 0 | 74 | 0 | 4,425 | 24 |
| mem2_win10 | 0 | 144 | 4 exited, 2 no PEB, 1 no threads, 1 system | 1 `ImageBaseAddress` | 96 | 0 | 8,310 | 0 |
| mem5_server2016 | 0 | 66 | 3 exited, 1 VAD tree incomplete, 1 system | 0 | 65 | 0 | 3,487 | 0 |
| mem6_server2025 | 0 | 88 | 8 exited, 1 no PEB, 1 system | 3 `ImageBaseAddress` | 65 | 0 | 4,856 | 0 |
| mem7_server2025 | 0 | 78 | 9 exited, 1 no PEB, 1 system | 1 `ImageBaseAddress` | 36 | 0 | 4,487 | 0 |

   - Every rule gives 0 rows on the five captures, as M2 to M11 predict for captures taken without an attack. The not-examined states are the LsaIso.exe and msedge.exe processes of M2.
   - Header pages not read through the process's page tables (H10 to H13 not applied): 0, 47, 1, 23, 42; one more on mem2 is the zero page of M9.
   - Ghosting `FileName` reads that failed: 0, 3, 0, 3, 14.
   - Run time per tool: 0.6 to 4.5 s per capture.
   - No capture holds a hollowed or ghosted process, so the positive cases rest on the fixtures (O6).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | `_SECTION.u1` is an unnamed union (T7); that it holds the control area rests on M5 alone. | A symbol-table change that keeps union members; owner decision on the measured placement |
| O2 | `_KPROCESS.SecureState` is an unnamed union (T2); using any nonzero value as "has a secure counterpart" rests on M8. | Owner decision; a source for the union's members |
| O3 | `ImageFileName`'s encoding is not documented; names outside ASCII are not compared by H9. Case folding for H8 uses Unicode simple folding, which may differ from the volume's upcase table. | A source for the encoding; owner decision |
| O4 | `DeletePending` says a delete operation exists (D1), not that the file is already gone. A ghosted image and an image whose deletion is merely pending both give G1. | A capture of a ghosted process, plus the file system's own state (out of scope) |
| O5 | `_MMSECTION_FLAGS.DeleteOnClose` has no documentation. It is reported per row and counted, but is not a finding: on mem1 it is set for GPU driver libraries served over VSMB (M11). | Owner decision: make it a finding |
| O6 | No capture holds a hollowed or ghosted process; every positive case rests on fixtures built from this specification. | A capture with known process hollowing and process ghosting (Q-dataset request to the owner) |
| O7 | The image view is 0x3000 larger than `SizeOfImage` on 26100 (M10); its cause is not documented, so H12 checks only that the view is not smaller. | A source for the extra pages |
| O8 | When the walk is short of `VadCount`, or the process has a secure counterpart, a missing view is reported as not examined instead of as H1 (4.2 step 6). An attacker who also corrupts `VadCount` would hide H1. | Owner decision |
| O9 | Row field names are owner question Q2. Hollowing: `Note` is replaced by `Finding` and `Detail`; `EPROCESS`, `ImageBaseAddress`, `SectionBaseAddress`, `RangeStart`, `RangeEnd`, `RangeType`, `Protection` and `Path` are new. Ghosting: `PID`, `Process`, `Base`, `FileObject`, `DeletePending`, `DeleteOnClose` and `Path` keep their names (the last two now from T5 and T6 as defined in 7); `EPROCESS`, `Source`, `Main`, `End`, `ControlArea`, `NameEmpty`, `NoFileObject` and `Findings` are new. | Owner decision |
| O10 | x86 kernels: the tables give the layouts, but no 32-bit capture was measured. | A 32-bit capture (Q7) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep the measured placement |
| O2 | Any nonzero value |
| O3 | Skip non-ASCII; simple folding |
| O4 | Raise G1 for both |
| O5 | Count only |
| O6 | Supply the capture |
| O7 | Check not smaller only |
| O8 | Report not examined |
| O9 | Accept the new names |
| O10 | Defer |

## 11. Provenance

Written from Microsoft Learn's WDK and Win32 documentation, the PE Format specification on Microsoft Learn, the ntoskrnl types in the project's symbol tables, and the project's measurements with `imagefacts`. Every rule rests on the sources and measurements above.
