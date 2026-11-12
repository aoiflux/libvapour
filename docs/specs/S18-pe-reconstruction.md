# S18: PE reconstruction from memory

Version 1, 2026-11-12.

## 1. Purpose

An examiner who finds a loaded driver or DLL wants it as a file that PE readers and disassemblers open. The loaded image is not the file on disk. The loader has placed each section at its RVA, padded it to its virtual size, applied base relocations, filled the import address table and left out what it does not map, such as the attribute certificates. Written out unchanged, the bytes contradict the headers: every section's file pointer names the wrong place.

This specification turns the mapped bytes of one image into a PE file whose headers describe those bytes. The file keeps the memory layout: a section's raw data starts at its RVA. It is a reconstruction for analysis. Relocations stay applied, the import address table keeps the resolved addresses, unread pages are zeros, and nothing the loader did not map is recovered.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Image | bytes | `SizeOfImage` bytes read from the image base, unread pages as zeros (the caller's gap map records them). |
| Base | address | The address the image is loaded at, sign-extended. |
| Limits | `MaxArtifactBytes`, `MaxTableEntries` | The file cap and the debug-entry cap. |

The caller (`windows.pe.dump`) reads the headers first (`extract.ReadHeaders`), refuses an image whose `SizeOfImage` exceeds `MaxArtifactBytes`, then reads the image page by page.

## 3. Facts from the sources

All from Microsoft Learn, "PE Format" (learn.microsoft.com/windows/win32/debug/pe-format), page dated 2026-09-10, accessed 2026-11-12.

| # | Fact |
|---|---|
| P1 | `SectionAlignment` (optional header offset 32): "The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment." |
| P2 | `FileAlignment` (offset 36): "The value should be a power of 2 between 512 and 64 K, inclusive … If the SectionAlignment is less than the architecture's page size, then FileAlignment must match SectionAlignment." |
| P3 | `SizeOfImage` (offset 56): "The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment." |
| P4 | `SizeOfHeaders` (offset 60): "The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment." |
| P5 | `ImageBase` (offset 28 in PE32, 4 bytes; 24 in PE32+, 8 bytes): "The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K." |
| P6 | `NumberOfRvaAndSizes` (offset 92 / 108) gives "the number of data-directory entries in the remainder of the optional header". The directories start at offset 96 / 112, 8 bytes each; entry 4 is the Certificate Table, entry 6 is Debug. |
| P7 | Certificate Table: "These certificates are not loaded into memory as part of the image. As such, the first field of this entry, which is normally an RVA, is a file pointer instead." The overview adds that the attribute certificate and debug information are placed at the end of the file "because the loader does not map these into memory". |
| P8 | Section table: `VirtualSize` is "The total size of the section when loaded into memory. If this value is greater than SizeOfRawData, the section is zero-padded." `VirtualAddress` is, for images, "the address of the first byte of the section relative to the image base when the section is loaded into memory". `SizeOfRawData` and `PointerToRawData` "must be a multiple of FileAlignment" for images, and are zero for a section of only uninitialized data. |
| P9 | "In an image file, the VAs for sections must be assigned by the linker so that they are in ascending order and adjacent, and they must be a multiple of the SectionAlignment value." |
| P10 | A debug directory entry is 28 bytes: `SizeOfData` at 16, `AddressOfRawData` ("The address of the debug data when loaded, relative to the image base") at 20, `PointerToRawData` ("The file pointer to the debug data") at 24. "The specified RVA can be zero if the debug information is not covered by a section header … and is not mapped into the run-time address space." |
| P11 | COFF file header `PointerToSymbolTable` (offset 8) and `NumberOfSymbols` (offset 12): "This value should be zero for an image because COFF debugging information is deprecated." |
| P12 | The section table follows the optional header, whose size is `SizeOfOptionalHeader` in the COFF file header. |
| P13 | `CheckSum` (optional header offset 64, 4 bytes, both formats): "The image file checksum." It is checked at load time for drivers, DLLs loaded at boot and DLLs loaded into a critical Windows process. |

### Measurements

M1 comes from `pefacts`, run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393) and mem6_server2025 (26100). It reads every listed kernel module (reader chosen per module as the tool does) and the modules of the first five processes whose first module's headers read, 1,084 images in all: 683 kernel, 401 process.

| # | Measured |
|---|---|
| M1 | Every image has `SectionAlignment` 0x1000 and `FileAlignment` 0x200, 0x400 or 0x1000. In every image the sections are adjacent and ascending and the last ends, rounded up to `SectionAlignment`, exactly at `SizeOfImage`. No section has `VirtualSize` 0. In 6,478 sections the file layout differs from the memory layout (`PointerToRawData` ≠ `VirtualAddress`). 798 images carry a Certificate Table entry. Of the debug entries that are mapped, 1,374 have `PointerToRawData` ≠ `AddressOfRawData`. 51 kernel images on mem5 have a linker `ImageBase` that is not a multiple of 64 K. No image has a COFF symbol table pointer. 1,067 of 1,084 images have at least one unread page. |

## 4. Algorithm

1. **Cap.** If the image is longer than `MaxArtifactBytes`, fail with `ErrRebuildTooLarge`.
2. **Headers.** Parse the DOS header, NT signature, COFF header, optional header and section table from the image (`pe.ParseHeaders`). The buffer length must equal `SizeOfImage`, else `ErrRebuildSize` (P3).
3. **Directories fit.** `SizeOfOptionalHeader` must hold the data directories that `NumberOfRvaAndSizes` declares, `96 + 8·n` (PE32) or `112 + 8·n` (PE32+), else `ErrRebuildHeaders` (P6, P12). Without this a short optional header would put the section table, which step 5 rewrites, over the header fields.
4. **Alignment.** `SectionAlignment` must be a nonzero power of two, else `ErrBadAlignment` (P1).
5. **Sections.** For each section header, in table order:
   - span = `VirtualSize`, or `SizeOfRawData` when `VirtualSize` is 0, rounded up to `SectionAlignment` (P8, P9);
   - if the RVA is at or past `SizeOfImage`, or the span is 0, the section holds no bytes: `PointerToRawData` and `SizeOfRawData` become 0 and the name is listed as **empty** (P8);
   - if RVA + span passes `SizeOfImage`, `SizeOfRawData` becomes `SizeOfImage` − RVA and the name is listed as **clipped**;
   - otherwise `PointerToRawData` = RVA and `SizeOfRawData` = span.
   Every section's raw data is then its memory bytes, and every RVA in the file is also its file offset. `VirtualSize` and `VirtualAddress` are kept.
6. **FileAlignment.** Kept when it is a power of two no larger than `SectionAlignment`: every raw pointer and size from step 5 is a multiple of `SectionAlignment`, hence of `FileAlignment` (P2, P8). Otherwise it becomes `SectionAlignment`, reported as **file alignment set**. The 512-byte lower bound of P2 is not enforced: a file whose raw data is already aligned breaks no reader.
7. **SizeOfHeaders.** Kept when it does not pass the lowest RVA of a section with bytes; otherwise set to that RVA, reported (P4). The headers are the bytes before the first section.
8. **ImageBase.** Set to the load address, because the loader applied the relocations for that address and every absolute address in the file refers to it. PE32+ takes 8 bytes. PE32 takes the address only if it fits 32 bits; otherwise the linker value stays and the result says so (P5). The 64 K rule of P5 is not enforced (M1: 51 linker bases already break it).
9. **COFF symbols.** If `PointerToSymbolTable` or `NumberOfSymbols` is nonzero, both become 0: the pointer is a file offset into bytes that were never mapped (P11).
10. **Certificate Table.** If the entry is present and nonzero, it becomes 0 (P7). Its file pointer would otherwise name unrelated bytes of the rebuilt file.
11. **Debug entries.** When the Debug directory lies at or after the end of the section table and starts inside the image, each whole 28-byte entry inside the image, up to `MaxTableEntries`, gets `PointerToRawData` = `AddressOfRawData` when that RVA is nonzero and the data fits the image, and 0 otherwise (P10). Entries already right are untouched. The counts of repointed and unmapped entries are returned.
12. **CheckSum.** If nonzero, it becomes 0 (P13, O2). The linker computed it over the file on disk; the rebuilt file holds other bytes, so a kept value would claim an integrity it does not have. Zero means not checked.
13. **Output.** The image bytes with the header edits of steps 5 to 12. Nothing else changes, and the file is `SizeOfImage` bytes long.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Image within the artefact cap | Limits | `ErrRebuildTooLarge` |
| Buffer length equals `SizeOfImage` | P3 | `ErrRebuildSize` |
| Optional header holds its declared directories | P6, P12 | `ErrRebuildHeaders` |
| `SectionAlignment` a nonzero power of two | P1 | `ErrBadAlignment` |
| Section inside `SizeOfImage` | P3, P8 | Empty or clipped, listed |
| `FileAlignment` a power of two ≤ `SectionAlignment` | P1, P2 | Replaced, reported |
| `SizeOfHeaders` ends at or before the first section | P4 | Replaced, reported |
| Debug directory after the section table | P10, step 3 | Entries left as they are |
| `CheckSum` zero in the file | P13, O2 | Zeroed, reported |

## 6. Failure modes

| Case | Result |
|---|---|
| Headers do not parse | The `pe.ParseHeaders` error (`ErrNotPE`, `ErrNoNTSignature`, `ErrUnsupportedOptionalMagic`, `ErrShortOptionalHeader`, `TruncatedError`) |
| Rules of section 5 that fail the rebuild | The sentinel named there |
| Unread pages | Zeros in the file; the caller's row carries the gap map (`Captured`, `Gaps`) |
| 32-bit image above 4 GB | Rebuilt with the linker `ImageBase`; diagnostic `windows.pe.dump: <source> <name> at 0x<base>: base does not fit a 32-bit ImageBase, kept 0x<value>` |
| Sections empty or clipped | Diagnostic `windows.pe.dump: <source> <name> at 0x<base>: <n> sections hold no bytes inside SizeOfImage, <m> end past it` |

The rebuild has no strict-mode behaviour of its own; the tool's existing strict handling of the module lists is unchanged.

## 7. Result schema

`pe.Rebuilt`: `File` (bytes), `Sections` (names placed), `Empty`, `Clipped` (names), `ImageBaseSet`, `OriginalImageBase`, `FileAlignmentSet`, `SizeOfHeadersSet`, `SizeOfImageAligned` (P3 holds), `CertificateCleared`, `DebugRepointed`, `DebugUnmapped` (counts), `SymbolTableCleared`, `CheckSumCleared`.

The `windows.pe.dump` row is unchanged in shape: `Size` is the file length (`SizeOfImage`), `Sections` the number of sections placed, `OriginalImageBase` and `ImageBaseFixed` from the rebuild.

## 8. Limits

- `MaxArtifactBytes`: the image and the file.
- `MaxTableEntries`: debug entries rewritten.

## 9. Acceptance

1. Synthetic fixtures (`pe/rebuild_test.go`): PE32 and PE32+ images rebuild, parse with `debug/pe`, every section's data equals memory at its RVA, and `ImageBase` is the load address; no byte outside the rewritten fields changes; a 32-bit image above 4 GB keeps its base; empty and clipped sections; `VirtualSize` 0; unusable `FileAlignment` values; `SizeOfHeaders` past the first section; Certificate Table and COFF symbols cleared; `CheckSum` zeroed in PE32 and PE32+, and a zero `CheckSum` not reported as cleared; debug entries repointed, zeroed and left alone; every failure sentinel.
2. Fuzz target `FuzzRebuild`: arbitrary bytes and base. It must not panic. A successful rebuild keeps the length, its headers parse again, every section with raw data has it at its RVA inside the file and a multiple of `SectionAlignment` long unless it ends the file, `FileAlignment` is a power of two no larger than `SectionAlignment`, the Certificate entry and `CheckSum` are 0, and no byte outside the rewritten fields changed. Run for 30 s on 2026-11-12: 1.68 million executions, no failure after the fix of section 4 step 3, which it found. Rerun for 30 s after O2 with the `CheckSum` check: 3,225,544 executions, no failure.
3. On the captures (`pefacts`, 2026-11-12): all 1,084 images rebuild and parse with `debug/pe`; in all 10,866 sections with raw data the file bytes equal memory at the RVA, apart from the rewritten debug pointers; every rebuilt `ImageBase` is the load address. For every kernel image the CodeView entry's `PointerToRawData` now leads to its `RSDS` record (682 of 683; the other has no mapped debug data). For process images 181 lead to `RSDS` and 99 point into a page that did not read. Rerun after O2 (`pefacts -processes 5`, 2026-11-12): all 1,084 images still rebuild with the same counts, and every one carried a nonzero `CheckSum`, now zeroed (195, 192, 142 and 154 kernel images, 174, 118, 79 and 30 process images).

| Capture | Kernel images | Process images | Headers unread | Certificates cleared | Debug entries repointed (images) |
|---|---|---|---|---|---|
| mem1_win11 | 195 | 174 | 0 | 277 | 15 |
| mem2_win10 | 192 | 118 | 3 | 232 | 274 |
| mem5_server2016 | 142 | 79 | 0 | 152 | 210 |
| mem6_server2025 | 154 | 30 | 160 | 137 | 6 |

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The file keeps the memory layout rather than the original raw layout (6,478 sections differ, M1). The original layout cannot be restored byte for byte: relocations and the import address table are applied, and bytes past `VirtualSize` were never mapped. Owner decision: keep the memory layout (default), or offer the raw layout as an option. | Owner decision |
| O2 | `CheckSum` is left as the linker wrote it, so it does not match the rebuilt file. Zeroing it is the other choice. Owner decision 2026-11-12: Zero it. Done: section 4 step 12, P13, `Rebuilt.CheckSumCleared`, the fixture and fuzz checks (`pe/rebuild.go`, `pe/rebuild_test.go`, `pe/rebuild_fuzz_test.go`). | Owner decision |
| O3 | `ImageBase` becomes the load address even when that breaks the 64 K rule of P5 (drivers load at page granularity). | Owner decision |
| O4 | No 32-bit image was measured. | A 32-bit capture (Q7) |
| O5 | Follow-up Mem-M9: `windows.pe.dump` run on mem1 (pid 11172) and mem2 (pid 3804), loaded modules and base dumps. Not a bug. Every written image follows the header rules of section 4: `VirtualSize` fields kept (step 5), `ImageBase` set to the load address (step 8), the Certificate Table entry (step 10), debug entry file pointers (step 11) and `CheckSum` (step 12). | Owner decision 2026-11-12 (follow-up Mem-M9): run the dump tests once per image. Done: no code change. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Memory layout |
| O2 | Zero it |
| O3 | Use the load address |
| O4 | Ship as written, mark untested |
| O5 | Follow-up Mem-M9: not a bug |

## 11. Provenance

Written from Microsoft Learn's PE Format specification and the project's measurements. Every rule rests on the sources and measurements above.
