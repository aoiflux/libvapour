# S32: PDB streams and names, symbol fingerprint and download path, processor start page

Version 1, 2026-11-12.

## 1. Purpose

Every Windows tool reads kernel and module structures through a symbol table built from the build's PDB. The examiner needs three things from this layer: the right PDB for the image (its fingerprint and where the symbol server keeps it), a table that states each type's layout and each symbol's image-relative address as the PDB records them, and the running kernel's identity before any table exists.

This specification covers:

- the MSF container and the PDB information, type (TPI), debug information (DBI), module and symbol record streams, as far as the table needs them;
- how type records become the table's records, enumerations and type expressions, and how symbol records become its addresses, including x86 C name decoration;
- the fingerprint notation, the symbol-server path and the cache path;
- finding the running kernel from the processor start page below 1 MiB.

The table format itself is the project's own (`symbols/FORMAT.md`) and is not changed here.

## 2. Inputs

| Input | Use |
|---|---|
| PDB bytes | Fetched from `LoadOptions.ServerURL` (default `http://msdl.microsoft.com/download/symbols`), at most `MaxDownload` bytes. |
| `Fingerprint` | PDB file name, 32-digit GUID and age, from the image's CodeView record or from kernel identification. |
| `LoadOptions` | `OfflineOnly`, `CacheDir`, `ServerURL`, `HTTPTimeout`, `MaxDownload`, `Read` (table read options), `Limits`. Unchanged. |
| `Limits.MaxRecursionDepth` | Depth bound for type references (section 8). |
| `Limits.MaxKernelImageBytes` | How far below the long-mode target the kernel's headers are searched for. |
| Physical memory | For the processor start page. |

## 3. Facts from the sources

### Documentation

LLVM, "The PDB File Format" pages (llvm.org/docs/PDB/), accessed 2026-11-12: MsfFile, PdbStream, TpiStream, DbiStream, ModiStream, CodeViewTypes, CodeViewSymbols. Microsoft, microsoft-pdb repository, `include/cvinfo.h` (github.com/microsoft/microsoft-pdb, master), accessed 2026-11-12. Microsoft Learn pages as named. Intel 64 and IA-32 Architectures Software Developer's Manual (SDM), sections as named.

| # | Fact | Source |
|---|---|---|
| F1 | An MSF file starts with a 32-byte magic, `"Microsoft C/C++ MSF 7.00\r\n"` and `1A 44 53 00 00 00`, then `BlockSize`, `FreeBlockMapBlock`, `NumBlocks`, `NumDirectoryBytes`, `Unknown`, `BlockMapAddr`, each 32 bits. Valid block sizes are 512, 1024, 2048 and 4096. `NumBlocks × BlockSize` should equal the file size. | MsfFile |
| F2 | The block at `BlockMapAddr` holds `ceil(NumDirectoryBytes / BlockSize)` 32-bit block numbers, the blocks of the stream directory. The directory is `NumStreams`, then `NumStreams` sizes, then each stream's block numbers, `ceil(size / BlockSize)` of them. Streams are not contiguous. | MsfFile |
| F3 | Stream 1 is the PDB information stream: `Version`, `Signature`, `Age` (32 bits each) and the 16-byte GUID at offset 12. | PdbStream |
| F4 | Stream 2 (TPI) starts with a header of `HeaderSize` bytes (56 for the documented layout): `Version`, `HeaderSize`, `TypeIndexBegin`, `TypeIndexEnd`, `TypeRecordBytes`, then hash fields. `TypeRecordBytes` of records follow; there are `TypeIndexEnd − TypeIndexBegin` of them, the first with index `TypeIndexBegin` (0x1000 in practice). Records form a DAG in which a record refers only to earlier ones. | TpiStream |
| F5 | A type index below `TypeIndexBegin` is a simple type: bits 0–7 the kind, bits 8–11 the mode (0 direct; 1 near, 2 far, 3 huge, 4 near32, 5 far32, 6 near64, 7 near128 pointer). | TpiStream (Type Indices) |
| F6 | Every type record starts with `RecordLen` (16 bits, not counting itself) and `RecordKind`. Within an `LF_FIELDLIST` the member records have no length of their own, and padding bytes 0xF0–0xFF (`LF_PAD0`–`LF_PAD15`) align them; the low nibble of an `LF_PADn` byte is the count of bytes to skip. | CodeViewTypes; cvinfo.h `LF_PAD0` |
| F7 | Record layouts after the kind: `lfModifier` type (32), attr (16); `lfPointer` utype (32), attr (32) with `ptrtype` bits 0–4 (`CV_PTR_NEAR32` 0x0a, `CV_PTR_64` 0x0c), `size` bits 13–18; `lfArray` elemtype, idxtype (32 each), a numeric leaf of the size in bytes, name; `lfBitfield` type (32), length (8), position (8); `lfClass` (LF_CLASS, LF_STRUCTURE, LF_INTERFACE) count (16), property (16), field, derived, vshape (32 each), numeric size, name; `lfUnion` count, property, field, numeric size, name; `lfEnum` count, property, utype, field, name. | cvinfo.h |
| F8 | `CV_prop_t`: `fwdref` (bit 7) marks a forward reference, an incomplete definition; `hasuniquename` (bit 9) means a decorated name follows the name. | cvinfo.h |
| F9 | Field-list members: `lfMember` attr (16), type (32), numeric offset, name; `lfEnumerate` attr (16), numeric value, name; `lfIndex` pad (16), index (32), the continuation list; `lfBClass` attr, type, numeric offset; `lfVBClass`/`lfIVBClass` attr, btype, vbptr type, two numerics; `lfVFuncTab` pad, type; `lfSTMember`, `lfMethod`, `lfNestType` 2 + 4 bytes then a name; `lfOneMethod` attr, type, a 32-bit vbase offset when the method property is introducing virtual (4 or 6), name. | cvinfo.h |
| F10 | Numeric leaves: a 16-bit value below `LF_NUMERIC` (0x8000) is the value; otherwise the leaf names the form that follows: `LF_CHAR` (8-bit signed), `LF_SHORT`, `LF_USHORT`, `LF_LONG`, `LF_ULONG`, `LF_QUADWORD`, `LF_UQUADWORD`, and non-integer forms (reals, strings). | cvinfo.h |
| F11 | Simple type kinds: 0x03 void, 0x08 HRESULT, 0x10/0x20 8-bit signed/unsigned, 0x68/0x69 8-bit int, 0x70 "really a char", 0x71 wide char, 0x7a char16_t, 0x7b char32_t, 0x7c char8_t, 0x11/0x21 and 0x72/0x73 16-bit, 0x12/0x22 and 0x74/0x75 32-bit, 0x13/0x23 and 0x76/0x77 64-bit, 0x14/0x24 and 0x78/0x79 128-bit, 0x30–0x34 booleans of 8 to 128 bits, 0x40 float32, 0x41 float64, 0x42 float80, 0x43 float128, 0x44 float48, 0x45 float32 partial precision, 0x46 float16, 0x50–0x56 complex, 0x00 no type. | TpiStream; cvinfo.h |
| F12 | Stream 3 (DBI) has a 64-byte header: `VersionSignature` (−1 observed), `VersionHeader`, `Age` at 8, `GlobalStreamIndex`, `BuildNumber`, `PublicStreamIndex`, `PdbDllVersion`, `SymRecordStream` at 20, `PdbDllRbld`, then `ModInfoSize`, `SectionContributionSize`, `SectionMapSize`, `SourceInfoSize`, `TypeServerMapSize` (24–43), `MFCTypeServerIndex`, `OptionalDbgHeaderSize` at 48, `ECSubstreamSize` at 52, `Flags`, `Machine` at 58. The substreams follow in the order module info, section contributions, section map, file info, type server map, EC, optional debug header. `Age` equals the PDB stream's. | DbiStream |
| F13 | A module info entry is 64 fixed bytes (`ModuleSymStream` at 34, `SymByteSize` at 36) and two NUL-terminated names; entries are 4-byte aligned. A module stream starts with a 32-bit signature, and `SymByteSize` (which includes it) bytes of symbol records. | DbiStream; ModiStream |
| F14 | The optional debug header is an array of 16-bit stream numbers, −1 for absent: [4] OMAP from source, [5] section headers, [10] original section headers. Each stream's layout is that of the PE debug data of that type. | DbiStream |
| F15 | A section header is 40 bytes; `VirtualAddress` is at offset 12. | Microsoft Learn, "PE Format", Section Table |
| F16 | An OMAP entry is `rva`, `rvaTo` (32 bits each); an array sorted by `rva` maps an address: take the entry with the largest `rva` not above it and add the difference to `rvaTo`. | Microsoft Learn, "OMAP structure (dbghelp.h)" |
| F17 | Symbol records: `PUBSYM32` flags (32), off (32), seg (16), name; `DATASYM32` type (32), off, seg, name; `REFSYM2` (S_PROCREF, S_LPROCREF) sumName (32), ibSym (32, offset in the module's symbol stream), imod (16, from 1), name; `PROCSYM32` parent, end, next, len, dbgStart, dbgEnd, type (32 each), off (32), seg (16), flags (8), name. Kinds: S_PUB32 0x110E, S_LDATA32 0x110C, S_GDATA32 0x110D, S_LPROC32 0x110F, S_GPROC32 0x1110, S_PROCREF 0x1125, S_LPROCREF 0x1127. | cvinfo.h; CodeViewSymbols |
| F18 | C decoration: `__cdecl` a leading `_`; `__stdcall` a leading `_` and `@` with the parameter bytes in decimal; `__fastcall` a leading and a trailing `@` with the bytes; `__vectorcall` `@@` and the bytes. In 64-bit code only `__vectorcall` decorates C names. C++ decorated names start with `?`. | Microsoft Learn, "Decorated names" |
| F19 | A symbol store holds one folder per file name, one folder per version under it, the file inside: `<name>/<version>/<name>`. PDBs are looked up by GUID and age. | Microsoft Learn, "Symbol Store Folder Tree", "Symbol Storage Format" |
| F20 | The GUID in a CodeView `RSDS` record is a 32-bit, two 16-bit (little-endian) and eight single-byte fields. | Microsoft Learn, "PE Format", Debug Type |
| F21 | An application processor leaves wait-for-SIPI at real-mode address `000VV000H`, `VV` the 8-bit vector of the STARTUP IPI, so its first code is page-aligned below 1 MiB. | SDM Vol. 3A, "MP Initialization Protocol Algorithm" and the ICR Start-Up delivery mode |
| F22 | `E9 cw` is `JMP rel16` in 16-bit code, the displacement relative to the next instruction (3 bytes on). | SDM Vol. 2A, JMP |
| F23 | With 4-level paging CR3 bits 51:12 are the PML4 table's physical address; bits 11:0 are flags (PWT, PCD) or, with CR4.PCIDE, the PCID. | SDM Vol. 3A, "Use of CR3 with 4-Level Paging" |
| F24 | Kernel addresses of a 48-bit canonical x64 space are at or above 0xFFFF800000000000. | SDM Vol. 1, canonical addressing |

### Kernel types

From the ntoskrnl PDBs of builds 26100 (0D960CE103763A6097E839406D8B369F, 953A8DE880B0818C32DA2DEC1D79C2D9), 19045 (F57E740B088E5056E8AF0772F1CC5BEB) and 14393 (3DFC5F7228304C26859E55E481700385), read through the converted tables.

| # | Fact |
|---|---|
| K1 | `_KPROCESSOR_STATE.SpecialRegisters` at 0 and `_KSPECIAL_REGISTERS.Cr3` at 0x10 on all four. |
| K2 | `_KPROCESSOR_STATE.ContextFrame` at 0xF0 (26100, 19045) and 0xE0 (14393); `_CONTEXT.Rip` at 0xF8 on all four. |
| K3 | No PDB of the captures (ntkrnlmp, hal) defines `_PROCESSOR_START_BLOCK` or another type for the start page. |

### Measurements

`pdbfacts`, 2026-11-12. The PDB store holds the 29 PDBs that the five Windows captures need (mem1_win11, mem2_win10, mem5_server2016, mem6_server2025, mem7_server2025): the kernel, hal, tcpip and win32kbase of each, and ntdll, wntdll, advapi32, kerberos, conhost and WorkFoldersShell where present (`fingerprints`, then the Microsoft server).

| # | Measured |
|---|---|
| M1 | Block sizes 4096 (21 files) and 1024 (8); `NumBlocks × BlockSize` equals the file size in all 29; no stream size is 0xFFFFFFFF; the streams' blocks sum to fewer than `NumBlocks` in all 29; directories need 1 to 37 map entries, all in one block. |
| M2 | PDB stream version 20000404 and TPI version 20040203, `HeaderSize` 56, `TypeIndexBegin` 0x1000, in all 29. Where the TPI holds records (ntkrnlmp ×4, ntdll ×3, wntdll, hal 14393) the records fill `TypeRecordBytes` exactly and number `TypeIndexEnd − TypeIndexBegin`. |
| M3 | TPI record kinds seen: LF_MODIFIER, LF_POINTER, LF_PROCEDURE, LF_ARGLIST, LF_FIELDLIST, LF_BITFIELD, LF_ARRAY, LF_STRUCTURE, LF_UNION, LF_ENUM. Field-list members: LF_MEMBER and LF_ENUMERATE only. Numeric forms: immediate, LF_CHAR, LF_USHORT, LF_LONG, LF_ULONG. Simple types referenced: 0x00, 0x03, 0x08, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x40, 0x41, 0x70, 0x71, 0x74, 0x75, and pointer modes 4 (wntdll) and 6. |
| M4 | Names defined by more than one non-forward record: `<unnamed-tag>` or `<anonymous-tag>` in every PDB with types (hundreds of unrelated layouts), and in ntkrnlmp 19045 and 26100 `_DRIVER_EXTENSION`, `_FAST_IO_DISPATCH`, `_IRP`, `_KAPC`, `_KPCR`, `_KPRCB`, `_MDL`: a short definition beside a fuller one (`_KPRCB` 1,792 bytes with 57 members beside 52,992 with 407 on 0D960CE1). |
| M5 | DBI `VersionSignature` −1 and version 19990903 in all 29; the header and seven substreams fill the stream exactly in all 29. Machine 0x8664 in 28, 0x14C in wntdll. DBI age 1 in all 29; the PDB stream age is 2 to 6 in all 29. No PDB has an OMAP stream; slot 5 is present in all. |
| M6 | Symbol record kinds: S_PUB32 in all 29, S_LPROCREF in 26 (not in the two stub hal PDBs and ntkrnlmp 14393, which has publics only), S_PROCREF in 18, S_ANNOTATIONREF in 8. No S_GDATA32 or S_LDATA32. Module streams start with signature 4. |
| M7 | wntdll (x86) publics include `_Name@N` stdcall names, `___Name@N`, `__real@<hex>`, `__xmm@<hex>` constants (two of whose hex digits are all decimal: `__real@0000000000000000`, `__xmm@00010001000100010001000100010001`, `__xmm@80000000000000008000000000000000`), `___@@_PchSym_@…` linker names and two assembler names without an underscore, `ExecuteHandler@20` and `ExecuteHandler2@20`. |
| M8 | The Microsoft server answers `mfc100.amd64.pdb/E6AB77CE50004AA289714029B570488517/…` (age 23 as hex 17) and not `…23`; likewise c2.pdb age 20 under `14` and mfc110.amd64.pdb age 23 under `17`. It answers upper- and lower-case GUIDs and file names alike. |
| M9 | Processor start page: in each capture exactly one page below 1 MiB starts with 0xE9: 0x12000 (mem1, mem2), 0x10000 (mem5), 0x11000 (mem6, mem7). Its first bytes are `E9 4D 06` (jump to 0x650; `E9 3D 06`, to 0x640, on 14393), then 0, then the 32-bit value 1. The quadword at 0xA0 equals the kernel's page-table root found from the process list (0x7d5000, 0x7d4000, 0x7d2000, 0x7d5000, 0x7d5000), and no other quadword of the page does. The quadword at 0x70 is a kernel address inside ntoskrnl (26100, 19045) or inside hal.dll, loaded right after ntoskrnl (14393, ntoskrnl+0x820000+0x173D0). The quadword at 0x278 (0x268 on 14393) is inside ntoskrnl: 0x90 + K2's ContextFrame + Rip. |

## 4. Algorithm

### 4.1 Container

1. Check the magic and the superblock (F1). Refuse a block size not in F1, a `NumBlocks` larger than the file's whole blocks, and a block-map block past `NumBlocks`.
2. The directory's block list must fit in the one block at `BlockMapAddr` (F2, M1). Read the directory from the blocks it names, each below `NumBlocks`.
3. Read `NumStreams`, the sizes and the block lists (F2). A size of 0xFFFFFFFF is an absent stream with no blocks. Refuse a list that runs past the directory, a block number not below `NumBlocks`, and streams whose blocks together exceed `NumBlocks`: in a well-formed file a block belongs to one stream (F1, M1), so no stream data can outgrow the file.
4. A stream reads as its blocks' bytes in list order, cut to its size. An absent or unlisted stream reads as none.

### 4.2 Build identity and debug information

1. GUID: bytes 12–27 of stream 1, formatted as in 4.6 (F3, F20). The age is the DBI header's (F12, M5: the PDB stream age differs from it in all 29, and the DBI age is the one the images' CodeView records carry). A PDB whose GUID or DBI age is not the one asked for is refused (the existing check in `declare.go`).
2. DBI: at least 64 bytes, `VersionSignature` −1 (F12, M5). Take the seven substream sizes as signed; each must be non-negative and the substreams must fit the stream in the order of F12.
3. Module entries (F13): read whole entries in order; stop at one whose fixed part or names do not fit.
4. Optional debug header (F14). If slots 10 and 4 are both present, symbols are placed with the original section headers and the OMAP; otherwise with slot 5's headers. The section list is the `VirtualAddress` of each whole 40-byte header (F15).
5. Machine (F12): 0x14C gives 4-byte pointers, 0x8664 and 0xAA64 (PE/COFF machine values) 8-byte ones; any other is refused.

### 4.3 Types

1. Walk the TPI records (F4, F6). Each needs at least its kind; the walk must consume `TypeRecordBytes` exactly and give `TypeIndexEnd − TypeIndexBegin` records, and that count may not exceed `TypeRecordBytes / 4` before anything is allocated (M2).
2. Index the definitions: for each LF_CLASS, LF_STRUCTURE, LF_INTERFACE, LF_UNION or LF_ENUM without `fwdref`, keyed by its unique name when it has one, else by its name (F8). The first definition of a key is its definition.
3. Render a type index as a type expression:
   - simple type (F5, F11): the kind's name from section 7, or no name; a mode 1–7 makes it a pointer to that;
   - LF_MODIFIER: the type it modifies (F7);
   - LF_POINTER: `*` and the referent;
   - LF_ARRAY: `[n]` and the element, `n` = size ÷ element size, 0 when the element size is 0;
   - LF_BITFIELD with a length: `@position:length` and the underlying type;
   - LF_STRUCTURE, LF_CLASS, LF_INTERFACE, LF_UNION: its name;
   - LF_ENUM: the underlying type of its definition (forward references resolved by step 2); no name when the definition is absent;
   - anything else, LF_PROCEDURE and LF_MFUNCTION among them: no name. A pointer to a function is therefore `*` (FORMAT.md).
   An operator chain stops with no name at `symbols.MaxTypeOperators` levels.
4. Sizes for array counts: a simple type's width (section 7, plus float80 10, float48 6, float16 2, 128-bit 16, wide booleans 2/4/8/16, complex 4–32; pointers by mode: 2, 4, 4, 4, 6, 8, 16); LF_POINTER its `size` field, else 4 for `CV_PTR_NEAR32` and 8 for `CV_PTR_64` (F7); LF_ARRAY its size; modifiers and bitfields their underlying type; structures and unions their definition's size; enums their definition's underlying type.
5. Records: every non-forward structure, class, interface or union whose name is not `<unnamed-tag>` or `<anonymous-tag>` (M4) and that keeps at least one member. Members are the LF_MEMBER entries of its field list (F9), following LF_INDEX continuations, stopping at a member kind of unknown layout or a continuation already seen; the first member of a name is kept. When one name has several definitions, the one with more members is kept, then the larger, then the earlier (M4: the full `_KPRCB`).
6. Enumerations: every non-forward LF_ENUM whose enumerator list reads whole (an incomplete list would give it constants it does not have). Width and base are those of its underlying type; values are the numeric leaves as signed 64-bit (F10). Several definitions of a name are chosen as in step 5, by constant count.
7. Every rendering and size step counts its depth; past `MaxRecursionDepth` the step stops and the conversion fails as a cycle (F4: a well-formed stream refers only backwards).

### 4.4 Addresses

1. Walk the symbol record stream named by `SymRecordStream` (F12) from its start; stop at a record that does not fit.
2. S_PUB32: the public's segment and offset (F17). On x86 (machine 0x14C) its name loses its C decoration (4.5).
3. S_LDATA32 and S_LPROCREF: static data and static procedures have no public, so these records place them. For S_LPROCREF the module (from 1) and offset must lead, past the module stream's 4-byte signature and inside `SymByteSize`, to an S_LPROC32 or S_GPROC32 of the same name, whose segment and offset are taken (F13, F17).
4. S_GDATA32 and S_PROCREF are not taken: a global's address is its public's (M6: 18 PDBs list global procedures by undecorated name beside their decorated public).
5. Place: a segment from 1 to the number of section headers; RVA = section `VirtualAddress` + offset, at most 0xFFFFFFFF; through the OMAP when 4.2 step 4 chose it (F16). An address before the first OMAP entry, or in an entry mapped to 0, has no place in the final image and the symbol is left out.
6. Names: a public takes a name before any non-public; among publics, and among non-publics, the first record of a name in the stream keeps it.

### 4.5 x86 C names

From F18, for an S_PUB32 name on x86:

1. A name starting with `?` is C++ and kept.
2. A name with no `@` loses one leading `_` (`__cdecl`).
3. `base@@N` with `base` free of `@` becomes `base` (`__vectorcall`).
4. `@base@N` and `_base@N`, `base` non-empty and free of `@`, become `base` (`__fastcall`, `__stdcall`).
5. Any other name with an `@` is not a C name and is kept (M7: `__real@3fe0…`, `___@@_PchSym_@…`, `ExecuteHandler@20`).

`N` is a decimal byte count: digits only, no leading zero unless it is `0`, below 2^32 (a parameter list on a 32-bit machine is smaller than its address space). Constants named after hexadecimal values are therefore kept (M7).

### 4.6 Fingerprint, symbol-server path and cache path

1. GUID text: the 32-bit field as 8 upper-case hex digits, the two 16-bit fields as 4 each, then the 8 bytes as 2 each (F20).
2. Fingerprint notation: `<pdb>/<GUID>-<age>`, age in decimal. It is the project's notation, shared with `symbols.PDBBuild`. `tools/gui` keys its layouts by the GUID and age.
3. Symbol-server path (F19, M8): `<server>/<pdb>/<GUID><age>/<pdb>`, GUID in upper case and age in upper-case hexadecimal.
4. Cache path: `<cache>/<BuilderVersion>/<pdb without .pdb>-<GUID upper case>-<age decimal>.vsym`. `BuilderVersion` is 10 (section 9).
5. A fingerprint whose PDB name is not a bare file name of letters, digits and `._-+~`, or whose GUID is not 32 hex digits, is refused before it reaches a path or URL.
6. Kernel PDB names: `ntoskrnl.pdb`, `ntkrnlmp.pdb`, `ntkrnlpa.pdb`, `ntkrpamp.pdb`, without regard to case, after the four kernel images (uniprocessor, multiprocessor, and their x86 PAE forms).

### 4.7 Processor start page

1. For each readable page-aligned physical address below 1 MiB (F21), the page is a start page if it begins with `E9` (F22) and the jump target, 3 + the signed 16-bit displacement, lies inside the page and at or after 0xA8, the end of the fields read in step 2 (the code it starts is in the page, after the data it uses).
2. From a start page take the long-mode target, the quadword at 0x70, and CR3, the quadword at 0x90 + 0x10 (M9, K1: the saved processor state at 0x90, its CR3 0x10 into `_KPROCESSOR_STATE`; K2 and M9's Rip at 0x90 + ContextFrame + 0xF8 corroborate 0x90 on all four builds). CR3's frame is bits 51:12 (F23).
3. The CR3 frame must be nonzero and inside the image, and the target a kernel address (F24) that translates through it.
4. From the target's page downwards, at most `MaxKernelImageBytes`, the first page whose image's CodeView record names a kernel PDB (4.6 step 6) is the kernel's base. Other images (hal on 14393, M9) and unmapped pages are passed over.
5. All start pages are tried. Pages that name different kernels are refused (`errStartsDisagree`); pages that agree give the kernel, its base and the CR3 frame as its DTB.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Magic and block size | F1 | `errNotMSF`, or `autoload: pdb block size <n> is not 512, 1024, 2048 or 4096` |
| Blocks inside the file and below `NumBlocks` | F1, F2 | refused |
| Directory map in one block | F2, M1 | refused |
| Stream blocks no more than `NumBlocks` | F1, M1 | refused |
| TPI header fits; records fill `TypeRecordBytes` and number the index range | F4, M2 | refused |
| DBI header 64 bytes, signature −1, substreams non-negative and inside | F12, M5 | refused |
| GUID and DBI age are the ones asked for | F3, F12 | refused (`declare.go`) |
| Machine known | F12 | refused (`declare.go`) |
| At least one section header and one placed symbol | 4.4 | refused (`declare.go`) |
| Module entry fits | F13 | later entries not read |
| Procedure reference leads to a procedure of its name | F17 | symbol left out |
| Segment names a section; RVA 32-bit; OMAP maps it | F15, F16 | symbol left out |
| Enumerator list whole | F9 | enumeration left out |
| Placeholder record names | M4 | record left out |
| Type depth within `MaxRecursionDepth` | F4 | conversion fails |
| Start page jump inside the page, at or after 0xA8 | F21, F22 | not a start page |
| CR3 frame inside the image, target a kernel address that translates | F23, F24 | start page reported as leading nowhere |

## 6. Failure modes

| Case | Result |
|---|---|
| Malformed container or stream | The leaf error of section 5, wrapped `autoload: symbols for <fp>: convert the PDB: <error>; supply a symbol table for this build instead`; nothing is cached. |
| Download fails or exceeds `MaxDownload` | `autoload: symbols for <fp>: download <url>: …`; a cached table rejected first is named after it. |
| Offline, no table | `autoload: symbols not available offline: <fp>: no cached table at <path>; place a table for this build there, or allow network access once to build it` (`ErrSymbolsUnavailableOffline`). |
| Offline, unusable table | Same sentinel, `cached table <path> cannot be used: <why>; replace it with a table for this build, or allow network access once to rebuild it`. |
| Bad option | `autoload: <Option> <value> is negative` / `is past its ceiling <c>`; `autoload: ServerURL "<u>": want an http or https URL with a host and no user, query or fragment`. |
| No start page | `lowStubKernel` reports none; identification goes on to the scan. The crash dump header is tried before the start page (unchanged). |
| Start page leads nowhere | `autoload: processor start page at 0x<page>: CR3 0x<v> is outside the image` / `long-mode target 0x<v> is not a kernel address` / `long-mode target 0x<v>: <translation error>` / `no kernel image within MaxKernelImageBytes (<n>) below 0x<v>`. The scan takes over; the first such error is reported, as `the processor start page did not lead to a kernel: <error>`, only when the scan names no kernel either. |
| Start pages disagree | `autoload: processor start pages name different kernels: <fp> at 0x<base> and <fp> at 0x<base>`. The scan takes over, and the error is reported as in the row above. |

There is no strict mode at this layer.

## 7. Result schema

Table content (`symbols.Declaration`, encoded by `symbols.Encode`; ordering is `declare.go`'s):

- Scalars, a fixed set: `void` (0), `bool` (1), `char` (1, signed), `unsigned char` (1), `wchar_t` (2), `short`, `unsigned short` (2), `int`, `unsigned int`, `long`, `unsigned long` (4), `long long`, `unsigned long long` (8), `float` (4), `double` (8), and `pointer` of the machine's width.
- Simple type names: integers by width and sign, so one name has one width in every table: 8-bit signed and real char `char`, 8-bit unsigned and char8_t `unsigned char`, 16-bit `short`/`unsigned short` (char16_t unsigned), 32-bit and HRESULT `int`/`unsigned int` (char32_t unsigned), 64-bit `long long`/`unsigned long long`, wide char `wchar_t`, 8-bit boolean `bool`, float32 and partial precision `float`, float64 `double`, void `void`. Other kinds have no name. `long` and `unsigned long` are declared (Windows' 4-byte `long`, Microsoft Learn "Data Type Ranges") but no PDB type is written with them.
- Records: name, width, members (name, byte offset, type expression).
- Enumerations: name, width, constants.
- Addresses: name, image-relative address.
- `windows_pdb`: GUID and DBI age.

`RunningKernel{Fingerprint, Base, DTB}` from the start page, unchanged.

## 8. Limits

| Limit | Use | Why |
|---|---|---|
| `MaxDownload` (default 512 MiB, ceiling 4 GiB) | PDB response | The largest measured PDB is 11.4 MB; MSF sizes are 32-bit. |
| `HTTPTimeout` (default 10 min, ceiling 24 h) | PDB download | Unchanged. |
| `MaxRecursionDepth` (default 1,024) | type rendering and sizes | A backward-referring stream never nests that deep (F4). |
| `symbols.MaxTypeOperators` (32) | operator chain | The table format's own bound. |
| `MaxKernelImageBytes` (default 64 MiB) | search below the long-mode target | M9: the kernel is 8.7 MB below the target on 14393. |
| Pages below 1 MiB | start page scan | F21. |

## 9. Acceptance

1. Unit tests (`pdb_msf_test.go`, `pdb_types_test.go`, `pdb_symbols_test.go`, `autoload_test.go`, `low_stub_test.go`, fixtures in `s32_fixture_test.go`): every block size; multi-block directories; each superblock and directory refusal; absent streams; simple type names and widths; derived expressions including `*` for a function pointer and the enum's underlying type; array counts of defined, forward and unique-named elements; the fuller-definition rule with a partial `_KPRCB`; placeholder names; LF_INDEX continuation and its cycle; whole and partial enumerator lists; each TPI refusal; a modifier cycle failing at `MaxRecursionDepth`; operator chains within the format; publics before statics, first of a name kept, globals not taken, procedure references checked, segments and OMAP (including entries mapped to 0 and addresses before the map); DBI refusals; module entries; the x86 name table of 4.5; the symbol-server path with a hex age; offline and cache behaviour; option bounds; fingerprint refusals; start page found, hal skipped, CR3 flag bits masked, no start page, each lead-nowhere case, disagreeing pages, the span bound.
2. Fuzz targets, 30 s each on 2026-11-12, no failure: `FuzzReadMSF` (streams match the directory and never outgrow the file; 11,339 executions), `FuzzTypeStream` (every rendered member encodes; 2.17 million), `FuzzAddresses` (names non-empty, addresses 32-bit; 1.79 million), `FuzzUndecorateC` (a C++ name unchanged, output part of the input; 2.27 million), `FuzzProcessorStartPage` (a named kernel has a kernel PDB and page-aligned base and DTB; 749).
3. Table identity (`pdbfacts convert`, old converter against new, 29 PDBs): 20 tables have identical content; 9 differ, each only as below.

| Difference | Tables | Count | Justification |
|---|---|---|---|
| Member pointing to a function written `*` (was `*void`) | ntkrnlmp ×4, ntdll ×3, wntdll, hal 14393 | 2,858 members (716, 714, 544, 206; 149, 149, 117; 149; 114) | The referent is LF_PROCEDURE, not void (F7); FORMAT.md writes a pointer to a function as `*`. |
| Member whose type is a forward enum with no definition written with no name (was `void`) | ntkrnlmp 0D960CE1 | 1 (`_IO_ADAPTER_CRYPTO_KEY_DESCRIPTOR.KeyType`, `_STORAGE_ICE_KEY_TYPE`, underlying 0x00) | 0x00 is "no type" (F11); the enum's storage is unknown, not void. |
| x86 names with an `@` outside the forms of F18 kept whole | wntdll | 11 names gone, 12 added | The old names were not C names: `ExecuteHandler`, `ExecuteHandler2` (from `…@20` with no underscore), seven `__@@_PchSym_…` (from `___@@…`), `_real` and `_xmm` (from constants `__real@0000000000000000`, `__xmm@0001…`, `__xmm@8000…`; `_xmm` stood for two constants at once). |

   The converter's output changed, so `BuilderVersion` is now 10: tables are cached under `…/symbols/windows/10/`, and each is rebuilt from its PDB the first time it is needed (offline sessions need the table placed there). The 29 tables of the captures were converted with the new code and placed in the local cache.

4. Processor start page on the captures (`pdbfacts lowstub`, identification through a reader without the crash-dump header): all five give the kernel the process list gives, with its base and page-table root: mem1 0xfffff8037d130000/0x7d5000 (39 ms), mem2 0xfffff80563400000/0x7d4000 (21 ms), mem5 0xfffff80145019000/0x7d2000 (36 ms, stepping over hal), mem6 0xfffff804a6ba0000/0x7d5000 (53 ms), mem7 0xfffff801a1850000/0x7d5000 (48 ms). The previous rule gave the same kernels on mem1, mem2 and mem5 (mem6 and mem7 are identified from their crash dump header first).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Enumeration-typed members are written as the enum's underlying type, as before; the table can name the enumeration instead (FORMAT.md allows it), which would let tools show constant names. Owner decision: keep the underlying type (default) or name the enumeration (another `BuilderVersion`). | Owner decision |
| O2 | Records named `<unnamed-tag>`/`<anonymous-tag>` are left out, so a member of such a type has a type the table does not hold. Embedding them (`embeds`) or naming them after their unique names would make them readable. | Owner decision |
| O3 | Global procedures are reached by their (decorated) public only; their undecorated S_PROCREF names (M6) could be added as further names. | Owner decision |
| O4 | Base classes (LF_BCLASS) are skipped, so a C++ class's inherited members are not brought up. No measured PDB with types has one (M3). | A PDB with C++ types, Owner decision |
| O5 | The start page layout (offsets 0x70 and 0x90) has no type source (K3); it rests on four builds. | A capture of another build (Q7) |
| O6 | No PDB with OMAP or LF_CLASS/LF_INTERFACE was measured (M3, M5); those paths are tested on fixtures only. ARM64 PDBs (0xAA64) are accepted on the PE/COFF machine value alone. | A PDB of those kinds |
| O7 | An OMAP entry mapped to 0 is read as removed code; F16 does not say so. | A PDB with OMAP |
| O8 | The scalar names (`int` names the 32-bit integer and `long long` the 64-bit one) and the fixed scalar set are the table vocabulary (Q2/Q3 naming). | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep underlying type |
| O2 | Leave them out |
| O3 | Public decorated name only |
| O4 | Keep skipping |
| O5 | Defer; four builds agree |
| O6 | Defer; fixtures only |
| O7 | Read as removed code |
| O8 | Keep these names and fixed set |

## 11. Provenance

Written from LLVM's PDB format documentation, Microsoft's `cvinfo.h`, Microsoft Learn (PE Format, OMAP, Decorated names, Symbol Store Folder Tree, Symbol Storage Format, Data Type Ranges), the Intel SDM and the project's measurements. Old implementation files were read only for exported names, callers and internal names used by `declare.go`; the old converter was run only to produce the tables compared in section 9. Every rule rests on the sources and measurements above.
