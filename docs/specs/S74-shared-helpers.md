# S74: Shared helpers

Version 1, 2026-11-12.

## 1. Purpose

Every tool reads untrusted bytes through the same small helpers: integers and alignment, FILETIME values, region digests, C strings behind a pointer, counted `UNICODE_STRING`s, UTF-16 and UTF-8 text, a bounded set of limits, an x86 instruction decoder with a handful of questions about each instruction, and owner-only output files. An examiner needs each helper to say the same thing about the same bytes as the format's own definition does, to show ill-formed input rather than hide it, and to stop on absurd counts instead of reading without end.

This specification covers the packages `util`, `limits`, `disasm`, and `internal/ownerfile` (with `ownerfiletest`). The root `limits.go` of package `libvapour` is not covered (wave 10).

## 2. Inputs

| Helper | Input |
|---|---|
| `util` integers, alignment, slices | A byte slice, a byte order, a value and an alignment. |
| `util` FILETIME | A 64-bit FILETIME value. |
| `util` digests | A `memory.MemoryReader`, an offset and a size. |
| `util.ReadCString` | A reader, an address, a byte count (often from the image) and a limit (the caller's, usually `Limits.MaxNameBytes`). |
| `util.ReadUnicodeString` | The reader of the structure's own address space, its address, a `UnicodeStringLayout` (from `ResolveUnicodeStringLayout` and a symbol table, or the ABI layout) and a byte cap. |
| `util` text | UTF-16LE or UTF-8 bytes. |
| `limits` | A `Limits` value whose zero fields mean "default". |
| `disasm` | Code bytes, the address of the first byte, and the mode (`Mode32`, `Mode64`). |
| `ownerfile` | A path. |

## 3. Facts from the sources

### 3.1 Unicode and UTF-8

The Unicode Standard, Version 16.0.0, Chapter 3 (https://www.unicode.org/versions/Unicode16.0.0/core-spec/chapter-3/, accessed 2026-11-12). RFC 3629 (https://www.rfc-editor.org/rfc/rfc3629.txt, accessed 2026-11-12).

| # | Fact | Source |
|---|---|---|
| U1 | UTF-16 maps U+0000..U+D7FF and U+E000..U+FFFF to one 16-bit code unit and U+10000..U+10FFFF to a surrogate pair. "Because surrogate code points are not Unicode scalar values, isolated UTF-16 code units in the range D800..DFFF are ill-formed." | D91, 3.9.2 |
| U2 | A surrogate pair is a high-surrogate code unit followed by a low-surrogate code unit; "Isolated surrogate code units have no interpretation on their own." | D75 |
| U3 | Well-formed UTF-8 (Table 3-7): 00..7F; C2..DF 80..BF; E0 A0..BF 80..BF; E1..EC 80..BF 80..BF; ED 80..9F 80..BF; EE..EF 80..BF 80..BF; F0 90..BF 80..BF 80..BF; F1..F3 80..BF 80..BF 80..BF; F4 80..8F 80..BF 80..BF. "The following byte values are disallowed in UTF-8: C0-C1, F5-FF." | 3.9.3, Table 3-7 |
| U4 | RFC 3629 section 4 gives the same grammar (`UTF8-2 = %xC2-DF UTF8-tail`, `UTF8-3 = %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) / %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )`, `UTF8-4 = %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) / %xF4 %x80-8F 2( UTF8-tail )`). | RFC 3629 §4 |
| U5 | A maximal subpart is "the longest code unit subsequence starting at an unconvertible offset that is either: a. the initial subsequence of a well-formed code unit sequence, or b. a subsequence of length one". The recommended practice replaces each maximal subpart by a single U+FFFD and continues after it. The Standard does not require this practice for conformance. | D93a, D93b, 3.9.6 |
| U6 | Tables 3-8 to 3-11 give the expected output for four inputs: `C0 AF E0 80 BF F0 81 82 41` gives 8 × U+FFFD then A. `ED A0 80 ED BF BF ED AF 41` gives 8 × U+FFFD then A. `F4 91 92 93 FF 41 80 BF 42` gives 5 × U+FFFD, A, 2 × U+FFFD, B. `E1 80 E2 F0 91 92 F1 BF 41` gives 4 × U+FFFD then A. | 3.9.6 |
| U7 | U+2400 is SYMBOL FOR NULL, general category So (a graphic symbol). | UnicodeData.txt 16.0.0 (https://www.unicode.org/Public/16.0.0/ucd/UnicodeData.txt) |

### 3.2 Microsoft Learn

| # | Fact | Source (accessed 2026-11-12) |
|---|---|---|
| L1 | A FILETIME "contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)", stored as `dwLowDateTime` then `dwHighDateTime`. | "FILETIME (minwinbase.h)", updated 2024-02-22 |
| L2 | For `FileTimeToSystemTime`, the value "must be less than 0x8000000000000000. Otherwise, the function fails." | "FileTimeToSystemTime function (timezoneapi.h)", updated 2025-07-01 |
| L3 | `UNICODE_STRING` is `{ USHORT Length; USHORT MaximumLength; PWSTR Buffer; }`. Length is "the length, in bytes, of the string stored in Buffer"; MaximumLength "the length, in bytes, of Buffer". "If the string is null-terminated, Length does not include the trailing null character." | "_UNICODE_STRING (ntdef.h)", updated 2024-02-22 |
| L4 | `CreateFileW`: the security descriptor in `lpSecurityAttributes` is applied to the file; if it is NULL "the file or device associated with the returned handle is assigned a default security descriptor". "CreateFile ignores the lpSecurityDescriptor member when opening an existing file or device." `CREATE_NEW` creates the file only when no file of that name exists; otherwise the call fails with ERROR_FILE_EXISTS (80). With `FILE_FLAG_OPEN_REPARSE_POINT`, "Normal reparse point processing will not occur; CreateFile will attempt to open the reparse point"; the flag "cannot be used with the CREATE_ALWAYS flag". | "CreateFileW function (fileapi.h)", updated 2025-07-01 |
| L5 | `CreateDirectoryW`: the descriptor in `lpSecurityAttributes` is applied to the new directory; with NULL "the directory gets a default security descriptor. The ACLs in the default security descriptor for a directory are inherited from its parent directory." The function "will only create the final directory in the path" (`ERROR_PATH_NOT_FOUND` otherwise) and fails with `ERROR_ALREADY_EXISTS` for an existing one. | "CreateDirectoryW function (fileapi.h)", updated 2025-07-01 |
| L6 | `SetSecurityInfo` sets the parts of an object's descriptor named in `SecurityInfo`; with `DACL_SECURITY_INFORMATION` and a NULL `pDacl`, "full access to the object is granted to everyone". | "SetSecurityInfo function (aclapi.h)", updated 2024-02-22 |
| L7 | Security descriptor strings: `O:owner_sid`, `D:dacl_flags(string_ace)...`; the DACL flag "P" sets `SE_DACL_PROTECTED`. | "Security Descriptor String Format", updated 2025-07-10 |
| L8 | ACE strings: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid`. "A" is `ACCESS_ALLOWED_ACE_TYPE`, "D" `ACCESS_DENIED_ACE_TYPE`; flags "OI" `OBJECT_INHERIT_ACE`, "CI" `CONTAINER_INHERIT_ACE`; rights "FA" `FILE_GENERIC_ALL` (`FILE_ALL_ACCESS`), "FR" `FILE_GENERIC_READ`. | "ACE Strings", updated 2025-03-12 |
| L9 | `S-1-5-18` (`SECURITY_LOCAL_SYSTEM_RID`) is "a special account used by the operating system"; `S-1-5-32-545` is the local Users group (SDDL "BU"); `S-1-3-0` (Creator Owner) "is used in inheritable ACEs" and replaced by the creator's SID. | "Well-known SIDs", updated 2025-10-01 |

### 3.3 POSIX

The Open Group Base Specifications Issue 8, IEEE Std 1003.1-2024, `open()` (https://pubs.opengroup.org/onlinepubs/9799919799/functions/open.html, accessed 2026-11-12).

| # | Fact |
|---|---|
| P1 | With `O_CREAT` the new file's permission bits are the mode argument ANDed with the complement of the file mode creation mask; "If the file exists, this flag has no effect except as noted under O_EXCL". |
| P2 | "If O_CREAT and O_EXCL are set, open() shall fail if the file exists." "If O_EXCL and O_CREAT are set, and path names a symbolic link, open() shall fail and set errno to [EEXIST], regardless of the contents of the symbolic link." |
| P3 | `O_TRUNC` on an existing regular file opened for writing truncates it to 0, and "the mode and owner shall be unchanged". |

### 3.4 Intel SDM

Volume 2 (combined 2A-2D), order number 325383-093US. Volume 1, order number 253665-093US. Volume 3A, order number 253668-093US. AMD APM Volume 3 could not be fetched (O3).

| # | Fact | Source |
|---|---|---|
| I1 | "The maximum length of an Intel 64 and IA-32 instruction remains 15 bytes." | Vol 2 2.3.11 |
| I2 | "The LOCK prefix can be prepended only to the following instructions and only to those forms of the instructions where the destination operand is a memory operand: ADD, ADC, AND, BTC, BTR, BTS, CMPXCHG, CMPXCH8B, CMPXCHG16B, DEC, INC, NEG, NOT, OR, SBB, SUB, XOR, XADD, and XCHG." Other uses raise #UD. | Vol 2, LOCK |
| I3 | `0F 05 SYSCALL`: 64-bit mode Valid, Compat/Leg mode Invalid; "#UD The SYSCALL instruction is not recognized in compatibility mode" (and in protected, real-address and virtual-8086 mode). Table A-3 marks SYSCALL and SYSRET (0F 07) "o64". | Vol 2 4-699, Table A-3 |
| I4 | "A REX prefix is ignored, as are its individual bits, when it is not needed for an instruction or when it does not immediately precede the opcode byte or the escape opcode byte (0FH)." | Vol 2 2.2.1 |
| I5 | In 64-bit mode ModR/M mod = 00, r/m = 101 means RIP + Disp32, "using a signed 32-bit displacement"; the effective address adds the displacement "to the 64-bit RIP of the next instruction". The SIB form with base = 101 and mod = 00 stays a plain Disp32. | Vol 2 2.2.1.6, Table 2-7 |
| I6 | In 64-bit mode the direct memory-offset MOV forms (A0..A3) take a 64-bit offset. | Vol 2 2.2.1.4 |
| I7 | `CC INT3` and `CD 03` both raise vector 3; "Intel and Microsoft assemblers will not generate the CD03 opcode from any mnemonic". | Vol 2, INT n/INTO/INT3/INT1 |
| I8 | "32-bit operands generate a 32-bit result, zero-extended to a 64-bit result in the destination general-purpose register"; 8- and 16-bit operands leave the upper bits unchanged. | Vol 1 3.4.1.1 |
| I9 | One-operand MUL, IMUL, DIV and IDIV leave the result in AX, DX:AX, EDX:EAX or RDX:RAX by operand size; two- and three-operand IMUL write the destination operand. CWD, CDQ and CQO write DX, EDX or RDX only. CWDE writes EAX, CDQE writes RAX. CPUID writes EAX..EDX; RDTSC, RDMSR, RDPMC and XGETBV write EDX:EAX; RDTSCP writes EDX:EAX and ECX; POPAD writes the eight 32-bit registers; LODSD loads EAX and LODSQ RAX. CMPXCHG loads the accumulator only when the comparison fails. TEST and CMP set flags only; BOUND reads its register operand. | Vol 2 instruction pages |
| I10 | Table A-2 marks 82 (Group 1, Eb, Ib) "i64": invalid in 64-bit mode, valid outside it. SALC (D6) is valid outside 64-bit mode; in 64-bit mode D6 encodes UDB (#UD). | Vol 2 Table A-2, SALC, UDB |
| I11 | Table A-6 leaves Group 2 /6 (C0, C1, D0..D3) and Group 3 /1 (F6, F7) blank; Table A-10 leaves D9 D8..DF blank; Table A-3 leaves 0F 24 and 0F 26 blank. "All blanks in all opcode maps are reserved and must not be used." | Vol 2 Appendix A |
| I12 | "EVEX.mmm: P[2:0] provides access to up to eight decoding maps. Currently, only the following decoding maps are supported: 1, 2, 3, 5, and 6." Outside 64-bit mode, 62 is BOUND when P[7:6] is not 11b. | Vol 2 2.7.1, 2.7.11 Table 2-40 |
| I13 | Physical addresses are at most 52 bits wide (MAXPHYADDR); 5-level paging translates 57-bit linear addresses. | Vol 3A 2.5, 5.1.4 (S04, S53 P2) |

### 3.5 golang.org/x/arch v0.29.0 (x86asm)

Measured by the package's own tests (section 9.3), not by reading its source.

| # | Fact |
|---|---|
| X1 | A run of prefixes with no opcode (`66 66`) returns no error and a zero `Op`. |
| X2 | A four-byte buffer that starts with 62 (`62 30 30 30`) panics. |
| X3 | A 32-bit displacement is returned zero-extended: `[rip-0x10]` arrives as `Disp` 0xFFFFFFF0. |
| X4 | `0F 05` in 32-bit mode is an error. |
| X5 | The library refuses 82 and D6 in 32-bit mode, every Table A-6/A-10 blank of I11, a REX that is not next to the opcode, and RDSEED. It decodes 0F 24 and 0F 26 as `MOV` to or from `TR0`..`TR7`, an EVEX map 5 or 6 encoding as a map 1 to 3 instruction, and LOCK on a register destination. |
| X6 | It does not decode CLAC, STAC (0F 01 CA, CB) or SETSSBSY (F3 0F 01 E8) (M3). |
| X7 | `x86asm.Inst.Opcode` holds the opcode byte in its top 8 bits and may hold the ModR/M byte below it. |

### 3.6 Linux

| # | Fact | Source |
|---|---|---|
| K1 | `PATH_MAX` is 4096 ("chars in a path name including nul") and `NAME_MAX` 255. | `include/uapi/linux/limits.h` at v4.19, v6.1, v6.4, v6.14, v6.17 |

### 3.7 Measurements

`helperfacts` on all seven captures, 2026-11-12, and the package tests on the differential corpus `disasm/testdata/disasm_corpus.tsv`.

- **M1 `_UNICODE_STRING`.** On mem1, mem2, mem5, mem6 and mem7 (builds 26100, 19045, 14393, 26100, 26100), the kernel table gives size 16, `Length` 0 (2 bytes), `MaximumLength` 2 (2 bytes), `Buffer` 8 (8 bytes), pointer size 8. `ResolveUnicodeStringLayout` returns `{0, 2, 8, 16}` on each.
- **M2 Module names.** Every `FullDllName` and `BaseDllName` on `PsLoadedModuleList` reads: 390 strings (mem1, 195 modules), 390 (mem2, 195), 284 (mem5, 142), 316 (mem6, 158), 330 (mem7, 165). None fails, is empty, has an odd `Length`, has `Length` above `MaximumLength`, decodes with a U+FFFD, holds a NUL, or has a NULL `Buffer`. On every one `MaximumLength` equals `Length`. The longest `Length` is 208 bytes (232 on mem6).
- **M3 Decoding kernel routines.** Linear decode from the symbol, at most 64 instructions, stopping at RET or INT3: `NtReadVirtualMemory` 8 instructions (7 on mem2, mem5), all ending in RET. `KeBugCheckEx` 59 instructions, 4 RIP-relative and 5 transfers, on all five. `KiSystemCall64` stops at `F3 0F 01 E8` after 11 instructions (mem1, mem6, mem7), at `0F 01 CB` after 20 (mem2), and decodes all 64 on mem5 (X6).
- **M4 FILETIME.** `_KUSER_SHARED_DATA.SystemTime` converts to 2026-05-06T18:24:25.8349547Z (mem1), 2026-05-26T20:50:39.1244503Z (mem2), 2026-01-30T08:27:03.7901414Z (mem5), 2026-09-27T19:18:15.6445791Z (mem6), 2026-10-29T19:09:32.4613491Z (mem7). `NtSystemRoot` decodes to `C:\Windows` on all five.
- **M5 C string.** `linux_banner` read with `ReadCString`, count 1024, limit `MaxNameBytes`: 273 bytes on mem3 (6.17), 210 on mem4 (6.14), each ending in a newline before its NUL.
- **M6 Corpus.** 5,278 encodings: 2,344 from ntdll.dll `.text` (64- and 32-bit), 2,800 random, 134 by hand. The independent decoder reads 5,080; this package reads 5,035; the two disagree on 45 (table 9.1), none from ntdll. Of the 5,035, the corpus spells 12 control transfers differently (far branches as `ljmp`/`lcall`, a prefix folded into `bnd ret`, `CD 03` as `int`) and marks 33 register writes against the manual (table 9.2). The control-transfer kinds reached are call 97, int3 214, jmp 127, lea 122, leave 24, mov 910, ret 51, syscall 3. There are 35 RIP-relative second operands, 7 backward and 21 from compiled code, and 636 accumulator and 24 R10 writes.

## 4. Algorithm

### 4.1 Integers, alignment, slices

`ReadUint16/32/64` decode the first 2, 4 or 8 bytes in the given order, or return `ErrBufferTooSmall`. `AlignDown(v, a)` is `v − v mod a`; `AlignUp(v, a)` adds `a − v mod a` when the remainder is not 0, wrapping past 2^64 as unsigned arithmetic does; `IsAligned` tests `v mod a = 0`. An alignment of 0 means none: the value is returned and is aligned. `SafeSubslice(b, off, n)` returns `b[off:off+n]` when `0 ≤ off ≤ len(b)` and `0 ≤ n ≤ len(b) − off`, never forming `off + n`.

### 4.2 FILETIME

`FiletimeToTime(v)`: 0 is no time (a time never set); `v ≥ 2^63` is no time (L2). Otherwise seconds are `v / 10^7 − 11,644,473,600` and nanoseconds `(v mod 10^7) × 100` (L1), in UTC. 11,644,473,600 is 369 years of 365 days plus 89 leap days, in seconds. `FiletimeToRFC3339` formats the same time with whole seconds and gives no text past 9999-12-31T23:59:59Z (`LastRFC3339Second`), since RFC 3339 has a four-digit year.

### 4.3 Region digests

`HashRegion` reads the region in reads of at most 1 MiB and feeds MD5, SHA-1 and SHA-256 at once; `MD5Region`, `SHA1Region` and `SHA256Region` feed one. Digests are lower-case hex. A read error ends the digest with that error; a read that returns fewer bytes than asked ends it with an error naming the address, since a digest over fewer bytes names a region that is not there.

### 4.4 C strings behind a pointer

`ReadCString(r, addr, count, limit)`:

1. `count` 0 is an error.
2. Read up to the end of the 4-KByte page or `count`, whichever is first.
3. A failed read with nothing read yet is the error; after the first read it ends the text.
4. A NUL ends the text before it.
5. A read shorter than asked, or an address that would wrap past 2^64, ends the text.
6. More than `limit` bytes of text is `ErrStringPastLimit`.
7. The bytes are decoded as UTF-8 with replacement (4.7).

### 4.5 UNICODE_STRING

`ResolveUnicodeStringLayout(table)`: the ABI layout (two USHORTs, then the pointer at its own alignment: `{0, 2, 8, 16}` for 8-byte pointers, `{0, 2, 4, 8}` for 4-byte ones, L3), with each member offset and the size replaced by the table's `_UNICODE_STRING` when it has them (M1). A nil table gives the 8-byte layout.

`ReadUnicodeString(r, addr, layout, maxBytes)`:

1. No reader is an error. `maxBytes` 0 or above 0xFFFF becomes 0xFFFF (`MaxUnicodeStringBytes`, the USHORT maximum).
2. Read the header through the end of its furthest member only: the padding after it may be on a page that is not resident. The pointer width is the structure size less `BufferOffset` when that is 4, else 8.
3. A short header read is an error.
4. `Length` 0 is the empty string, whatever `Buffer` holds.
5. `Length` above 0 with `Buffer` 0 is an error: no buffer holds text at address 0.
6. Read `min(Length, maxBytes)` bytes at `Buffer` and decode them with 4.6, NULs kept. The counts stay as read when the buffer read fails, so a caller can report them.

`Chars` is `Length / 2`. `MaxChars` is `MaximumLength / 2 − 1` (the units the buffer holds less one for a terminating NUL, L3), 0 below 2 bytes. `Text` and `CountedText` drop trailing NULs (a terminator) and show each remaining NUL as U+2400 (`VisibleNUL`, U7): an embedded NUL is data, such as an argument separator in a command line or a registry name the Win32 API cannot reach, and a visible `\0` could be a real path component.

### 4.6 UTF-16LE

`DecodeUTF16LE` decodes every unit; `DecodeUTF16LEZ` stops at the first 0 unit. Each unpaired surrogate becomes U+FFFD (U1, U2). A final odd byte is part of a code unit and becomes U+FFFD; when the unit before it is a high surrogate, the two are the start of one character cut short and become one U+FFFD (U5 applied at code-unit granularity, O14). `DecodeCountedUTF16LE` is `CountedText` of `DecodeUTF16LE`.

### 4.7 UTF-8

`DecodeUTF8Replace` returns well-formed input unchanged. Otherwise each maximal subpart (U5) becomes one U+FFFD: from a lead byte of Table 3-7 (U3), accept as many following bytes as stay within the table's ranges (the second byte's range depends on the lead), and replace that prefix; any other byte is replaced alone. NULs are kept. `DecodeUTF8Z` cuts at the first NUL byte first; a NUL is a whole one-byte character, so the cut splits no sequence. `ReplaceInvalidUTF8` does the same for a string.

### 4.8 Limits

`Resolved` takes each field in turn: negative is an error, above its ceiling is an error, 0 becomes its default. Then four nestings must hold: `MaxNameBytes ≤ MaxTextBytes ≤ MaxBufferBytes` and `RowPreviewBytes ≤ MaxArtifactBytes ≤ MaxImageBytes`. Each error is a `*Error` naming the field, its value and the reason. `Effective` is `Resolved`, or every default when that fails: a field-by-field fallback could break a nesting. `Default` is the zero value resolved. `Workers` defaults to `GOMAXPROCS`, capped at its ceiling.

### 4.9 Instruction decoding

`Decode(code, address, mode)`:

1. Empty code is no instruction.
2. Decode with x86asm in the mode. A panic (X2) or an error is no instruction.
3. A zero `Op` (X1), or a length outside 1..15 (I1), is no instruction.
4. LOCK is allowed only on an I2 instruction whose first operand is memory; otherwise no instruction (I2, X5).
5. An operand that is a test register is no instruction (I11, X5).
6. After the legacy prefixes, a 62 byte whose next byte selects EVEX (always in 64-bit mode; P[7:6] = 11b outside it, I12) must name map 1, 2 or 3; maps 5 and 6 exist (I12) but the library cannot read them (X5).
7. Otherwise the instruction carries the address, its length, and its Intel-syntax text with no symbol lookup.

SYSCALL and SYSRET in 32-bit mode are refused by step 2 (X4), which is what the manual says (I3).

Predicates on a decoded instruction:

| Predicate | True for | Source |
|---|---|---|
| `IsJmp` | `JMP` and far `LJMP` | |
| `IsCall` | `CALL` and far `LCALL` | |
| `IsRet` | near `RET`, with or without an immediate or prefixes; a far return is not one | |
| `IsLeave`, `IsSyscall`, `IsLea` | `LEAVE`, `SYSCALL`, `LEA` | |
| `IsInt3` | `CC`, and `INT` with immediate 3 | I7 |
| `IsMov` | `MOV`, except B8+r with a 64-bit operand and A0..A3 with a 64-bit offset | I6 |
| `RIPRelativeTarget` | the second operand is `[rip + disp]`: the target is the address after the instruction plus the displacement taken as a signed 32-bit value | I5, X3 |
| `HasZeroOpcode` | the opcode byte (top byte of `Opcode`) is 00 | X7 |
| `Op` | the library's operation | |

### 4.10 Register writes

`WritesAccumulator` asks whether the instruction leaves a new value in all of RAX (or EAX in 32-bit mode); `WritesR10` the same for R10. A write is a 64-bit write or a 32-bit write, which zero-extends (I8); an 8- or 16-bit write is not one.

1. Operand writes. The first operand is written except where the instruction only reads it: CMP, TEST, BT, PUSH, JMP, LJMP, CALL, LCALL, OUT, VERR, VERW, LLDT, LTR, LMSW, NOP, one-operand MUL, IMUL, DIV and IDIV, BOUND, INVPCID, WRFSBASE, WRGSBASE, SCAS and CMPS (I9). XCHG and XADD also write the second operand.
2. Implicit writes, counted only when the write always happens (I9): CPUID, RDTSC, RDTSCP, RDMSR, RDPMC, XGETBV, POPAD, CWDE and LODSD write EAX; CDQE and LODSQ write RAX; one-operand MUL, IMUL, DIV and IDIV write EAX or RAX at a 32- or 64-bit operand width, taken from the register operand, else the memory operand's size, else the default operand size. CMPXCHG, CWD, CDQ and CQO are not counted. No instruction writes R10 implicitly.

### 4.11 Owner-only files

POSIX:

- `CreateNew`: open with `O_WRONLY|O_CREAT|O_EXCL` and mode 0600 (P1, P2); an existing file or a symbolic link fails.
- `Create`: open with `O_WRONLY|O_CREAT|O_TRUNC` and mode 0600. `O_CREAT` leaves an existing file's mode as it was (P1, P3), so an existing regular file whose mode is not 0600 is set to 0600 through the handle. A device keeps its mode: narrowing a shared device such as `/dev/null` as root would break it for every user.
- `MkdirAll`: create missing directories with mode 0700; existing ones are untouched.
- `IsPrivate`: no group or other permission bit set.

Windows:

- The descriptor is `O:<user>D:P(A;<f>;FA;;;<user>)(A;<f>;FA;;;SY)` (L7, L8, L9), where `<user>` is the process token's user. Creator Owner is not used, because in an elevated process the creator owner would be the Administrators group. `<f>` is `OICI` for a directory, so what is created inside it inherits both entries, and empty for a file. "P" stops the parent's entries from applying. The system account keeps access because the operating system acts as it.
- `CreateNew`: `CreateFileW` with `GENERIC_WRITE`, read and write sharing, the descriptor, `CREATE_NEW` and `FILE_FLAG_OPEN_REPARSE_POINT` (L4). The flag makes a link at the path count as an existing file, so the call fails instead of creating the link's target.
- `Create`:
  - An existing path that is neither a regular file nor a directory, such as `NUL`, is opened for writing as it is.
  - Otherwise `CreateNew` is tried first.
  - If the file exists, `CreateFileW` ignores the descriptor (L4). The file is opened with `WRITE_DAC`, the protected list is set through the handle (`SetSecurityInfo`, `PROTECTED_DACL_SECURITY_INFORMATION`, L6), and then the file is truncated.
- `MkdirAll`: walk up the path until an existing entry is found; one that is not a directory is `ENOTDIR`. Create each missing directory from the outermost down with the directory descriptor (L5). A directory that appears meanwhile is accepted.
- `IsPrivate`: read the DACL. A NULL DACL grants everyone everything (L6) and is not private. Every access-allowed entry must name the user or `S-1-5-18`. Access-denied entries are allowed. Any other entry kind is not vouched for and makes the file not private.

`ownerfiletest.LooseDir` returns a test directory opened up (POSIX mode 0755; on Windows an unprotected entry granting BUILTIN\Users read, inherited by files) and proves a plain file in it is not private before returning it.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| FILETIME 0 or ≥ 2^63 | L2; 0 is the value of a time never set | no time |
| UNICODE_STRING text cut at `maxBytes` | `Length` is a USHORT (L3); a longer read is never needed | partial text, no error |
| `Length` > 0 with NULL `Buffer` | address 0 holds no text | error, counts kept |
| C string longer than the limit | the limit is the caller's bound | `ErrStringPastLimit` |
| Ill-formed UTF-16 or UTF-8 | U1, U3, U5 | U+FFFD, never dropped |
| LOCK, test registers, EVEX maps 5 and 6, length > 15 | I1, I2, I11, I12 | no instruction |
| Limits negative, past a ceiling, or out of nesting | section 8 | `*limits.Error` |

## 6. Failure modes

| Case | Result |
|---|---|
| Buffer too short for an integer | `util.ErrBufferTooSmall` ("util: buffer too short") |
| C string count 0 | "util: string byte count is zero" |
| C string over limit | `util.ErrStringPastLimit` ("util: string exceeds its read limit") |
| First C string read fails | the reader's error |
| Region read fails / short | the reader's error / "util: region read at 0x…: n of m bytes" |
| UNICODE_STRING: no reader, header unreadable, header short, NULL buffer, buffer unreadable | "util: _UNICODE_STRING at 0x…: no reader", "…: %w", "…: n of m bytes read", "…: length n with a null buffer", "util: _UNICODE_STRING buffer at 0x…: %w" |
| Limits | "limits: <Field> <value>: negative", "…: past its ceiling <c>", "…: exceeds <Field> <value>" |
| Decode failure | `ok` false, no error |
| ownerfile | `*os.PathError` from the system call; "ownerfile: process token user: %w", "ownerfile: private security descriptor: %w" |

## 7. Result schema

No tool rows. Exported types and their units:

| Type | Fields |
|---|---|
| `util.UnicodeString` | `Length`, `MaximumLength` (bytes, as read), `Buffer` (address), `Value` (decoded text, NULs kept) |
| `util.UnicodeStringLayout` | byte offsets of the three members and the structure size |
| `util.RegionHashes` | `MD5`, `SHA1`, `SHA256`, lower-case hex |
| `disasm.Inst` | `Address`, `Len` (bytes), `Text` (Intel syntax, relative targets from 0) |
| `limits.Limits` | counts (`int`) and byte sizes (`int64`); 0 is the default |

## 8. Limits

| Field | Default | Ceiling | Reason |
|---|---|---|---|
| `MaxListEntries`, `MaxTableEntries`, `MaxRowsPerObject` | 2^20, 2^22, 2^20 | 2^31 − 1 | ceiling: the largest `int` on every supported platform (O8) |
| `MaxRecursionDepth` | 1024 | 2^16 | O8 |
| `MaxPathSteps` | 4096 | 2^20 | O8 |
| `MaxNameBytes` | 4096 | 2^32 | `PATH_MAX` (K1) |
| `MaxTextBytes`, `MaxBufferBytes`, `MaxKernelImageBytes` | 1 MiB, 64 MiB, 64 MiB | 2^32 | O8 |
| `MaxRegionScanBytes` | 1 GiB | 2^57 | ceiling: the 57-bit linear address space (I13) |
| `MaxMatchesPerChunk` | 1,000,000 | 2^24 | O8 |
| `PTECacheEntries` | 8192 | 2^22 | default measured in S53 M9 |
| `Workers` | `GOMAXPROCS` | 1024 | O8 |
| `MaxArtifactBytes`, `MaxImageBytes`, `RowPreviewBytes` | 1 GiB, 1 TiB, 128 | 2^52 | ceiling: the 52-bit physical address width (I13) |
| `MaxArchiveBytes` | 16 GiB | 2^52 | the sum of one archive's members (S12 section 8, follow-up D4); not nested, so it may be set below `MaxArtifactBytes` |
| `NameAttempts` | 65536 | 2^20 | O8 |

`MaxUnicodeStringBytes` is 0xFFFF, the USHORT maximum (L3). `HashRegion` reads at most 1 MiB at a time; the C-string reader at most a page.

## 9. Acceptance

### 9.1 Decode disagreements with the corpus (M6)

| Rule | Count | Source |
|---|---|---|
| 82 and D6 (SALC) outside 64-bit mode: valid, refused by the library | 13 | I10, X5 |
| Blank in the opcode map: Group 2 /6, F6/F7 /1, D9 D8 | 16 | I11 |
| REX not next to the opcode: ignored by the processor, refused by the library | 9 | I4 |
| RDSEED, absent from the library | 1 | X5 |
| SYSCALL and SYSRET outside 64-bit mode | 5 | I3 |
| LOCK with a register destination | 1 | I2 |

Every one of the 45 is an encoding the corpus decodes and this package does not; none is in this package only; none is from ntdll.

### 9.2 Register-write disagreements (M6)

| Rule | Count | Source |
|---|---|---|
| TEST sets flags only | 12 | I9 |
| CDQ and CQO write only EDX or RDX | 12 | I9 |
| BOUND reads its register operand | 1 | I9 |
| A 32-bit destination zero-extends into R10 | 8 | I8 |

### 9.3 Tests

- `util`: Unicode Tables 3-8 to 3-11 (U6); surrogate pairs, lone surrogates, odd bytes, NUL views; FILETIME at 1, the Unix epoch, 2^63 − 1 (30828-09-14T02:48:05.4775807Z), 0 and 2^63; RFC 3339 at 9999-12-31T23:59:59Z and one second later; alignment with a power of two, with 3, with 0 and at the top of the range; `SafeSubslice` at overflow; region digests equal to the standard library's over a 2.4 MB region in three reads; short and unreadable regions; C strings across a page, cut by count, at a limit, before an unreadable page; UNICODE_STRING at both pointer widths, at a page end, with a NULL buffer, an unreadable buffer, `Length` 0xFFFF and a cap.
- `limits`: every default; set fields kept; every ceiling accepted; each refusal names its field; `Effective` falls back whole.
- `disasm`: the corpus tests (9.1, 9.2, lengths, control-transfer kinds, RIP-relative targets, zero opcodes); refused encodings (I1 to I3, I10 to I12); LOCK on memory destinations; 15-byte instructions; control transfers including far forms, `CD 03` and far return; `IsMov` forms; RIP-relative sign extension and the SIB Disp32 form; register writes; and the library facts X1 to X4.
- `ownerfile`: everything created in an opened-up directory is private; `CreateNew` refuses an existing file; `MkdirAll` leaves an existing directory alone and refuses a path below a file; `Create` opens the null device as it is. Windows: protected list, owner, two full-access entries for the user and the system account, inheritance on directories, and `IsPrivate` on six lists. POSIX (built for linux, not run on this host): modes, mode bits and a dangling link.
- Fuzz targets, 30 s each: `FuzzDecodeUTF16LE`, `FuzzDecodeUTF8Replace`, `FuzzReadCString`, `FuzzUnicodeStringHeader`, `FuzzFiletimeToTime` (util); `FuzzDecode` (disasm, with the X2 crash input kept).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Exported names are kept. New or changed messages: the UNICODE_STRING null-buffer and header messages, the short region read, the C-string count message and the ownerfile prefixes. | Owner decision (Q2) |
| O2 | Behaviour changes from 0.1.0. `Decode` now refuses LOCK on a register destination, 0F 24 and 0F 26, EVEX maps 5 and 6, and SYSCALL or SYSRET in 32-bit mode. `WritesAccumulator` now counts LODSD and LODSQ and no longer counts BOUND. `ReadUnicodeString` refuses a NULL buffer without reading. `HashRegion` refuses a short read. `AlignDown` and `AlignUp` give arithmetic results for alignments that are not powers of two. | Owner decision |
| O3 | AMD APM Volume 3 could not be fetched. AMD processors may accept SYSCALL outside 64-bit mode. Only Intel's rule (I3) is applied. | The APM, SYSCALL page |
| O4 | Gaps in the library (X5, X6) are not patched: 82 and SALC in 32-bit mode, REX not next to the opcode, RDSEED, CLAC, STAC and SETSSBSY. A linear walk stops early at these (M3). | A newer golang.org/x/arch, measured against the corpus |
| O5 | `RIPRelativeTarget` looks at the second operand only. A RIP-relative first operand, as in `jmp [rip+x]` or `mov [rip+x], eax`, gives false. Callers depend on this. | Owner decision: keep, or add a predicate for any operand |
| O6 | `Mode.String` returns "intel" and "intel64", kept from 0.1.0. | Owner decision (Q2) |
| O7 | The differential corpus was made by an independent decoder that the repository does not name or hold. It is kept as test data. | Owner decision: keep, or regenerate from a documented source |
| O8 | Most limit defaults and some ceilings are project policy with no primary source. | Owner decision on each value |
| O9 | On Windows, `Create` on an existing file changes its DACL, not its owner. `IsPrivate` treats an inherit-only entry for another account as not private. | Owner decision |
| O10 | The POSIX half of `ownerfile` was built and vetted for linux but not run. | A run on a Linux host |
| O11 | A high surrogate followed by a lone final byte gives one U+FFFD. This applies D93b (U5) to a truncated code unit, which the Standard does not define. | Owner decision |
| O12 | `MaxChars` subtracts one unit for a terminating NUL. On all 1,710 measured module names `MaximumLength` equals `Length`, so `MaxChars` is one less than `Chars` there (M2). | Owner decision on whether capacity should count the terminator |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept |
| O2 | Accept |
| O3 | Keep Intel rule |
| O4 | Leave unpatched |
| O5 | Keep |
| O6 | Keep |
| O7 | Keep |
| O8 | Accept as policy |
| O9 | Keep |
| O10 | Run it |
| O11 | One U+FFFD |
| O12 | Subtract one for NUL |

## 11. Provenance

Written from the Unicode Standard 16.0 chapter 3, RFC 3629, the Microsoft Learn pages listed in 3.2, POSIX Issue 8, Intel SDM Volumes 1, 2 and 3A (edition 093), the Linux `limits.h` at the tags named, the ntoskrnl types in the project's symbol tables, the measured behaviour of golang.org/x/arch v0.29.0, and the project's measurements. Every rule rests on the sources and measurements above. The differential corpus (O7) holds another decoder's results.
