# S58: Symbol tables: types, members, bitfields, enumerations, symbols and the .vsym file

Version 1, 2026-11-12.

## 1. Purpose

Every tool reads kernel and process structures through a symbol table: where each member of a type lies, how wide it is, how a bitfield is cut out of its storage unit, what an enumeration constant is worth, and where a symbol lives. A wrong answer here is a wrong value in every row of every tool. The table must therefore say exactly what the image's own type information records (owner decision: type only what the image records), refuse what it cannot state, and never guess a width.

This specification covers the project's own table model in `symbols/` (top level): the declaration a converter or generator produces, the checks on it, how embedded (anonymous) members are brought up, lookups by name and by address, member widths and integer decoding, the reading helpers `IntField` and `CharArrayField`, and the `.vsym` file format of `symbols/FORMAT.md` (writer and reader). How PDB records become a declaration is S32; how BTF and kallsyms become one is S59 and S38.

## 2. Inputs

| Input | Use |
|---|---|
| `Declaration` | From the PDB converter (S32), the Linux generator (S59), the `.vsym` reader, or a caller. |
| `.vsym` bytes | A file of `symbols/FORMAT.md`, format 1, read whole. |
| `ReadOptions.MaxTableFile` | Default `MaxTableFile` (512 MiB), ceiling 4 GiB; bounds the bytes read from a file. |
| `ReadOptions.MaxTableEntries` | Default `limits.DefaultMaxTableEntries` (4,194,304), ceiling `limits.CeilingEntries`; the margin of the embedding bound (section 8). |
| `memory.MemoryReader` | For `ReadStruct`, `ReadUint32/64`, `ReadPointer`, `IntField.Read` and `CharArrayField.Read`. |

## 3. Facts from the sources

### Documentation

`symbols/FORMAT.md` (the project's own format, format 1). RFC 8259 (JSON) and RFC 3629 (UTF-8). ISO/IEC 9899:2011 (C11, the N1570 draft). Microsoft Learn pages as named, accessed 2026-11-12. Linux `Documentation/bpf/btf.rst` at v6.1 and v6.17 (the file does not exist at v4.19), fetched from git.kernel.org on 2026-11-12. LLVM "CodeView Type Records" and Microsoft `cvinfo.h` through S32 F7 and F9. DWARF 5 (dwarfstd.org) section 5.7.6. System V ABI AMD64 Architecture Processor Supplement, section 3.1.2.

| # | Fact | Source |
|---|---|---|
| F1 | A table file is one UTF-8 JSON object. The writer emits keys in the listed order, sorts lists as stated, indents by two spaces, writes one entry per line and ends with a newline, so one table always gives the same bytes. The reader refuses unknown, repeated or missing required keys, a format other than 1, a number that is not an exact integer in range, a value of the wrong type and anything after the object. It accepts list entries in any order. | FORMAT.md, Encoding |
| F2 | Widths, offsets and counts are unsigned 64-bit; enumeration values signed 64-bit; addresses are `0x` and lower-case hex with no leading zeros. | FORMAT.md, Encoding |
| F3 | Top-level keys `vsym` (1), `pointer_width` (4 or 8), `windows_pdb` (`guid` 32 upper-case hex, `age` unsigned 32-bit, optional non-empty `file`), `linux_banner` (non-empty), `scalars`, `records`, `enumerations`, `addresses`. With `scalars` absent a type's width is known from its name; with it present only declared widths count. | FORMAT.md, Top level, Scalars |
| F4 | A scalar has `name`, `width`, `kind` (integer, float, char, bool, void), optional `signed` and `big_endian` (written only when true). A float or big-endian scalar is never decoded as a little-endian integer. | FORMAT.md, Scalars |
| F5 | A record has `name`, optional `width` and `members` in declaration order. A named member has a unique non-empty name, a byte offset and a type expression. An embedded member names a record (`embeds`) whose members become this record's at their offsets plus its own, to any depth; its name is for messages only. When two members brought up share a name, the later replaces the earlier. A record whose embedded members cannot be brought up (missing record, record that embeds itself) stays as unreadable with the reason. A table whose embedding would bring up more than twice its members plus `MaxTableEntries` is refused. A record with no members is a name only. A record and an enumeration may share a name; the record is what a lookup returns. | FORMAT.md, Records |
| F6 | Type expressions: `name`; `*T`; `[N]T` (`[0]T` an array of no elements); `@O:L T`, `L` bits from bit `O` counted from the least significant bit of a `T` storage unit. A name starting with `*`, `[`, `@` or `\` is written after a `\`. At most 32 operators. `*` alone is a pointer to a function. | FORMAT.md, Type expressions |
| F7 | Enumerations: `name`, optional `width`, `constants` sorted by value then name. Addresses: `name`, `address`, optional `type`; sorted by name. | FORMAT.md |
| F8 | JSON strings escape `"`, `\` and control characters U+0000 to U+001F; `\uXXXX` with surrogate pairs for characters past U+FFFF. Numbers are `-? (0 | [1-9][0-9]*)` with optional fraction and exponent. `null`, `true`, `false` are literals. | RFC 8259 sections 6, 7, 3 |
| F9 | Well-formed UTF-8 excludes overlong forms and surrogates. | RFC 3629 section 3 |
| F10 | The type specifiers of a C type form a multiset and may occur in any order: `unsigned long int` and `long unsigned int` are one type; `long long`, `short int`, `signed`, `unsigned` are the listed sets. | C11 6.7.2p2 |
| F11 | Microsoft C/C++ sizes: `char`, `bool`, `__int8` 1; `short`, `wchar_t`, `__int16` 2; `int`, `long`, `float`, `__int32` 4; `long long`, `double`, `long double`, `__int64` 8. `signed`/`unsigned` modify any integral type except `bool`. | Microsoft Learn, "Data Type Ranges" |
| F12 | Exact-width integer types `intN_t`/`uintN_t` for N = 8, 16, 32, 64 have exactly N bits. | C11 7.20.1.1 |
| F13 | In C the storage of an enumeration is that of an int. | Microsoft Learn, "C Enumeration Declarations" |
| F14 | An enumerated type is compatible with an implementation-defined integer type capable of representing all its members' values. | C11 6.7.2.2p4 |
| F15 | Bit fields are allocated within an integer from least-significant to most-significant bit. | Microsoft Learn, "C Bit Fields" |
| F16 | Bit-fields are allocated from right to left (least to most significant) within their storage unit. | System V AMD64 psABI 3.1.2, Bit-Fields |
| F17 | A member's `DW_AT_data_bit_offset` counts bits from the start of the containing entity; on a little-endian target that is its least significant bit. | DWARF 5, 5.7.6 |
| F18 | A BTF member's `offset` is in bits; with `kind_flag` set, bits 0–23 are the bit offset and 24–31 the bitfield size. A BTF enum has `size` 1, 2, 4 or 8 and 32-bit values; `BTF_KIND_ENUM64` holds 64-bit values. | btf.rst 2.2.5, 2.2.6, 2.2.19 at v6.1 and v6.17 |
| F19 | An `lfBitfield` record gives the storage type, a bit length and a bit position; an `lfEnum` its underlying type. | S32 F7 (cvinfo.h) |
| F20 | x86-64 stores multi-byte values least significant byte first. | Intel SDM Vol. 1, 1.3.1 Bit and Byte Order |
| F21 | x86-64 System V sizes: `_Bool`, `char` 1; `short` 2; `int`, `enum` 4; `long` 8 under LP64 and 4 under ILP32; `long long` 8; a pointer 8 (LP64) or 4 (ILP32); `float` 4, `double` 8, `long double` 16. The figure gives no size for `wchar_t`. | System V AMD64 psABI, Figure 3.1 "Scalar Types" (x86-64-ABI repository, `low-level-sys-info.tex` at commit e1ce0983, 2025-03-12, fetched 2026-11-12) |
| F22 | The Microsoft sizes of F11 hold for the 32-bit and the 64-bit compilers alike. | Microsoft Learn, "Data Type Ranges" |

### Measurements

Script: `tablefacts` (new). Captures: mem1_win11, mem2_win10, mem5_server2016, mem6_server2025, mem7_server2025, mem3_ubuntu24 (6.17), mem4_fedora40 (6.14), E:\dataset\memory. Cache: `%LOCALAPPDATA%\libvapour\symbols\windows\10` (BuilderVersion 10).

| # | Measurement | Result |
|---|---|---|
| M1 | Cache tables read by the new reader, decoded and written again (`tablefacts <cache dir>`) | 42 tables, 39,235,341 bytes, every one written back byte for byte (42/42). At the last run the cache held 50 tables (44,422,115 bytes; other agents add tables), 50/50 byte-equal. |
| M2 | Shape of the 42 cache tables | 672 scalars (16 per table, the S32 set); 8,508 records, none name-only, none unreadable, none sharing an enumeration's name; 85,513 named members, 0 embedded; 11,899 bitfields, none reaching past its storage unit, highest bit end 64; 14,433 pointers; 4,842 arrays (11 of no elements); deepest type 5 operators; 1,991 enumerations, all width 4, 21,172 constants, none outside 32 bits; 381,750 addresses, none typed. |
| M3 | Tables the session builds for the Linux captures (`tablefacts -os linux`) | mem3: 24,224,689 bytes written, round trip 1/1; 375 scalars; 13,987 records (648 name only, 0 unreadable, 2 sharing an enumeration's name); 78,351 named + 1,314 embedded members, 84,143 after embedding; 3,237 bitfields (0 past storage, highest end 64); 5,025 arrays (1,313 of no elements); deepest 3 operators; 2,736 enumerations (widths 1:6, 4:2,715, 8:15), 23,444 constants (44 outside 32 bits); 210,415 addresses (439 typed). mem4: 24,566,357 bytes, 1/1; 367 scalars; 13,780 records (747 name only, 0 unreadable, 2 shared); 77,052 + 1,264, 82,626 after; 3,033 bitfields (0 past); 5,272 arrays (1,371 empty); 2,584 enumerations (1:6, 4:2,564, 8:14), 22,392 constants (45 outside 32 bits); 216,496 addresses (411 typed). |
| M4 | Windows sessions (`tablefacts -os windows`): kernel table and `_EPROCESS` | mem1 ntkrnlmp 0D960CE1… 2,112 bytes / 263 members (open 1.0 s); mem2 F57E740B… 2,624 / 237 (5.9 s); mem5 3DFC5F72… 1,968 / 207 (6.4 s); mem6 and mem7 953A8DE8… 2,112 / 260 (0.5 s, 0.3 s). |
| M5 | Load time, new against the old implementation, same files | 42 cache tables: 398 ms against 839 ms in total; the four ntkrnlmp tables 27–42 ms against 85–121 ms. Linux 24 MB files: decode 258/228 ms against 1,313/1,302 ms; build 187/260 ms against 471/394 ms. |
| M6 | Every lookup answer of every table (`tablefacts -dump`: SizeOf, LookupType, EnumValue, Struct, FieldSize, ResolveIntField, ReadStruct over zeroed memory, LookupSymbol, SymbolTypeRef, NamesAt), new against old | 42 cache tables: identical apart from the wording of one message (`… is N bytes wide, not a readable integer`). Linux: identical apart from `ResolveIntField` on an array of no elements: 1,077 members (mem3) and 1,151 (mem4), such as `char __data[]` of the `trace_event_raw_*` records, were given the element's width and are now refused (rule V9). |
| M7 | Platform of each table and members whose type is not a pointer and is sized by the platform (4.4 rule 4) (`tablefacts`, 2026-11-12) | 50 cache tables: all Windows; 114 such members, all of a declared scalar. mem3: Linux; 4,547 such members, all `long int` or `long unsigned int`, 0 of an undeclared scalar. mem4: Linux; 4,567, 0 undeclared. Both Linux tables declare `long int` and `long unsigned int` as 8 bytes and `wchar_t` as 2 bytes, though no member uses `wchar_t`. So the fallback of rule 4 is never reached on a capture. |

## 4. Algorithm

### 4.1 Declaration check

1. Pointer width 4 or 8 (F3). PDB GUID 32 hex digits (F3; upper case is required of a file, any case of a declaration, and the writer upper-cases it). A banner, when present, is not empty.
2. Names of scalars, records, enumerations, the constants of each enumeration and addresses are non-empty and distinct within their list (F3–F7). A scalar's kind is one of the five (F4).
3. In each record: an embedded member has no type; any other member has a non-empty name not used by another named member of the record, and a valid type (4.2). An address type is valid.
4. Before writing, every string (names, embeds, rendered types, banner, PDB file) is UTF-8 (F1, F9).

### 4.2 Type expressions

1. A `TypeRef` is one level. A level is at most one of pointer, array (`IsArray`, or a count above 0) and bitfield (`BitLength` > 0); `BitOffset` is 0 when there is no bitfield; a named level has no `Element`; at most 32 operator levels (F6). An operator level with no `Element` stands for its `Name`.
2. Every level built from a file carries the innermost name, so `*_LIST_ENTRY` is a pointer level named `_LIST_ENTRY` over the level `_LIST_ENTRY`.
3. Parsing reads operators while the next byte is `*`, `[` or `@`: `[` up to `]` a decimal count without leading zeros within 64 bits; `@` up to a space `O:L`, `O` 0–255, `L` 1–255 (the `TypeRef` widths). The rest is the name; a leading `\` is taken off and must stand before `*`, `[`, `@` or `\` (F6). Writing is the inverse, so a parsed expression writes back to the same text.

### 4.3 Building a table

1. Scalars are kept by name when declared (nil otherwise, F3). Enumerations are kept with their constants sorted by value then name (F7).
2. Records with members are placed. A record with no embedded member keeps its members as written. For the others the members each brings up are counted first, depth first with a memo, a record met again on the current path being a cycle; a record that embeds one the table does not hold, or a cycle, is unreadable with the reason (F5). If the sum over all records is more than twice the members written plus `MaxTableEntries`, the table is refused before any member is brought up (F5).
3. Members are then brought up in declaration order: an embedded member's members at its offset plus theirs, recursively; a name seen before replaces the earlier member in the earlier member's place (F5). An offset that passes 2^64 − 1 makes the record unreadable.
4. A record with no members is not placed: a tool cannot read it (F5).
5. Each address becomes a symbol. Its `Type` text is what a reader of its first element reads: an array's element, a bitfield's storage, and any pointer as `*` and the innermost name (every pointer has the pointer width). The full expression is kept for `SymbolTypeRef`.

`NewTable`, `AddStruct`, `AddEnum` and `AddSymbol` build a table in code: pointer width 0 means 8; a record's members are put in offset, then name, order, since code often gathers them from a map; a record with no members is still placed; constants are sorted as in 1; an empty name is ignored.

### 4.4 Widths

1. A pointer has the pointer width; an array its count times its element (an overflow past 64 bits is unknown); a bitfield its storage unit (F15–F19); a name: a placed record its width, an enumeration its enumeration width (3), a declared scalar its width; when the table declares no scalars, the name's C width (2, 4); else unknown (F3).
2. A C type name is recognised as: `pointer` or a trailing `*` (pointer width); `bool`, `_Bool`, `char8_t` 1; `wchar_t`, `__wchar_t`, `char16_t` 2; `char32_t`, `float` 4; `intN`/`uintN` and `intN_t`/`uintN_t` N/8 (F12; the bare names are what the project's ELF generator writes); `__intN`, optionally `signed`/`unsigned`, N/8; otherwise the multiset of `signed`, `unsigned`, `char`, `short`, `int`, `long`, `double` (F10) under the Microsoft sizes (F11): `char` 1, `short` 2, `int`, `long`, `signed`, `unsigned` 4, `long long` 8, `double` and `long double` 8. Any other word or combination is unknown. The widths of `long` (with or without `int`, `signed`, `unsigned`), `long double` and `wchar_t`/`__wchar_t` are the platform's, by rule 4. `BaseTypeWidth` answers the other names and gives 0 for these three; `ScalarWidth` answers all of them for a platform.
3. An enumeration's width is its declared width; with none, 4 (F13), or 8 when its constants fit neither the signed nor the unsigned 32-bit range (F14).
4. **Platform of a table.** A table built from a declaration with a Windows PDB and no Linux banner is a Windows table; one with a banner and no PDB is a Linux table; any other table, and every hand-built table until `SetPlatform` names one, is of unknown platform. For the names of rule 2 whose width the platform decides:
   - Windows (LLP64 for 8-byte pointers, F11, F22): `long` 4, `long double` 8, `wchar_t` 2.
   - Linux (F21): `long` 8 for 8-byte pointers (LP64) and 4 for 4-byte pointers (ILP32); `long double` 16; `wchar_t` unknown (0), since F21 does not size it.
   - Unknown platform: the width is not guessed. `ScalarWidth`, `FieldSize`, `SizeOf` and `ResolveIntField` fail with `ErrPlatformUnknown`; `ReadStruct` lists the member in `Unsized` (V8). A table that is not a `*Table` gives its platform through a `Platform() Platform` method; one without it is of unknown platform.

### 4.5 Reading

1. `ReadStruct` reads each member at its own width (4.4): an array of no elements whose element has a width gives no bytes; a member of unknown width is listed in `Unsized` (sorted) rather than read at a guess or left out; a read error or a short read fails the call.
2. A member is an integer when it is a pointer, a bitfield ending at or before bit 64, or a named type up to 8 bytes that is not a placed record, a float or a big-endian scalar (F4). The value is little-endian (F20); a bitfield is shifted right by its offset and masked to its length (F15–F17). Everything else is kept raw.
3. `ReadUint32`, `ReadUint64`, `ReadPointer` read 4, 8 or pointer-width little-endian bytes and fail on a short read.
4. `ResolveIntField` gives a member's offset, its width (`FieldSize` when the table sizes members, else 4.4 with `ScalarWidth` and the table's platform for names; `ErrPlatformUnknown` from either is returned) and its bit offset and length; a width of 0 or past 8 is refused. `Read` and `Decode` read exactly that width and cut the bits.
5. `ResolveCharArray` gives a member's offset and its array count, or the caller's fallback when the member is not an array; `Read` reads exactly that many bytes and stops at the first NUL, or takes them all (a full array has no NUL).

### 4.6 Lookups

`Struct`, `Field`, `OffsetOf`, `FieldSize`, `LookupType` (record first, F5), `SizeOf`, `EnumValue`, `LookupSymbol`, `SymbolTypeRef`, `SymbolNames` and `TableSymbols` (both sorted by name), `WindowsPDB`, `LinuxBanner`. `SizeOf` also takes a type expression (a symbol's `Type`). `SymbolsAt` returns the symbols at one address, sorted by name, from an index built on first use under a lock and rebuilt after `AddSymbol`; `NamesAt` gives their names, nil when there are none.

### 4.7 Writing a file

The declaration is checked (4.1), then written as FORMAT.md lays it out (F1): `vsym`, `pointer_width`, `windows_pdb` (GUID upper-cased, `file` only when set), `linux_banner`, `scalars` (whenever declared, `[]` when empty), then `records`, `enumerations`, `addresses` (each only when not empty), lists sorted by name with a stable sort, constants by value then name, one list entry per line indented by four spaces, record members one per line indented by six. A record's `width` and an enumeration's `width` are written when not 0; `signed` and `big_endian` only when true. Strings escape `"`, `\`, LF, TAB and CR by letter and other control characters as `\u00xx` (F8); everything else, including non-ASCII, is written as it is.

### 4.8 Reading a file

1. `ReadFile` reads at most `MaxTableFile` + 1 bytes and refuses a longer file (`ErrTableTooLarge`).
2. A strict scanner reads the object key by key into the declaration (F1, F2, F8, F9): each key at most once in its object; strings UTF-8 with the RFC 8259 escapes and paired surrogates; integers without fraction, exponent or leading zero, unsigned or signed 64-bit as F2 gives; booleans only `true` or `false`; no `null`.
3. Anything that is not an object with a `vsym` key is `ErrNotVsym`: a malformed text before the `vsym` key is read, or an object without one. Unknown top-level keys are stepped over (to a nesting depth of 256) so that a file in another layout is recognised as not a table; once `vsym` is present an unknown key is an error.
4. `vsym` must be 1 and `pointer_width` 4 or 8; the declaration is then checked (4.1) and built (4.3).

## 5. Validity rules

| # | Rule | Justification | On failure |
|---|---|---|---|
| V1 | Pointer width 4 or 8 | F3 | refused |
| V2 | GUID 32 hex digits (upper case in a file); age 32-bit; `file` and banner not empty | F3 | refused |
| V3 | Names non-empty and distinct per list; member names distinct per record; scalar kind known | F3–F7 | refused |
| V4 | One operator per level, at most 32, bit offset only with a bit length, bit fields 0–255 and 1–255 | F6 | refused |
| V5 | Strict JSON as 4.8 | F1, F2, F8, F9 | refused |
| V6 | Embedded member names a held record, no cycle, offsets within 64 bits | F5 | record unreadable (`UnusableTypeError`) |
| V7 | Embedding brings up at most twice the members written plus `MaxTableEntries` | F5 | table refused |
| V8 | A width is never guessed: unknown widths are 0 | F3 | member `Unsized`; `SizeOf` `UnknownTypeError` |
| V9 | An integer is at most 8 bytes; an array of no elements is not an integer | F2, 4.5 | `ResolveIntField` refuses |
| V10 | Floats and big-endian scalars are not decoded | F4 | kept raw |
| V11 | A bitfield reaching past bit 64 is not decoded | 4.5 (a value holds 64 bits); M2/M3: none measured | kept raw |
| V12 | Reads are exact: a short read is an error | 4.5 | error |
| V13 | A width the platform decides is taken only from a known platform | F11, F21, F22, 4.4 rule 4 | `ErrPlatformUnknown`; member `Unsized` in `ReadStruct` |

## 6. Failure modes

| Case | Result |
|---|---|
| Not a table | `symbols: not a vsym symbol table: …` (`ErrNotVsym`), wrapped `symbols: table <name>: …` by `Read`/`Decode`/`ReadFile`. |
| File too large | `symbols: symbol table file is past the size limit: <path> is more than <n> bytes` (`ErrTableTooLarge`). |
| Malformed table | `symbols: at byte <n>: <what>` (for example `key "vsym" written twice`, `number is not an integer`, `string is not UTF-8`, `unknown key "x" in a member`); `symbols: format <n> is not supported, only format 1`; `symbols: unknown key "<k>"`; `symbols: no "pointer_width" key`. |
| Bad declaration | `symbols: pointer width <n> is not 4 or 8`, `symbols: PDB GUID "<g>" is not 32 hex digits`, `symbols: Linux banner is empty`, `symbols: <list entry> <n> has no name`, `symbols: <kind> "<name>" is named twice`, `symbols: record "<r>": <member problem>`, `symbols: address "<a>": <type problem>`, `symbols: "<s>" is not UTF-8`. |
| Embedding too large | `symbols: anonymous members would bring up <n> members, more than twice the <w> written plus MaxTableEntries (<m>)`. |
| Unreadable record | `UnusableTypeError`: `symbols: type "<r>" is unreadable: <reason>`, the reason naming the missing record, the cycle path (`"a" holds itself through embedded members: a > b > a`) or the offset. From `Struct`, `Field`, `LookupType`, `SizeOf`. |
| Unknown names | `UnknownTypeError` `symbols: no type "<t>"`; `UnknownFieldError` `symbols: type "<t>" has no field "<f>"`; `symbols: no symbol "<s>"`; `symbols: symbol "<s>" has no type`. |
| Reads | The reader's error; `symbols: read of <n> bytes at 0x<a> gave <m>`; `symbols: <T>.<F> is <n> bytes wide, not a readable integer`; `symbols: member at 0x<a>: width <n> is not a readable integer`; `symbols: member at +0x<o>: <n> bytes end past the <m>-byte record`; `symbols: char array at 0x<a>: …`; `symbols: <T>.<F>: the table gives no array length and there is no fallback`. |
| Platform | `symbols: table platform not known: width of "<name>" depends on it` (`ErrPlatformUnknown`), wrapped `symbols: <T>.<F>: …` by `ResolveIntField`. |
| Options | `symbols: MaxTableFile <n> is negative` / `is past its ceiling <c>`; the same for `MaxTableEntries`. |

There is no strict mode at this layer: every failure is an error to the caller.

## 7. Result schema

The exported API is kept, except the unused exports removed (section 10, O1). Types: `Declaration{PointerWidth, WindowsPDB, LinuxBanner, Scalars, Records, Enumerations, Addresses}`, `Scalar{Name, Width, Kind, Signed, BigEndian}`, `ScalarKind` (`integer`, `float`, `char`, `bool`, `void`), `Record{Name, Width, Members}`, `Member{Name, Offset, Type, Embeds}`, `Address{Name, Address, Type}`, `PDBBuild{Database, GUID, Age}` (`String` is `<file>/<GUID>-<age>` or `<GUID>-<age>`), `TypeRef`, `Field`, `StructType`, `EnumType`, `EnumValue`, `Symbol{Name, Address, Type}`, `StructInstance{Type, Offset, Fields, RawFields, Unsized}`, `Type{Name, Kind, Size, Fields, Enum}`, `TypeKind`, `IntField`, `CharArrayField`, `ReadOptions`, `Platform` (`PlatformUnknown`, `PlatformWindows`, `PlatformLinux`); functions `Build`, `BuildWith`, `Decode`, `DecodeDeclaration`, `Encode`, `Read`, `ReadFile`, `ReadFileWith`, `NewTable`, `ResolveIntField`, `ResolveCharArray`, `NamesAt`, `BaseTypeWidth`, `ScalarWidth`; methods `(*Table).Platform`, `(*Table).SetPlatform`; interfaces `SymbolTable`, `DeterministicLookup`, `FieldSizer`, `SymbolLocator`; errors `UnknownTypeError`, `UnknownFieldError`, `UnusableTypeError`, `ErrNotVsym`, `ErrTableTooLarge`, `ErrPlatformUnknown`; constants `FormatVersion` (1), `MaxTableFile`, `MaxTypeOperators` (32).

Order: a built record's members in declaration order with embedded members in place; a hand-built record's by offset, then name; constants by value, then name; `Unsized`, `SymbolNames`, `TableSymbols` and `SymbolsAt` by name. Addresses are in the table's own space: image-relative for Windows, link-time for Linux (FORMAT.md).

`BuilderVersion` stays 10: the file format and the bytes written are unchanged (M1, M3).

## 8. Limits

| Limit | Use | Why |
|---|---|---|
| `MaxTableFile` (512 MiB, ceiling 4 GiB) | file read | Largest measured table 24.6 MB (M3); a file is read whole. |
| `MaxTableEntries` (4,194,304) | embedding margin | FORMAT.md; M3: embedding adds 4,478 and 4,310 members to the 79,665 and 78,316 written. |
| `MaxTypeOperators` (32) | expression depth | FORMAT.md; deepest measured 5 (M2). |
| Skip depth 256 | stepping over unknown top-level values | Bounds recursion on a file in another layout; the format nests 5 levels. |

## 9. Acceptance

1. Unit tests (`expr_test.go`, `width_test.go`, `table_test.go`, `embed_test.go`, `vsym_test.go`, `intread_test.go`, `handbuilt_test.go`, helpers in `s58_helpers_test.go`, `example_test.go`): expressions written back as read, every level named, each malformed expression and `TypeRef` refused; C widths for every specifier order and the refused combinations; the platform widths of `long`, `long double` and `wchar_t` for Windows and Linux at both pointer widths, `ErrPlatformUnknown` for each with no platform, and the platform a declaration gives (PDB, banner, both); `ResolveIntField` on a hand-built table before and after `SetPlatform` and through a wrapper that hides the platform; enumeration widths at the 32-bit edges; array overflow; bit cutting at 0, 63 and 64; lookups, record-over-enumeration, unknown names, sizes with and without declared scalars and of expressions; `ReadStruct` with bitfields, pointers, a function pointer, a record by value, float, big-endian, an enumeration-named record, arrays of no elements with and without an element width, unknown widths, short reads and reads past memory; wide bitfields kept raw; both pointer widths; symbols by name and address, untyped symbols, the symbol type text, concurrent `SymbolsAt`; every declaration refusal; embedding in place with replacement, name-only records embedded, each unreadable reason through all four lookups, the embedding bound and its margin; the writer's exact bytes (escapes, empty and absent lists, PDB, banner, sort orders, escaped names) and a read back to the same declaration; 37 malformed files each refused with its reason and not as `ErrNotVsym`; files in another layout, empty files and deep nesting as `ErrNotVsym`; the file size limit and option bounds; `IntField` through a sizing and a non-sizing table, `Decode` and `Read` bounds; `CharArrayField` with and without NUL and fallbacks; hand-built tables and the address index after `AddSymbol`. Statement coverage 96.1%.
2. Fuzz targets, 30 s each on 2026-11-12, no failure: `FuzzDecodeDeclaration` (a table that reads is written, reads back and writes the same bytes; built tables answer lookups without panic; 1.84 million executions), `FuzzTypeExpression` (an expression that parses passes the check and writes back unchanged; 2.47 million).
3. Ground truth on the captures: M1 and M3 (byte-equal round trip of all 42 cache tables and both Linux tables), M6 (every lookup answer unchanged on all Windows tables; the one Linux change is V9).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Removed exports with no caller in the repository: `Resolver`, `Generator`, `MissingSymbolTableError`, `UnsupportedArchitectureError`. Their behaviour had no source and nothing used them. Owner decision: keep them removed (default) or restore. | Owner decision |
| O2 | `ResolveIntField` now refuses an array of no elements (V9, M6: 1,077 and 1,151 Linux members), where the element's width was used before. No tool in the repository resolves such a member; a caller that wants the first element should resolve the element type. | Owner decision |
| O3 | `BaseTypeWidth` no longer recognises `uchar`, `ushort`, `ulong`, `ulonglong`, `byte`, `wchar`, nor names that merely contain `int8`/`char`/`short`/`int16`/`int32`/`int64`/`long long`; it recognises C specifier sets in any order (so `long unsigned int` is 4 under the Windows model, before 0). It matters only for tables that declare no scalars (hand-built tables and the ELF generator); every measured table declares scalars (M2, M3). | Owner decision |
| O4 | `SizeOf` of a C type name the table does not declare is now unknown when the table declares scalars (before, a fixed list such as `uint32` or `long` answered 4 regardless). It answers type expressions (`*T`, `[N]T`). | Owner decision |
| O5 | An enumeration with no declared width is 4 bytes (8 past 32 bits) by F13/F14; before, the smallest of 1, 2, 4, 8 bytes holding its constants. Every measured enumeration declares its width (M2, M3). | Owner decision |
| O6 | `ErrNotVsym` and `ErrTableTooLarge` now carry the `symbols:` prefix, and several messages are reworded (section 6); `UnusableTypeError` reads `is unreadable` (FORMAT.md's word). `UnknownTypeError` and `UnknownFieldError` keep their text. | Owner decision (Q2) |
| O7 | Symbol `Type` text keeps the earlier form (4.3 step 5) because tools and tests size symbols by it; the full expression is available from `SymbolTypeRef`. | Owner decision |
| O8 | The bitfield bit order rests on F15–F17 and on the converters (S32, S59) writing positions from the least significant bit; no capture was checked bit by bit at this layer. | A capture with a known bitfield value (for example `_HANDLE_TABLE_ENTRY` against a live handle) |
| O9 | `BaseTypeWidth` keeps its signature but no longer answers `long`, `long double` or `wchar_t` (4.4 rule 4); before, it gave the Windows widths for every table. A Linux table that declares no scalars now sizes `long` as 8. Measured tables declare every platform-sized type they use (M7), so no tool output changes. Hand-built tables in the repository still name no platform; only those sizing a platform-dependent member by name are affected, and `go test ./...` showed no failure from it on 2026-11-12. A 4-byte Linux table is taken as the psABI's ILP32; the i386 ABI was not consulted. | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep removed |
| O2 | Refuse |
| O3 | Accept stricter set |
| O4 | Unknown |
| O5 | 4 bytes, 8 past 32 bits |
| O6 | Accept |
| O7 | Keep earlier form |
| O8 | Defer to v0.2.0 |
| O9 | Stop answering |

## 11. Provenance

Written from `symbols/FORMAT.md` (the project's own format), RFC 8259, RFC 3629, C11, Microsoft Learn (Data Type Ranges, C Enumeration Declarations, C Bit Fields), the System V AMD64 psABI (Figure 3.1 at commit e1ce0983), DWARF 5, the kernel's `Documentation/bpf/btf.rst` at v6.1 and v6.17, S32's PDB facts and the project's measurements. The old implementation files were read for exported names, the shapes of exported types, and callers; the old package was built only to produce the comparison of M5 and M6. Every rule rests on the sources and measurements above.
