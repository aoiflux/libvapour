# libvapour symbol tables, format 1

A symbol table holds the layout of a program's types and the addresses of its
symbols. libvapour writes every table it makes in this format and reads it
back: the Windows PDB tables it caches, a table built from a Linux image, and
any table a caller saves with `symbols.Encode`. Files in this format use the
extension `.vsym`.

## Encoding

- The file is one JSON object, in UTF-8.
- A writer emits keys in the order listed here, and sorts each list as stated.
  It indents by two spaces, puts each entry of a top-level list and each
  record member on its own line, keeps an enumeration's constants on the
  enumeration's line, ends lines with LF and ends the file with a newline. One table always gives the same bytes, so
  two tables can be compared with a diff.
- A reader refuses:
  - an unknown key, a key written twice, or a missing required key;
  - a format other than 1;
  - a number that is not an exact integer in range;
  - a value of the wrong JSON type;
  - anything after the object.
- A reader accepts the entries of a list in any order.

Widths, offsets and counts are JSON integers, read exactly as unsigned 64-bit
values. Enumeration values are JSON integers read exactly as signed 64-bit
values. Addresses are strings of lower-case hex digits after `0x`, with no
leading zeros, because many JSON readers keep only 53 bits of a number.

## Top level

| Key             | Required | Value                                                                                                                                  |
| --------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `vsym`          | yes      | `1`, the format version.                                                                                                               |
| `pointer_width` | yes      | `4` or `8`: the bytes in a pointer.                                                                                                    |
| `windows_pdb`   | no       | The Windows PDB the table describes (below).                                                                                           |
| `linux_banner`  | no       | The Linux kernel banner the table describes, exactly, as a JSON string. It is not empty.                                               |
| `scalars`       | no       | The scalar types (below). When the key is absent, the table declares none, and a type's width is known from its name alone.            |
| `records`       | no       | The structures and unions (below).                                                                                                     |
| `enumerations`  | no       | The enumerations (below).                                                                                                              |
| `addresses`     | no       | The symbols and their addresses (below).                                                                                               |

`windows_pdb` and `linux_banner` name the build the table describes. A
session checks them against the image before using the table, because a table
for another build names the same types with the wrong layout.

### `windows_pdb`

| Key    | Required | Value                                                     |
| ------ | -------- | --------------------------------------------------------- |
| `guid` | yes      | The PDB's GUID: 32 hex digits, upper case.                |
| `age`  | yes      | The PDB's age, an unsigned 32-bit integer.                |
| `file` | no       | The PDB's file name, such as `ntkrnlmp.pdb`. Not empty.   |

## Scalars

`{"name": "unsigned long", "width": 4, "kind": "integer"}`

| Key          | Required | Value                                                                  |
| ------------ | -------- | ---------------------------------------------------------------------- |
| `name`       | yes      | The type's name. Not empty, and not shared with another scalar.        |
| `width`      | yes      | Its size in bytes. `0` for `void`.                                     |
| `kind`       | yes      | One of `integer`, `float`, `char`, `bool`, `void`.                     |
| `signed`     | no       | `true` for a signed type. Written only when true.                      |
| `big_endian` | no       | `true` for a type stored most significant byte first. Written only when true. |

A float, or a scalar stored big-endian, is never decoded as a little-endian
integer. Scalars are sorted by name.

## Records

A record is a structure or a union. A union is a record whose members share
offset 0.

`{"name": "_LIST_ENTRY", "width": 16, "members": [{"name": "Flink", "offset": 0, "type": "*_LIST_ENTRY"}, {"name": "Blink", "offset": 8, "type": "*_LIST_ENTRY"}]}`

| Key       | Required | Value                                                                     |
| --------- | -------- | ------------------------------------------------------------------------- |
| `name`    | yes      | The record's name. Not empty, and not shared with another record.         |
| `width`   | no       | Its size in bytes. Absent when the source does not say.                   |
| `members` | no       | Its members, in the order the source declares them.                       |

A member is one of these:

- **A named member**: `{"name": "Flink", "offset": 0, "type": "*_LIST_ENTRY"}`.
  Its name is not empty, and no other named member of the record has it. Its
  offset is in bytes from the start of the record. Its type is a type
  expression (below).
- **An embedded member**: `{"name": "u1", "offset": 16, "embeds": "<record>"}`.
  This is a member with no name of its own in the source, such as an anonymous
  union. The members of the record it embeds become members of this one, at
  their own offsets plus this one's, to any depth. Its `name` is optional and
  is used only in messages.

When two members brought up this way share a name, the later one replaces the
earlier. A record whose embedded members cannot be brought up stays in the
table as unreadable, with the reason: a member embeds a record the table does
not hold, or a record that embeds itself. A table whose embedded members would bring up more than twice the
members it holds, plus Limits.MaxTableEntries (4,194,304 by default), is
refused when it is loaded.

A record with no members is a name only. A tool cannot read it; another
record can embed it and brings up nothing from it.

Records are sorted by name. A record and an enumeration may share a name: the
record is the type a lookup by that name returns.

## Type expressions

A member's or an address's type is a string:

| Expression | Meaning                                                                                       |
| ---------- | --------------------------------------------------------------------------------------------- |
| `name`     | A scalar, record or enumeration, by name. The empty string is a type the table does not name, such as a function. |
| `*T`       | A pointer to `T`.                                                                             |
| `[N]T`     | An array of `N` elements of `T`. `[0]T` is an array of no elements, such as a structure's trailing variable-length array. |
| `@O:L T`   | A bitfield: `L` bits starting at bit `O`, counted from the least significant bit, of a `T` storage unit. One space separates it from `T`. |

A name that starts with `*`, `[`, `@` or `\` is written with a `\` in front of
it. An expression holds at most 32 operators.

Examples: `*_LIST_ENTRY`, `[16]unsigned char`, `*[4]*void`,
`@0:3 unsigned long`, `*` (a pointer to a function).

## Enumerations

`{"name": "_POOL_TYPE", "width": 4, "constants": [{"name": "NonPagedPool", "value": 0}, {"name": "PagedPool", "value": 1}]}`

| Key         | Required | Value                                                                     |
| ----------- | -------- | ------------------------------------------------------------------------- |
| `name`      | yes      | The enumeration's name. Not empty, and not shared with another one.       |
| `width`     | no       | Its storage size in bytes. Absent when the source does not say.           |
| `constants` | no       | Its constants: a `name`, not empty and not shared within the enumeration, and a `value`. |

Enumerations are sorted by name, and their constants by value, then name.

## Addresses

`{"name": "PsActiveProcessHead", "address": "0x5a1b30", "type": "_LIST_ENTRY"}`

| Key       | Required | Value                                                                    |
| --------- | -------- | ------------------------------------------------------------------------ |
| `name`    | yes      | The symbol's name. Not empty, and not shared with another address.      |
| `address` | yes      | Its address. In a Windows table it is relative to the image's base; in a Linux table it is the address the kernel was linked at. |
| `type`    | no       | Its type, as a type expression.                                          |

Addresses are sorted by name.

## Where libvapour keeps tables

Windows PDB tables are cached as
`{UserCacheDir}/libvapour/symbols/windows/<builder>/<pdb>-<GUID>-<age>.vsym`.
`<builder>` is the version of the PDB reader that wrote the table. A table
from another version is never read, and never deleted: removing old
directories is up to the user. `.json` files directly under `windows/` are not
read.

A Linux table is built from the image each time a session opens, and is not
cached.

## Other symbol files

`symbols.ReadFile` and `symbols.Read` read this format only, and refuse any
other file with `symbols.ErrNotVsym`. libvapour converts no other symbol-file
layout: a Linux table comes from the image's own BTF and kallsyms
(`symbols/generator`).
