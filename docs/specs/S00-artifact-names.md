# S00: Artefact names

Version 1, 2026-11-11.

## 1. Purpose

Several tools write evidence to the examiner's disk: memory regions, PE images, process minidumps, cached files, registry hives, kernel modules, page-cache files and archives, and framebuffer pictures. Each file needs a name that:

- says what it holds and where in the image it came from;
- sorts so that related artefacts sit together;
- cannot leave the output directory, open a device, or collide silently;
- is valid on Windows, Linux and macOS filesystems, because an examiner may copy a result set between hosts.

This specification defines one naming scheme for every writer of recovered evidence. One writer is excepted: the timeline body file `timeline.body` (S60; `BodyfileName` in `tools/any/timeline/tool.go`) is a text export, not recovered evidence, so it does not use the scheme. It is still created through `CreateUnique` (section 6), so an existing file is never replaced. Owner decision 2026-11-12.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kind | fixed word | What the bytes are (section 4.1). |
| Scope | process ID, kernel, or physical | Which address space the addresses belong to. |
| Addresses | 0 to 2 unsigned integers | The object's location: a base, a range, or a base and the record that described it. None for an artefact that gathers many objects (`pagecache`). |
| Width | pointer size in bytes, 4 or 8 | Decides how many hex digits an address takes. |
| Labels | 0 to 2 strings | Human context such as a file's base name or a process image name. They may come from the image, which makes them attacker-controlled. |
| Extension | fixed word | Section 4.1. |

## 3. Constraints from the target filesystems

| # | Constraint | Source |
|---|---|---|
| C1 | Portable names use only `A-Z a-z 0-9 . _ -`. | IEEE Std 1003.1-2017, Base Definitions 3.282, "Portable Filename Character Set". |
| C2 | `/` separates path components on POSIX. `\`, `/` and `:` are separators or reserved on Windows. `< > " \| ? *` and code points 0 to 31 are invalid on Windows. | IEEE Std 1003.1-2017 3.271; Microsoft Learn, "Naming Files, Paths, and Namespaces", section "Naming Conventions". |
| C3 | CON, PRN, AUX, NUL, COM0 to COM9, LPT0 to LPT9, and COM or LPT followed by a superscript 1, 2 or 3, name devices. This holds even when an extension follows. | Microsoft Learn, "Naming Files, Paths, and Namespaces". |
| C4 | CONIN$ and CONOUT$ open the console input and output buffers. | Microsoft Learn, "CreateFileW", section "Consoles". |
| C5 | A name must not end in a space or a period on Windows. | Microsoft Learn, "Naming Files, Paths, and Namespaces". |
| C6 | A component is at most 255 bytes on ext4 and other Linux filesystems (NAME_MAX), and at most 255 UTF-16 units on NTFS. With C1 these are the same limit. | Linux `include/uapi/linux/limits.h` (`NAME_MAX 255`); Microsoft Learn, "Maximum Path Length Limitation". |
| C7 | NTFS and APFS compare names without regard to case by default, so names that differ only in case collide. | Microsoft Learn, "Case sensitivity"; Apple, "File System Programming Guide". |
| C8 | A name that starts with `-` reads as an option to most command-line tools. A name that starts with `.` is hidden on POSIX. | IEEE Std 1003.1-2017, XBD 12.2 "Utility Syntax Guidelines", guideline 5; `ls` description. |

## 4. Algorithm

1. Build the components in order: `kind`, `scope`, each address, each label, `extension`. Join them with `.`.
2. **Scope.** `pid<N>`, with N in decimal, for a process address space. `kernel` for kernel space. `phys` when the examiner gave the object by physical address.
3. **Addresses.** Write `0x` followed by lowercase hex, zero-padded to `2 × Width` digits. With Width 4, mask the address to 32 bits first. Fixed width makes a directory listing sort by address within one kind and scope. Lowercase keeps the digits apart from C7 collisions.
4. **Labels.**
   - Take the part after the last `\` or `/`: an in-image path is written with `\`, and a caller may pass `/`.
   - Map every character outside C1 and `~` to `_`. This covers C2, and removes any separator before the label is joined.
   - Cut the label to 64 bytes so that the whole name stays far inside C6. A cut label ends in `~`, so the cut is visible. `~` is the only character outside C1 that the scheme writes. It is valid on every C2 filesystem.
   - Drop an empty label.
5. **Result.** The name starts with a lowercase kind word, so it never starts with `.` or `-` (C8) and its first component is never a C3 or C4 device. It ends with the extension, so it never ends in a space or period (C5).

### 4.1 Kinds and extensions

| Kind | Holds | Addresses | Labels | Extension |
|---|---|---|---|---|
| `region` | Raw bytes of a virtual range | start, end (inclusive) | none | `bin` |
| `region` | A whole memory layer: the physical layer (scope `phys`), or the kernel address space (scope `kernel`) | none | none | `bin` for the physical layer, `elf` (an ELF core file) for the kernel space |
| `module` | A PE module image rebuilt from memory | base, loader record | file base name | `pe` |
| `module` | A Linux kernel module rebuilt as ELF | base | module name | `elf` |
| `image` | The main PE image of a process | base, process object | none | `pe` |
| `image` | A mapped ELF file rebuilt from a process | start | the mapped file's path when read, else the process command name | `elf` |
| `process` | A process as a user-mode minidump | process object | image name | `dmp` (the Microsoft convention for the MINIDUMP format) |
| `file` | Cached file data | file object, the backing section or cache-map object | view (`data`, `image` or `cache`, after the SECTION_OBJECT_POINTERS members DataSectionObject, ImageSectionObject and SharedCacheMap in WDK `wdm.h`), file base name | `bin` |
| `hive` | A registry hive | the hive object | hive name | `regf` (the hive file signature) |
| `inode` | One file's pages from the Linux page cache | inode | none | `bin` |
| `pagecache` | The cached files of every Linux superblock as one archive (S12 4.8) | none | none | `tar.gz` (a POSIX tar stream in one gzip member; the two words are joined with `.` like any component) |
| `framebuffer` | The screen memory of a Linux framebuffer (S62) | `fb_info` | `fix.id` | `png` for a packed true-colour picture, else `bin` |

The timeline body file has no kind: it is the one writer outside the scheme (section 1).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| The name contains only C1 characters and `~`. | C1, C2 | Impossible by construction. A test checks it. |
| The name is at most 255 bytes. | C6 | Impossible by construction: the kind, scope and extension words are fixed and short, at most 2 addresses of at most 18 characters, at most 2 labels of at most 65 bytes. |
| `CreateNew` sanitises a caller's own string with the label rule, prefixes `_` when the name starts with `.` or `-` or names a device (C3, C4, C8), and replaces trailing spaces and periods with `_` (C5). | The filesystem boundary is the last place to stop an unsafe name. | Empty after sanitising, or over 255 bytes: an error. |
| A file of the same name is never replaced. | Replacing an earlier artefact destroys evidence. | `ErrArtifactExists`. |

## 6. Failure modes

- An empty name passed to `CreateNew`, `CreateUnique` or `RemoveArtifact` returns an error.
- An existing file returns `ErrArtifactExists`. `CreateUnique` then tries `<stem>-<n><ext>` up to the caller's attempt limit.

## 7. Result schema

A `string` holding the file name only, with no directory.

## 8. Limits

- 64 bytes per label (step 4) keeps the worst case at about 200 bytes, under C6.
- `CreateUnique` attempts: the caller's `Limits.NameAttempts`.

## 9. Acceptance

- A table test with one example per kind, checking the literal output.
- Properties over random input: only C1 characters and `~`; at most 255 bytes; no separator; never a device stem; deterministic.
- A fuzz target over labels and `CreateNew` names.
- A test that a hostile label (`..\..\x`, `\??\C:\NUL`, NUL bytes, non-ASCII) cannot leave the output directory.

## 10. Open points

None.

## 11. Provenance

Sources: as cited in section 3, accessed 2026-11-11. Author: the project.
