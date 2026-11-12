<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/wordmark-dark.svg">
    <img src="../assets/wordmark-light.svg" alt="libvapour: extract signal from volatile memory" width="380">
  </picture>
</p>

# libvapour Examples

Runnable programs built on libvapour's session API. They show how to use the
library and are not test fixtures. Each needs a **real memory image** you
supply; none is in the repository.

There are two kinds:

- **Workflow programs** (`processes`, `memory`, `registry`, `network`,
  `timeline`, `triage`) each answer one question about an image. They open a
  session with `libvapour.OpenMemory` and call each tool's typed `Run` on the
  session's context, so the code shows the calls and the result types.
- **`processlist` and `showcase`** run tools by name through the session.

A tool that runs in an example is not thereby correct. Some registered tools
are heuristics or placeholders (see "Tool status" below), and the repository's
README describes how mature the project is. The workflow programs use tools
tested on real captures, except `any.timeline.list`, which has no real-image
test. `windows.process.dump` writes minidumps that pass a structural audit and
load in a debugger.

## Prerequisites

- **A memory image.** Raw images, Windows full crash dumps, LiME and ELF core
  dumps are detected by content. Bitmap and kernel crash dumps, hibernation
  files and VMware snapshots are not supported yet.
- **Windows images:** the first run downloads kernel symbols from the Microsoft
  symbol server and caches them, so no `-symbols` flag is needed.
- **Linux images:** the only flag needed is `-os linux`.
  - The session takes the kernel's page table and KASLR shift from VMCOREINFO,
    and builds the symbol table from the image.
  - `-symbols <file>` names an uncompressed `.vsym` symbol table to use
    instead. It must match the running kernel.

Images and symbol caches are gitignored. Never commit real evidence, or any
file a program writes from it.

## Flags

Put flags before the image path: parsing stops at the first non-flag argument.

Every workflow program takes these:

| Flag | Meaning |
| --- | --- |
| `-os windows` or `-os linux` | The image's operating system. The default is `windows`. |
| `-symbols <file>` | The kernel's .vsym symbol table, used instead of the one found automatically. |
| `-cr3 <address>` | The kernel's page-table root. The session finds it (on Linux from VMCOREINFO), and a different value fails the open. |
| `-offline` | Windows only: download no symbols; use the symbol cache or `-symbols`. |
| `-strict` | Stop with an error where a tool that checks strict mode would report a diagnostic. |
| `-verbose` | Print each diagnostic after the tables. Without it, a run says how many it held back. |

A diagnostic tells you a result is incomplete: a list walk that stopped early,
or a kernel that could not be confirmed. The programs always collect them.

A bad command line (a bad flag, no image or two, a flag or program the
image's system does not take) prints the error and `usage: <synopsis>` on
standard error, followed by the flags, and exits with status 2. A failed
analysis prints its error and exits with status 1.

Each table comes under a heading line that starts with `==`. A heading names
the tool the rows come from, or counts the rows.

## Workflow programs

### `processes`

The process tree with each process's command line, and the kernel's modules.
With `-pid`, also what that process has loaded: DLLs and threads on Windows,
libraries on Linux.

```bash
go run ./examples/processes memory.raw
go run ./examples/processes -pid 4242 memory.raw
go run ./examples/processes -os linux -pid 1 memory.lime
```

Tools: `any.process.tree`, `any.process.read_arguments`, `windows.module.list`
or `linux.module.list`, then `windows.library.list` and `windows.thread.list`, or
`linux.library.list`.

- The tree's columns are PID, PPID, Name and Command line. Each level of the
  tree indents the name by `. `.
- Kernel modules print Base, Size and Name.
- DLLs print Base, Size, Loaded and Path. Threads print TID, State, Created,
  Start and Start file. Linux libraries print Base, Route and Path.

Command lines are matched to processes by kernel address, not PID, because an
image can hold two processes with the same PID.

### `memory`

One process's memory ranges: VADs on Windows, VMAs on Linux. `-pid` names the
process and is required. On Windows, `-out <dir>` also writes the process's
minidump, which a debugger opens, and one file per range.

```bash
go run ./examples/memory -pid 4242 memory.raw
go run ./examples/memory -pid 4242 -out dumps memory.raw
go run ./examples/memory -os linux -pid 1 memory.lime
```

Tools: `any.memory.list`, `windows.process.dump`, `windows.memory.dump`.

- The heading counts the ranges. The columns are Start, End, Protection, Type
  and File.
- File is `N/A` for a range that maps no file. It is `<unreadable>` only for a
  Linux range whose file name does not read.
- With `-out`, the minidump table gives the file name, its size, the modules,
  threads and regions written, the bytes taken from the image, and the bytes
  missing from the image and written as zeroes (Zero-filled).
- The range-file table gives each range's file, size and the bytes taken from
  the image. A range over the extraction limit (1 GiB) is not written, and its
  row says why.
- On Linux, `-out` is refused: there is no Linux minidump writer.

### `registry`

A registry key's subkeys and values, from each hive `-hive` selects. The
default hive is `SYSTEM`, and the default key is the computer's name.

```bash
go run ./examples/registry memory.raw
go run ./examples/registry -hive SOFTWARE -key "Microsoft\Windows NT\CurrentVersion" memory.raw
go run ./examples/registry -key ControlSet001\Services\Tcpip -recurse memory.raw
```

Tool: `windows.registry.read_key`. Windows only: with `-os linux` the program
says so and exits with status 2.

- `-hive SYSTEM` selects the hives whose path ends in `SYSTEM`. If none does,
  it selects the hives whose path contains the word. An empty `-hive` reads
  every hive.
- Each hive prints under its own heading: the hive's path, then
  `hive at 0x…`.
- Subkey and value names are indented by `. ` per level below the key.
- A key that is not in a hive, or whose path does not read, gets one line
  saying so under that hive's heading.

### `network`

Network endpoints.

```bash
go run ./examples/network memory.raw
go run ./examples/network -os linux -all memory.lime
```

On Windows it prints two lists, each under a heading and a count:

- `windows.network.list`: the endpoints in tcpip.sys's own tables.
- `windows.network.scan`: endpoint objects a pool-tag scan finds in memory,
  including ones no longer in those tables.

The columns are Protocol, Family, Local, Remote, State, PID, Process and
Created.

A list that fails prints `not listed: <reason>` under its heading, and the
other list still prints. `windows.network.list` refuses Windows Server 2016
(build 14393), because the measured layout for that build has no endpoint
tables. The program then prints the `windows.network.scan` list and exits with
the refusal.

On Linux it prints `linux.socket.list`'s sockets: IPv4 and IPv6 only, or every
family with `-all`. The columns are PID, Process, FD, Family, Type, Protocol,
Local, Remote and State.

### `timeline`

Every timed entry the image's tools give, in time order. With `-out <dir>`,
also a body file.

```bash
go run ./examples/timeline memory.raw
go run ./examples/timeline -tools any.process.list,windows.thread.list memory.raw
go run ./examples/timeline -out timeline memory.raw
```

Tool: `any.timeline.list`. `-tools` keeps the sources whose tool name contains
one of the words; without it every source runs.

The heading counts the entries. The columns are Time, Event, Tool, Field and
Subject. `-out` writes `timeline.body`, or the same name with a number added
when that name is taken.

### `triage`

Leads for an analyst to follow up, not verdicts.

```bash
go run ./examples/triage memory.raw
go run ./examples/triage -all memory.raw
go run ./examples/triage -os linux memory.lime
```

On Windows it runs three checks:

- `any.memory.find_code`: executable memory that may hold injected code. The
  heading is followed by a count of the regions. Each row gives the process,
  the range, its protection, the rule that matched (Rule), whether the region
  starts with an image header (Header), and its first bytes.
- `windows.process.compare`: processes missing from the active process list.
  Each row says which views see the process and gives its exit time (`-`
  when it has none). An exited process is expected to be off that list, and
  is not flagged.
- `windows.library.compare`: mapped images on only one of the loader's
  load-order and memory-order lists. Each row also says whether the image is
  on the initialization-order list. Images on neither list are counted, not
  shown: resource files mapped as images (`.mui` files, fonts) are on
  neither, and a clean server has dozens. A module removed from every list
  looks the same. Images in processes whose loader lists gave no record are
  counted too, and are not compared.

`-all` prints every row of the last two checks. Each of these two ends with
`N of M … shown`. A check that fails prints `not checked: <reason>` under its
heading, and the others still print.

On Linux the program runs `any.memory.find_code` only. Its rows give Rule and
the region's file (File) in place of Header.

## `processlist`

The smallest single-tool example: list processes and print a table of PID,
PPID, Name, Object (the process's kernel address) and Created.

```bash
go run ./examples/processlist memory.raw
go run ./examples/processlist -os linux memory.lime
```

Useful flags: `-offline`, `-strict`, `-verbose`, `-process-list-sanity`,
`-process-list-active-only`, `-process-list-cross-check-csv <file>`.

## `showcase`

Runs every registered tool of the image's system (and every `any` tool), and
writes a full text report and a summary.

```bash
go run ./examples/showcase memory.raw
go run ./examples/showcase -pid 4 memory.raw
go run ./examples/showcase -tools any.process.list,windows.network.scan,windows.handle.list memory.raw
```

`-tools` takes registered tool names and runs exactly those.

By default three tools are skipped, because each would be most of the report.
The report's header names each one and the reason:

- `any.memory.list_pages`: across every process it gives millions of page
  runs. `-pid`, `-opt pid=` or `-tools` runs it.
- `any.timeline.list`: it repeats the timed rows of the other tools. `-tools`
  runs it.
- `linux.kernel.list_symbols`: it lists every kernel symbol. `-tools` runs
  it.

`-max-rows <n>` cuts each table on stdout to `n` rows. The report file always
holds every row.

### Credentials

Credentials are redacted. These print as `[redacted]`, sizes included, on
stdout and in the report file, even when `-tools` names their tools:

- windows.credential.read_local's LM and NT hashes;
- windows.credential.read_cached's verifiers;
- windows.credential.read_lsa_secrets' secrets, current and old values;
- windows.credential.find_truecrypt's passphrases and their lengths.

The rows (account, RID, domain, secret name) still print. Each section with
hidden fields names them on a `hidden:` line.

`-reveal-secrets` prints the credentials. For
windows.credential.read_lsa_secrets that is each secret's size and its first
32 bytes, in hex. **If you use it, keep the terminal log and the report file to
yourself.**

## Files the programs write

`memory -out` and `timeline -out` write into the directory you name. No
program chooses a directory on its own.

- The directory is created if missing. The directory and each file are
  readable by you alone, on Windows and Unix alike.
- An existing file is never overwritten.

**A minidump or a memory range holds the process's memory as it was, and a
process such as lsass.exe holds credentials. Guard those files as you guard the
image.**

## How strings print

Every program prints recovered strings as printable ASCII, never trimmed or
merged, so two different names never print the same. A name planted in an
image cannot send a control sequence to your terminal.

- A control character, an invalid byte, or a non-ASCII character prints as a
  Go-style escape (`\t`, `\x1b`, `\u6587`). So does a leading or trailing
  space.
- A backslash prints as itself, unless what follows would read as an escape;
  then it is doubled. `C:\\temp` is the path `C:\temp`, while `C:\temp` is
  `C:`, a tab and `emp`.
- A value a tool could not read prints as `<unreadable>`. A value read only in
  part prints as that part followed by `<rest unreadable>`.
- `<empty>` is a command line that read empty. `<not listed>` is a process in
  the tree with no `any.process.read_arguments` row.
- In a value that ends in one of these markers, the marker's `<` prints as
  `\x3c`.
- `N/A` is a column that does not apply, such as the file of a range that maps
  none. `-` is a time that was not given.

## Tool status

Three registered tools do less than their names suggest:

| Registered name | Note |
| --- | --- |
| `windows.registry.list_hives` | lists hives only; `windows.registry.read_key` reads keys and values |
| `any.image.find_literal` | literal byte-string search, not a rule engine |
| `windows.service.find_candidates` | inferred from command lines, not the SCM database |

Heuristics and placeholders: `windows.module.list_drivers` (a filter over the
module list), `windows.service.find_candidates` and `any.image.find_literal`.
Their registered descriptions say so.

## Adding examples

Add an example together with the capability it shows, not before it. Do not
add an example for a tool known to be broken.

The programs share `examples/internal/cli`: the flags above and the string
rendering. It is not part of libvapour's API.
