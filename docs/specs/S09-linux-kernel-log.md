# S09: Linux kernel log reader across ring formats

Version 1, 2026-11-12.

## 1. Purpose

The kernel log holds what the kernel said about itself since boot: the version banner, hardware it found, modules that loaded, warnings, oopses, and lines that user space injected through `/dev/kmsg`. An examiner reads it from a memory capture to see what happened before the capture, including messages that a cleared or rotated on-disk log no longer holds. This specification reads the log from the kernel's own buffer, in each of the three formats the kernel has used, and reports one row per printed line with the fields the kernel keeps for it: sequence number, timestamp, facility, level, caller, the fragment flag and the device context.

The tool is `linux.log.read_kernel`. It takes no tool options.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxkern.Kernel` | Memory in the 48-bit (or 32-bit) address form, the session symbol table and the pointer width. |
| Physical memory | memory reader, optional | Searched for VMCOREINFO (S05) only when the symbol table lacks a type the reader needs. |
| Limits | effective `limits.Limits` | Section 8. |
| Strict mode | session option | Section 6. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17, the five project tags. The format boundaries were checked on the tags either side of each change: v3.4 and v3.5, v3.10 and v3.11, v5.0 and v5.1, v5.9 and v5.10, and v5.11. `printk.c` is `kernel/printk.c` up to v3.10 and `kernel/printk/printk.c` from v3.11.

### Formats and their symbols

| # | Fact | Source |
|---|---|---|
| B1 | Up to v3.4 the log is a ring of characters: `char *log_buf`, `int log_buf_len`, and `unsigned log_end`, the count of characters ever written. A character goes to `log_buf[log_end & (log_buf_len - 1)]`, then `log_end` grows by one. `log_buf_len` is a power of two (`roundup_pow_of_two` on the boot parameter; the default is `1 << CONFIG_LOG_BUF_SHIFT`). There are no records and no sequence numbers. | `kernel/printk.c` v3.4 (`LOG_BUF`, `emit_log_char`, `log_buf_len_setup`). |
| B2 | From v3.5 to v5.9 the log is a buffer of variable-length records: `char *log_buf`, `u32 log_buf_len`, `u32 log_first_idx` and `u32 log_next_idx` (byte offsets of the oldest record and of the next one to write), and `u64 log_first_seq` and `u64 log_next_seq`. The record header is `struct log` up to v3.10 and `struct printk_log` from v3.11, with the same members. `log_end` no longer exists. | `kernel/printk.c` v3.5, v3.10; `kernel/printk/printk.c` v3.11, v4.19, v5.0, v5.9. |
| B3 | From v5.10 the log is the lockless ring buffer, reached through `struct printk_ringbuffer *prb`, which points at `printk_rb_static` or, after `setup_log_buf` moves the log to a larger buffer, `printk_rb_dynamic`. `log_first_idx` no longer exists. | `kernel/printk/printk.c` v5.10, v6.1, v6.4, v6.14, v6.17. |

### The lockless ring (v5.10 on)

| # | Fact | Source |
|---|---|---|
| R1 | `struct printk_ringbuffer { struct prb_desc_ring desc_ring; struct prb_data_ring text_data_ring; atomic_long_t fail; }`. `struct prb_desc_ring { unsigned int count_bits; struct prb_desc *descs; struct printk_info *infos; atomic_long_t head_id; atomic_long_t tail_id; ... }`. `struct prb_data_ring { unsigned int size_bits; char *data; atomic_long_t head_lpos; atomic_long_t tail_lpos; }`. | `kernel/printk/printk_ringbuffer.h`, v5.10 to v6.17 (the last `prb_desc_ring` member is `last_finalized_id` at v6.1 and v6.4 and `last_finalized_seq` at v6.14 and v6.17; it is not read). |
| R2 | `struct prb_desc { atomic_long_t state_var; struct prb_data_blk_lpos text_blk_lpos; }` and `struct prb_data_blk_lpos { unsigned long begin; unsigned long next; }`. `atomic_long_t` is `atomic64_t` with 8-byte longs and `atomic_t` with 4-byte longs, each a struct holding only `counter`, so the value is at offset 0. | `printk_ringbuffer.h`, v5.10 to v6.17; `include/linux/types.h` and `include/linux/atomic/atomic-long.h`, v6.17. |
| R3 | `struct printk_info { u64 seq; u64 ts_nsec; u16 text_len; u8 facility; u8 flags:5; u8 level:3; u32 caller_id; struct dev_printk_info dev_info; }`. The ring code sets `seq`; printk sets the rest. | `printk_ringbuffer.h`, v5.10 to v6.17. |
| R4 | `struct dev_printk_info { char subsystem[PRINTK_INFO_SUBSYSTEM_LEN]; char device[PRINTK_INFO_DEVICE_LEN]; }`, with lengths 16 and 48. | `include/linux/dev_printk.h`, v5.10, v5.11, v6.1, v6.17. |
| R5 | The descriptor count is `1 << count_bits` and the data size is `1 << size_bits`. `DESC_INDEX(n)` is `n & (count - 1)`, and `n` "can be either a descriptor ID or a sequence number": the descriptor and the info of a record share one index, reached from either. `DATA_INDEX(lpos)` is `lpos & (size - 1)`; `DATA_WRAPS(lpos)` is `lpos >> size_bits`. | `printk_ringbuffer.c` (`to_desc`, `to_info`, the macros), v5.10 to v6.17. |
| R6 | `state_var` holds the descriptor ID in its low `BITS_PER_LONG - 2` bits and the state in the top 2 bits: `DESC_ID(sv) = sv & ~(3 << (BITS_PER_LONG - 2))`, `DESC_STATE(sv) = 3 & (sv >> (BITS_PER_LONG - 2))`. The states are reserved 0, committed 1, finalized 2 and reusable 3. A query with an ID that differs from `DESC_ID(sv)` is a miss. | `printk_ringbuffer.h`; `get_desc_state` in `printk_ringbuffer.c`, v5.10 to v6.17. |
| R7 | `tail_id` is the ID of the oldest descriptor and `head_id` of the newest. A new descriptor takes ID `DESC_ID(head_id + 1)`. So the records, oldest first, are the IDs from `tail_id` to `head_id`, and there are at most `count` of them. | `printk_ringbuffer.c` overview and `desc_reserve`, v6.17. |
| R8 | A reserved descriptor is being written. A committed one is consistent but may be reopened. A finalized one is complete. A reusable one "exists, but its text and/or meta data may no longer be available". Kernel readers return only finalized records whose `seq` is the one asked for, and report a reusable descriptor, or one whose `text_blk_lpos` is `FAILED_LPOS` (0x1) in both members, as a record whose data is lost. | `printk_ringbuffer.c` overview and `desc_read_finalized_seq`, v5.10 to v6.17. |
| R9 | A data block is an `unsigned long id` followed by the text. The block is valid only while the descriptor with that `id` points back at it. When a block's text would pass the end of the array, only the ID is stored at `begin` and the whole block is stored at index 0. | `struct prb_data_block` and `data_make_reusable` in `printk_ringbuffer.c`; overview, "Data Ring", v6.17. |
| R10 | `get_data`: when bit 0 of both `begin` and `next` is set the record has no data block; it is an empty line when both are 0x3 (`NO_LPOS` to v6.4, `EMPTY_LINE_LPOS` at v6.14 and v6.17, same value and meaning) and lost otherwise. When `DATA_WRAPS(begin) == DATA_WRAPS(next)` and `begin < next`, the block is at `DATA_INDEX(begin)` with size `next - begin`. When `DATA_WRAPS(begin + size) == DATA_WRAPS(next)`, the block is at index 0 with size `DATA_INDEX(next)`. Anything else is illegal. `begin` and `next` must be multiples of `sizeof(unsigned long)`, and the size must hold at least the ID. The text size is the size less the ID. | `get_data` in `printk_ringbuffer.c`, v5.10, v6.1, v6.14, v6.17 (the same apart from the constant's name). |
| R11 | `copy_data` refuses a record whose text size is less than `text_len`; the block may be longer because of alignment padding. | `copy_data`, v6.17. |
| R12 | A data block is valid only when it lies within the data ring's tail and head logical positions. | `printk_ringbuffer.c` overview, "Data Ring", condition 3, v6.17. |
| R13 | The data ring is `log_buf_len` bytes, at most `LOG_BUF_LEN_MAX` = 2^31, so `size_bits` ≤ 31. The descriptor count is `log_buf_len >> PRB_AVGBITS` with `PRB_AVGBITS` 5, so `count_bits` ≤ 26. `CONFIG_LOG_BUF_SHIFT <= PRB_AVGBITS` is a build error, so `count_bits` ≥ 1. | `printk.c` v5.10, v6.1, v6.4, v6.14, v6.17 (`LOG_BUF_LEN_MAX`, `PRB_AVGBITS`, `setup_log_buf`, `_DEFINE_PRINTKRB(printk_rb_static, ...)`). |
| R14 | On the ring, `caller_id` is always filled: `printk_caller_id()` gives the PID in task context and `0x80000000 + CPU` otherwise. | `vprintk_store` and `printk_caller_id` in `printk.c`, v5.10, v6.17. |
| R15 | `prb_init` and `_DEFINE_PRINTKRB` start both IDs at `DESC0_ID(count_bits)` = `DESC_ID(-(_DESCS_COUNT(count_bits) + 1))`, where `_DESCS_COUNT` is `1U << count_bits`, an `unsigned int`: the negation wraps at 32 bits, so the start ID is `0xffffffff - count` with 8-byte longs too. That descriptor, the last in the array, is set reusable with `FAILED_LPOS` in both `begin` and `next`, and stays the tail until the tail is first pushed. It holds no record ("Descriptor Bootstrap"). | `printk_ringbuffer.h` (`_DESCS_COUNT`, `DESC0_ID`, `DESC0_SV`, the bootstrap comment) and `prb_init` in `printk_ringbuffer.c`, v5.10, v6.1, v6.4, v6.14, v6.17. |
| R16 | Before a writer moves `head_lpos` to a new `next_lpos`, `data_alloc` pushes `tail_lpos` to at least `next_lpos - DATA_SIZE`, so `head_lpos - tail_lpos` is at most `size`. | `data_alloc` and `data_realloc`, `printk_ringbuffer.c` v5.10, v6.17. |

### The record buffer (v3.5 to v5.9)

| # | Fact | Source |
|---|---|---|
| L1 | `struct printk_log { u64 ts_nsec; u16 len; u16 text_len; u16 dict_len; u8 facility; u8 flags:5; u8 level:3; }`. From v5.1 a `u32 caller_id` follows `level` when `CONFIG_PRINTK_CALLER` is set (absent at v5.0). With `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS` the struct is `__packed __aligned(4)` (v4.19 to v5.9). | `printk.c` v3.5, v3.10 (`struct log`), v3.11, v4.19, v5.0, v5.1, v5.9. |
| L2 | A record is the header, then `text_len` bytes of text, then `dict_len` bytes of dictionary, then zero padding to `LOG_ALIGN`. `len` is the whole record. `LOG_ALIGN` is the alignment of the header type, or 4. | `msg_used_size` and `log_store` in `printk.c` v4.19; `log_store` v3.5. |
| L3 | A record header with `len` 0 marks the end of the buffer: the reader goes on at offset 0. `log_store` writes such a header when the next record would not fit before the end. | `log_from_idx`, `log_next` and `log_store`, v3.5, v4.19. |
| L4 | `log_first_idx` and `log_next_idx` are equal both when the buffer is empty and when it is full; `log_first_seq == log_next_seq` tells them apart. Each stored record adds one to `log_next_seq`; each dropped one adds one to `log_first_seq`. | `logbuf_has_space`, `log_make_free_space` and `log_store`, v4.19. |
| L5 | The dictionary holds `KEY=value` properties separated by NUL. The kernel's device context uses the keys `SUBSYSTEM` and `DEVICE`. | Comment above `enum log_flags` in `printk.c` v4.19. |
| L6 | The records from `log_first_idx` run to the end marker and go on from 0 up to `log_next_idx`, and while the buffer has wrapped, `log_next_idx` ≤ `log_first_idx` (the free space is the gap between them). So a walk from first to next passes the end marker at most once, and every record after it ends at or before `log_first_idx`. | `logbuf_has_space` and `log_store`, v3.5, v4.19. |

### Shared facts

| # | Fact | Source |
|---|---|---|
| C1 | Record flags: `LOG_NEWLINE` 2 (the text ended in a newline), `LOG_CONT` 8 (the text is a fragment of a continuation line); `LOG_PREFIX` 4 up to v5.9 and `LOG_FORCE_CON` 1 at v6.17. | `enum log_flags` in `printk.c` v4.19, v5.10; `enum printk_info_flags` in `kernel/printk/internal.h` v6.1, v6.4, v6.14, v6.17. |
| C2 | printk removes one trailing newline before storing the text and sets `LOG_NEWLINE`. | `vprintk_store` in `printk.c` v4.19; `printk_sprint` in `printk.c` v6.17. |
| C3 | When the kernel prints a record, it splits the text at each `\n` and prints every piece, including an empty one after a final `\n`, as a line with the record's prefix. An empty text prints one empty line. | `record_print_text`, `printk.c` v6.17. |
| C4 | `ts_nsec` is nanoseconds of `local_clock()`. The kernel prints it as `[%5lu.%06lu]`: whole seconds and microseconds, the nanoseconds cut. | `print_time`, `printk.c` v4.19, v6.17; v3.4 prints the same form into the buffer. |
| C5 | The caller is printed as `T` and the PID, or `C` and the CPU number when bit 31 is set. | `print_caller` and `info_print_ext_header`, `printk.c` v5.10, v6.17. |
| C6 | A record's priority is `(facility << 3) | level`. The level is 3 bits. Kernel messages carry facility 0; a line written to `/dev/kmsg` with no prefix carries facility 1 (`LOG_USER`), and one with a prefix carries `(prefix >> 3) & 0xff`. | `printk.c` (`LOG_LEVEL`, `LOG_FACILITY`, `devkmsg_write`) v6.17; `Documentation/ABI/testing/dev-kmsg` v4.19, v6.17. |
| C7 | The level names are those of `KERN_EMERG` 0, `KERN_ALERT` 1, `KERN_CRIT` 2, `KERN_ERR` 3, `KERN_WARNING` 4, `KERN_NOTICE` 5, `KERN_INFO` 6 and `KERN_DEBUG` 7. | `include/linux/kern_levels.h`, v4.19, v6.17. |
| C8 | Facility numbers: 0 kernel, 1 user-level, 2 mail, 3 system daemons, 4 security/authorization, 5 syslogd, 6 line printer, 7 network news, 8 UUCP, 9 clock daemon, 10 security/authorization, 11 FTP, 12 NTP, 13 log audit, 14 log alert, 15 clock daemon, 16 to 23 local use 0 to 7. POSIX names `LOG_KERN`, `LOG_USER`, `LOG_MAIL`, `LOG_NEWS`, `LOG_UUCP`, `LOG_DAEMON`, `LOG_AUTH`, `LOG_CRON`, `LOG_LPR` and `LOG_LOCAL0` to `LOG_LOCAL7`, without values. | RFC 5424 section 6.2.1, Table 1; POSIX.1-2024 `<syslog.h>`. |
| C9 | `linux_banner` is `"Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@" LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n"`, and `start_kernel` logs it with `pr_notice("%s", linux_banner)`. | `init/version.c` v4.19; `init/version-timestamp.c` v6.1, v6.4, v6.14, v6.17; `init/main.c` v4.19, v6.1, v6.4, v6.14, v6.17. |
| C10 | v3.4 stores each line as `<` level `>`, then (with `printk_time`) `[%5lu.%06lu] `, then the text and `\n`. A prefix the caller gave is copied as written, and may be several digits holding facility and level. | `vprintk` and `log_prefix`, `kernel/printk.c` v3.4. |
| C11 | VMCOREINFO exports the sizes and offsets the dump tools need: for the ring, `SYMBOL(prb)`, `SIZE` and `OFFSET` of `printk_ringbuffer`, `prb_desc_ring`, `prb_desc`, `prb_data_blk_lpos`, `printk_info` (`seq`, `ts_nsec`, `text_len`, `caller_id`, `dev_info`), `dev_printk_info` with `LENGTH(printk_info_subsystem)` and `LENGTH(printk_info_device)`, `prb_data_ring`, and `atomic_long_t.counter`; for the record buffer, `SYMBOL(log_buf)`, `SYMBOL(log_buf_len)`, `SYMBOL(log_first_idx)`, `SYMBOL(log_next_idx)`, and `SIZE` and `OFFSET` of `printk_log` (`ts_nsec`, `len`, `text_len`, `dict_len`, and `caller_id` with `CONFIG_PRINTK_CALLER`). Neither exports `facility`, `flags` or `level`, nor `log_first_seq`. | `log_buf_vmcoreinfo_setup`, `printk.c` v4.19, v5.9, v5.10, v6.1, v6.4, v6.14, v6.17; v3.10 and v3.11 export the same for `log` and `printk_log`. |
| C12 | A `u8` member that follows a `u16` member at an even offset takes the next byte, and a following `u8` the byte after it. On x86 bit-fields are allocated from the low-order bit of their unit, so `flags:5` is bits 0 to 4 and `level:3` bits 5 to 7 of the byte after `facility`. | C struct layout; System V x86-64 psABI, "Bit-Fields" (allocated right to left). |
| C13 | The `/dev/kmsg` form of a record's text writes every byte `c` with `c < ' '`, `c >= 127` or `c == '\\'` as `\x%02x` (two lowercase hex digits) and every other byte as itself. | `msg_print_ext_body`, `printk.c` v4.19; `msg_add_ext_text`, `printk.c` v6.17. |
| L7 | A record in the record buffer is written once, whole, by `log_store`; a continuation line is gathered in `struct cont` and stored only when `cont_flush` runs. The buffer has no record states, so a stored record is complete. | `log_store`, `struct cont`, `cont_flush`, `printk.c` v4.19. |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Both captures' symbol tables have `prb`, `printk_rb_static`, `printk_rb_dynamic`, `log_buf`, `log_buf_len`, `linux_banner`, and no `log_first_idx` or `log_end`. They type `printk_ringbuffer` (88 bytes), `prb_desc_ring` (48), `prb_data_ring` (32), `prb_desc` (24), `prb_data_blk_lpos` (16), `printk_info` (88) and `dev_printk_info` (64), with every member of R1 to R4 at the offsets VMCOREINFO gives; `facility` at 0x12, and `flags` and `level` at 0x13 as bits 0+5 and 5+3, as C12 derives. `atomic_long_t` members are typed `atomic64_t`. | `kernellogfacts`, 2026-11-12. |
| M2 | Ring sizes and record counts per capture. | Section 9 table. |
| M3 | With every log type hidden from the symbol table, the layout from VMCOREINFO and C12 gives the same rows as the typed table on both captures (552 and 611 rows, identical). | `kernellogfacts`, 2026-11-12. |
| M4 | Descriptor states over the whole array: mem3_ubuntu24 7,640 never used (state 0, ID 0), 551 finalized, 1 reusable (the bootstrap, R15); mem4_fedora40 7,581, 610 and 1. Neither has a committed record. | `kernellogfacts`, 2026-11-12. |

## 4. Algorithm

### 4.1 Format choice

Choose by symbol, in this order (B1 to B3):

1. `prb` present: the ring (4.3).
2. `log_first_idx` present: the record buffer (4.4).
3. `log_end` present: the character ring (4.5).
4. Otherwise `ErrNoLog`.

### 4.2 Layout

Each format needs member offsets and type sizes. Each is taken from the symbol table first. When the table lacks it and VMCOREINFO exports it (C11), it is taken from the first VMCOREINFO table of the S05 scan whose entry for the key is usable. A table whose entry is cut, is not an integer, is negative or does not fit 64 bits is passed over, and the later tables are tried. Integer widths are the source widths (R1 to R3, L1): `unsigned int` 4 bytes, `unsigned long` and `atomic_long_t` the pointer width, `u64` 8, `u32` 4, `u16` 2, `u8` 1. An `atomic_long_t` value is read at the member's offset (R2).

`facility`, `flags` and `level` come from the symbol table, with their bit positions. When the table lacks them, they are taken from C12: `facility` at `text_len` + 2 on the ring, or `dict_len` + 2 on the record buffer, and `flags` and `level` in the byte after it.

A required offset or size that neither source gives is `ErrLayout`, naming the member. `caller_id`, `dev_info` and `dict_len`'s dictionary are optional.

### 4.3 The ring

1. Read `prb` as a pointer. A null or unreadable pointer is `ErrHeader`.
2. Read `count_bits`, `descs`, `infos`, `head_id` and `tail_id` from `desc_ring`, and `size_bits`, `data`, `head_lpos` and `tail_lpos` from `text_data_ring` (R1).
3. Check the header (section 5). Refuse it with `ErrHeader`, or with `ErrLimit` when it is over the limits.
4. Read the descriptor array (`count` × `SIZE(prb_desc)` bytes), the info array (`count` × `SIZE(printk_info)` bytes) and the data array (`size` bytes) page by page. A page that does not read makes the bytes in it unavailable; the rest are kept.
5. For each ID from `tail_id` to `head_id`, stepping by one in the ID's width (R7):
   1. The index is `ID & (count - 1)` (R5). Read the descriptor's `state_var`, `begin` and `next`.
   2. `DESC_ID(state_var) != ID`: a miss (R6). Skip it.
   3. Reserved: skip it, counted as being written. Reusable: skip it, counted as reusable (R8), except the bootstrap descriptor (R15): the tail, with ID `DESC0_ID`, reusable, with `FAILED_LPOS` in both members. It is not a record and is not counted.
   4. Committed or finalized: read the info at the same index. Its `seq` must map to the same index (R5); otherwise the fields disagree, and the record is skipped.
   5. Find the text with R10. `FAILED_LPOS` in both, or any other data-less value except the empty line, is lost data (R8). An illegal or misaligned block is an invalid block.
   6. The block must lie within the tail and head positions (R12, R16): `next - tail_lpos` and `begin - tail_lpos`, in the pointer width, are at most `head_lpos - tail_lpos`. Otherwise the block is invalid.
   7. The ID stored at the start of the block (index 0 for a wrapping block, R9) must equal the record's ID. Otherwise the fields disagree.
   8. `text_len` must not exceed the text size (R11). Otherwise the block is invalid.
   9. The text is the `text_len` bytes after the block's ID. The record has `seq`, `ts_nsec`, `facility`, `level`, `flags`, `caller_id` (R14), and, when `dev_info` is laid out, the `subsystem` and `device` strings up to their first NUL. It is final when the descriptor's state is finalized, and not final when it is committed (R6, R8).
   10. Bytes that did not read make the record unreadable.
6. The records are in ID order.

Committed records are read, with `Final` false. Their data is consistent (R8), but a writer may still reopen one and add to its text, and a record printed without a final newline stays committed until the next record is reserved, so the newest record of a capture can be one (neither capture has one, M4).

### 4.4 The record buffer

1. Read `log_buf` (pointer), `log_buf_len`, `log_first_idx` and `log_next_idx` (each `u32`). Read `log_first_seq` and `log_next_seq` (`u64`) when both symbols exist.
2. Check the header (section 5).
3. Read the `log_buf_len` bytes at `log_buf` page by page.
4. Walk from `log_first_idx`:
   1. With the sequence numbers, the walk holds exactly `log_next_seq - log_first_seq` records (L4). Without them, the walk ends when it reaches `log_next_idx` again after at least one record; when `log_first_idx == log_next_idx`, the walk starts only if the header there is a valid record.
   2. Read the header at the offset. A header with `len` 0 sends the walk to offset 0 (L3); a second one in the same walk is an invalid record (L6).
   3. Check the record (section 5).
   4. The text is `text_len` bytes after the header; the dictionary is the next `dict_len` bytes (L2). `SUBSYSTEM` and `DEVICE` are taken from it (L5).
   5. The sequence number is `log_first_seq` plus the record's position in the walk, when known. Every record is final (L7).
   6. Go on at offset + `len`.
5. An invalid or unreadable record ends the walk, because the next offset comes from it. The records read so far are kept.

### 4.5 The character ring

1. Read `log_buf` (pointer), `log_buf_len` (`int`) and `log_end` (`u32`).
2. Check the header (section 5).
3. When `log_end` ≤ `log_buf_len`, the text is `log_buf[0, log_end)`. Otherwise the ring is full and holds the last `log_buf_len` characters: `log_buf[log_end & (len - 1), len)` then `log_buf[0, log_end & (len - 1))` (B1).
4. Split the text into lines at `\n`. A last piece with no `\n` is a line still being written, and is kept. When the ring is full the first line may be the tail of an older line. A line is final when its `\n` was read: the last piece before an unreadable page, and the last piece of the ring when it has no `\n`, are not final.
5. Each line is parsed as C10: `<`, decimal digits, `>`, giving level = value & 7 and facility = value >> 3 (C6); then, optionally, `[`, spaces, decimal seconds, `.`, six decimal digits, `]`, a space, giving the timestamp in nanoseconds (C4). A line whose prefix does not parse keeps its whole text and has no level, facility or timestamp.

### 4.6 Rows

Each record gives one row per line of its text (C3): the text split at every `\n`, so an empty text and a text ending in `\n` give an empty line. Every row of a record carries the record's fields. Rows are in record order, and in line order within a record.

Each line is given twice: decoded as UTF-8 with every invalid sequence replaced by U+FFFD, and escaped as the kernel's `/dev/kmsg` form writes it (C13). The escaped form holds every byte of the line, so the original bytes can be read back from it.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Ring: 1 ≤ `count_bits` ≤ 26 and 1 ≤ `size_bits` ≤ 31, and `size_bits` below the pointer width in bits | R13 | `ErrHeader` |
| Ring: `descs`, `infos` and `data` are not null | R1 | `ErrHeader` |
| Ring: `DESC_ID(head_id - tail_id)` < `count` | R7 | `ErrHeader` |
| Ring: `head_lpos - tail_lpos` ≤ `size`, in the pointer width | R16 | `ErrHeader` |
| Ring: `count` ≤ `MaxTableEntries`; the descriptor and info arrays together, and the data array, each ≤ `MaxBufferBytes` | Section 8 | `ErrLimit` |
| Descriptor ID matches; state committed or finalized | R6, R8 | Skipped, counted by state |
| Info `seq` maps to the descriptor's index | R5 | Skipped, counted as disagreeing |
| Block found by R10, aligned, and at least the ID long | R10 | Skipped: lost when data-less, otherwise invalid |
| Block inside the data ring's tail and head | R12 | Skipped as invalid |
| Block ID equals the descriptor ID | R9 | Skipped, counted as disagreeing |
| `text_len` ≤ text size | R11 | Skipped as invalid |
| Record buffer: `0 < log_buf_len` ≤ `MaxBufferBytes`; `log_first_idx` and `log_next_idx` below `log_buf_len`; with sequence numbers, `log_first_seq` ≤ `log_next_seq` | B2, L4 | `ErrHeader`, or `ErrLimit` for the size |
| Record: header inside the buffer; `len` ≥ header + `text_len` + `dict_len`; the padding `len` − that sum below 8 (no header type in the sources needs more than 8-byte alignment); record inside the buffer | L2, L3 | The walk ends with a diagnostic |
| Record walk: at most one end marker, and after it every record ends at or before `log_first_idx` | L6 | The walk ends with a diagnostic |
| Record walk without sequence numbers, `log_first_idx == log_next_idx`, and no valid record there | L4 | The buffer is empty; no diagnostic |
| Record walk: at most `log_buf_len` / header size + 1 records and `MaxListEntries` | Every record is at least a header long (L2) | The walk ends with a diagnostic |
| Character ring: `log_buf_len` a power of two, `0 < log_buf_len` ≤ `MaxBufferBytes` | B1 | `ErrHeader`, or `ErrLimit` for the size |

## 6. Failure modes

| Case | Result |
|---|---|
| No log symbol | `ErrNoLog`, `logkernel: no kernel log symbol in the symbol table` |
| A required layout entry missing, or a member outside its struct | `ErrLayout`, `logkernel: kernel log layout unknown`, after the list of missing members or `a member lies outside its struct` (`<type>: a member lies outside the header` on the record buffer) |
| Header pointer null or unreadable, header out of range | `ErrHeader`, `logkernel: kernel log header out of range`, after the object, its address and the failing values |
| Buffer over the limits | `ErrLimit`, `logkernel: kernel log over the limits` |
| Ring records skipped | One diagnostic per reason, `linux.log.read_kernel: ring at 0x<ring>: descriptors skipped: <n>: <reason>`. The reasons are `logkernel: descriptor holds another id`, `logkernel: descriptor reserved by a writer`, `logkernel: descriptor reusable`, `logkernel: record data lost`, `logkernel: data block invalid`, `logkernel: record fields disagree` and `logkernel: record memory unreadable`. |
| Record walk ended early | `linux.log.read_kernel: record at 0x<address>: <reason>`, the reason `logkernel: record header invalid`, `logkernel: record memory unreadable` or `logkernel: record walk over the limit`; the records read before it are kept |
| Character-ring page unreadable | `linux.log.read_kernel: log_buf at 0x<address>: logkernel: record memory unreadable`; the lines on either side of the gap are kept apart |
| Strict mode | Records skipped as invalid, disagreeing or unreadable, a record walk that ended early, and a character ring with unreadable pages are an error, `linux.log.read_kernel: strict mode: records left out`. Misses, reserved and reusable descriptors and lost data are kernel states, not read failures, and stay diagnostics. |

Errors are returned as `linux.log.read_kernel: <context>: <sentinel>`. For a header the context is the object, its address and the failing values, as `ring at 0x<address>: <what failed>`.

## 7. Result schema

One row per line.

| Field | Type | Meaning | Absent |
|---|---|---|---|
| `Sequence` | uint64 | The record's sequence number | `HasSequence` false: the character ring, or a record buffer without `log_first_seq` |
| `HasSequence` | bool | | |
| `TimestampNsec` | uint64 | `ts_nsec`, nanoseconds since boot on the kernel's local clock | `HasTimestamp` false: a character-ring line without a time prefix |
| `HasTimestamp` | bool | | |
| `Facility` | `Facility` | The facility's name, section 7.1 | Empty: a number with no name, or `HasFacility` false |
| `FacilityNumber` | uint8 | The facility number the record holds (C6) | `HasFacility` false: a character-ring line without a prefix |
| `HasFacility` | bool | | |
| `Level` | `Level` | Section 7.1 | Empty: as `HasFacility` |
| `Caller` | string | `T<pid>` or `C<cpu>` (C5) | Empty: no `caller_id` in the format |
| `Fragment` | bool | `LOG_CONT` set (C1) | false |
| `Final` | bool | The ring: the descriptor is finalized, false when committed (4.3). The record buffer: always (L7). The character ring: the line's `\n` was read (4.5) | |
| `Subsystem`, `Device` | string | The device context (R4, L5) | Empty |
| `Line` | string | One line of the text, invalid UTF-8 replaced by U+FFFD | |
| `LineEscaped` | string | The same line in the `/dev/kmsg` form (C13): bytes below 0x20, from 0x7f, and `\` as `\xNN` | |

### 7.1 Enumerations

`Level`: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug` for 0 to 7 (C7).

`Facility`: `kern` 0, `user` 1, `mail` 2, `daemon` 3, `auth` 4, `lpr` 6, `news` 7, `uucp` 8, `cron` 9, `local0` to `local7` 16 to 23: the POSIX names matched to the RFC 5424 numbers by their descriptions (C8). Any other number has no name, and `FacilityNumber` alone gives it; facility 5 (syslogd) is one. `FacilityNumber` is given for every facility, named or not, because the match of names to numbers is the project's (C8).

## 8. Limits

- `MaxBufferBytes`: each array read in one piece (the descriptor and info arrays together, the data array, the record buffer, the character ring). The kernel allows 2 GiB of log (R13); a log over the cap is refused rather than read in part, because the part read would not be the newest records.
- `MaxTableEntries`: the descriptor count.
- `MaxListEntries`: records in the record-buffer walk.

## 9. Acceptance

- Synthetic fixtures for each format:
  - Every format: a facility with a name and one without (its number kept), a line holding a control byte, a backslash, invalid UTF-8 and DEL, decoded and escaped, and `Final` as each format sets it.
  - Ring: records in each descriptor state, a miss, a wrapping block, an empty line, lost data, a misaligned block, a block outside the tail and head, a block ID mismatch, a `text_len` past the block, a `seq` at the wrong index, an unreadable data page, multi-line text, caller and device context, the bootstrap descriptor, and a header of each refused kind. The layout from VMCOREINFO alone, with `facility`, `flags` and `level` from C12.
  - Record buffer: a walk across the end marker, a full buffer with equal indices, a walk without sequence numbers, a dictionary, `caller_id`, the `struct log` name, the layout from VMCOREINFO, and each invalid record.
  - Character ring: before and after wrapping, prefixes of one and several digits, with and without the time, and a line still being written.
- Fuzz targets over the ring parser, the record walk and the character-ring parser: no panic; every ID from tail to head is either a record or a counted skip; no ring text is longer than the data array; a record walk keeps no more records than headers fit in the buffer and no more text than the buffer holds; the character ring orders exactly `min(log_end, log_buf_len)` bytes; every escaped line is printable ASCII and reads back to the line's bytes.
- On both captures:

| Capture | Ring | Records read | Rows | Skipped | Sequence | Gaps | First timestamp | Last timestamp | Banner |
|---|---|---|---|---|---|---|---|---|---|
| mem3_ubuntu24 (6.17) | `printk_rb_static`, `count_bits` 13, `size_bits` 18, 41,672 data bytes used | 551 | 552 | 0 (the bootstrap is not counted) | 0 to 550 | 0 | 0 ns | 50,495,774,887 ns (50.495774 s) | seq 0, 0 ns, `kern` `notice`, caller `T0`: `Linux version 6.17.0-35-generic (buildd@lcy02-amd64-079) ...`, equal to `linux_banner` without its newline |
| mem4_fedora40 (6.14) | `printk_rb_static`, `count_bits` 13, `size_bits` 18, 46,648 data bytes used | 610 | 611 | 0 | 0 to 609 | 0 | 0 ns | 236,913,644,933 ns (236.913644 s) | seq 0, 0 ns, `kern` `notice`, caller `T0`: `Linux version 6.14.5-100.fc40.x86_64 (mockbuild@...) ...`, equal to `linux_banner` without its newline |

Measured with `kernellogfacts`, 2026-11-12. The banner is the record whose text equals the `linux_banner` string less its final newline (C2, C9). On both captures it is the first record, at level notice as `pr_notice` gives it. Neither ring has wrapped: `tail_id` is still `DESC0_ID(13)` = 0xffffdfff and `tail_lpos` is still `-(1 << 18)`. One record on each capture has two lines. Every record carries a caller; 24 and 33 records carry device context. Levels: mem3 18 debug, 461 info, 62 notice, 10 warning; mem4 22, 528, 48, 12. Facilities: mem3 489 `kern` (0), 57 `daemon` (3), 5 of facility 5 with no name; mem4 500, 103 and 7. No record has `LOG_CONT` set. Every record on both captures is final (M4). The escaped line differs from the decoded one on 7 rows of mem3 (5 holding a tab, 2 a backslash in a systemd unit name) and 13 of mem4 (6 and 7); no line holds a byte at or above 0x7f. Measured with `kernellogfacts`, 2026-11-12.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision: facility names. POSIX names some facilities and RFC 5424 numbers them, but neither ties the two together; the match by description is the project's, and RFC 5424 gives two numbers each for "security/authorization" (4, 10) and "clock daemon" (9, 15). Facilities without a POSIX name print as numbers. | Owner choice: names as section 7.1, numbers only, or both fields. Owner decision 2026-11-12: both name and number fields. Done: rows carry `Facility` (the name, empty when the number has none), `FacilityNumber` and `HasFacility`; sections 7 and 7.1 and the acceptance list changed; `tools/linux/logkernel/read_kernel.go`, `text.go` and their tests. |
| O2 | Owner decision: line text. Bytes are decoded as UTF-8 with invalid sequences replaced; the kernel's `/dev/kmsg` form escapes every byte outside 0x20 to 0x7e, and `\`, as `\xNN` instead. | Owner choice of text form. Owner decision 2026-11-12: decoded text plus escaped field. Done: `Line` stays decoded and `LineEscaped` holds the `/dev/kmsg` form (C13, 4.6, section 7); fuzz property that the escaped form reads back to the bytes; measured rows in section 9; `tools/linux/logkernel/text.go`, `read_kernel.go`, `fuzz_test.go`. |
| O3 | Committed records are reported (4.3). Kernel readers wait for them to be finalized. | Owner choice; a `Final` field if they should be told apart. Owner decision 2026-11-12: add a Final field. Done: `Final` is the finalized state on the ring, always true on the record buffer (L7) and the read newline on the character ring (4.3, 4.4, 4.5, section 7); both captures have every record final; `tools/linux/logkernel/lockless.go`, `records.go`, `plain.go`, `text.go` and their tests. |
| O4 | VMCOREINFO is taken from the first table that holds a key. Images with several tables that disagree have not been seen. | A capture with a crash kernel loaded |
| O5 | The record buffer and character ring are written from the source only; neither capture has them. | A capture of a kernel before 5.10 (Q7) |
| O6 | On the character ring, `log_end` is a 32-bit count. After 2^32 characters it wraps, and a ring that is full looks not full. | Not expected on a running system; no closure planned |
| O7 | 4-byte pointers are written from the source only. | A 32-bit capture |
| O8 | Neither capture's ring has wrapped, so wrapping blocks, misses and a pushed tail are checked by fixtures only. | A capture of a system with a long uptime or a small `log_buf_len` |
| O9 | Facility 5 (syslogd's own messages in RFC 5424) appears on both captures, from `/dev/kmsg` writers, and prints as `5` under O1. | Settled with O1. Owner decision 2026-11-12: settle with the facility-name choice (O1). Done: facility 5 has no name, so its rows carry `Facility` empty, `FacilityNumber` 5 and `HasFacility` true (section 7.1); a fixture checks it. |
| O10 | The kernel sources were fetched with `curl` from the git.kernel.org plain URLs that the project's source rule names, because the same URLs refused the web-fetch tool (HTTP 403). | Owner check that this meets the source rule |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Both name and number fields |
| O2 | Decoded text plus escaped field |
| O3 | Add a Final field |
| O4 | Use first table holding a key |
| O5 | Ship as written, mark untested |
| O6 | No action |
| O7 | Ship as written, mark untested |
| O8 | Keep fixture-only checks |
| O9 | Settle with the facility-name choice (O1) |
| O10 | Accept: same URLs the rule names |

## 11. Provenance

Written from the Linux kernel sources at the tags in section 3, fetched from git.kernel.org on 2026-11-12, RFC 5424, POSIX.1-2024 `<syslog.h>`, the System V x86-64 psABI, and the project's measurements. Every rule rests on the sources and measurements above.
