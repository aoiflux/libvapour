# S02: Linux xarray, radix tree and IDR walk

Version 1, 2026-11-11.

## 1. Purpose

The kernel indexes objects by integer in a tree of fixed-fan-out nodes: the page cache of an inode, the PIDs of a namespace, BPF programs and maps, and other IDRs. Since 4.20 the tree is the xarray; before that it was the radix tree, whose layout and entry encoding differ. This specification defines one bounded, cycle-safe walk that lists the pointer entries of either tree with their indexes, chooses the layout from the image's own types, and defines the IDR walk on top of it.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Memory, symbol table, address form | as in S01 section 2 | |
| Limits | the effective `limits.Limits` | `MaxTableEntries`, `MaxRecursionDepth` (section 8). |
| Root | address, type name | The tree root: an `xarray` or a `radix_tree_root`, given with the name of its type as the symbol table records the member that holds it. |
| IDR | address | The IDR walk only: a `struct idr`. |

## 3. Constraints from the kernel source

Tags checked: v4.10, v4.11, v4.19, v4.20, v6.14 and v6.17.

| # | Constraint | Source |
|---|---|---|
| X1 | `struct xarray { spinlock_t xa_lock; gfp_t xa_flags; void *xa_head; }`. | `include/linux/xarray.h`, v4.20, v6.14, v6.17. |
| X2 | `struct xa_node` holds `shift` (bits remaining in each slot), `offset` (slot offset in the parent), `parent` (null at the top), `array` (the xarray it belongs to) and `slots[XA_CHUNK_SIZE]`. | `include/linux/xarray.h`, v4.20, v6.14, v6.17. |
| X3 | `XA_CHUNK_SHIFT` is 4 under `CONFIG_BASE_SMALL`, else 6; `XA_CHUNK_SIZE` is `1 << XA_CHUNK_SHIFT`. | `include/linux/xarray.h`, v6.14, v6.17. |
| X4 | The bottom two bits of an entry: 00 pointer, 10 internal, x1 value entry or tagged pointer. | `include/linux/xarray.h` header comment, `xa_is_value`, `xa_is_internal`, v6.14, v6.17. |
| X5 | An internal entry above 4096 is a node; the node is the entry minus 2. Internal values 0 to 62 are sibling entries, 256 the retry entry, 257 the zero entry. Internal entries are `(v << 2) \| 2`. | `include/linux/xarray.h` `xa_is_node`, `xa_to_node`, `xa_mk_internal`, `xa_is_sibling`, `XA_RETRY_ENTRY`, `XA_ZERO_ENTRY`, v6.14, v6.17. |
| X6 | A head that is not a node is the single entry at index 0. A lookup descends by `offset = (index >> node->shift) & XA_CHUNK_MASK`, and a sibling slot stands for the slot it names. | `lib/xarray.c` `xas_start`, `xas_descend`, v6.14. |
| X7 | A new node gets `shift`, `offset` in its parent, `parent` and `array` when it is allocated. Its shift is at most `BITS_PER_LONG`. | `lib/xarray.c` `xas_alloc`, v6.14. |
| R1 | `struct radix_tree_root { spinlock_t xa_lock; gfp_t gfp_mask; struct radix_tree_node *rnode; }` in v4.19. | `include/linux/radix-tree.h`, v4.19. |
| R2 | `struct radix_tree_node` has `shift`, `offset`, `parent`, `root` (v4.11 and later) and `slots[RADIX_TREE_MAP_SIZE]`; `RADIX_TREE_MAP_SHIFT` is 4 under `CONFIG_BASE_SMALL`, else 6. | `include/linux/radix-tree.h`, v4.11, v4.19. |
| R3 | The bottom two bits of a v4.19 radix entry: 00 data pointer, 01 internal, 10 exceptional, 11 reserved. The node is the entry with bit 0 cleared; the retry entry is the internal entry of a null node (value 1); a sibling entry points at a slot of the same node. | `include/linux/radix-tree.h` header comment and `radix_tree_is_internal_node`; `lib/radix-tree.c` `entry_to_node`, `RADIX_TREE_RETRY`, `is_sibling_entry`; v4.19. |
| R4 | A root that is not an internal entry is the single entry at index 0; descent uses `(index >> parent->shift) & RADIX_TREE_MAP_MASK`. | `lib/radix-tree.c` `radix_tree_load_root`, `radix_tree_descend`, v4.19. |
| R5 | From v4.20 `radix-tree.h` defines `radix_tree_root` as `xarray` and `radix_tree_node` as `xa_node`, and internal entries carry 10. | `include/linux/radix-tree.h`, v4.20, v6.14, v6.17. |
| I1 | `struct idr { struct radix_tree_root idr_rt; unsigned int idr_base; unsigned int idr_next; }` in v4.19 and later; v4.11 has no `idr_base`; v4.10 has the older layered `struct idr` with no `idr_rt`. | `include/linux/idr.h`, v4.10, v4.11, v4.19, v4.20, v6.14, v6.17. |
| I2 | An ID is the tree index plus `idr_base`. | `lib/idr.c` `idr_for_each`, v6.14. |

So the IDR moved onto the xarray in v4.20 (R5 with I1): the member type stays spelled `radix_tree_root` in source, but the compiled type is `xarray`.

## 4. Algorithm

### 4.1 Choosing the layout

The choice is made from the types, never from a version string.

1. Look up the root's structure type in the symbol table.
2. It has `xa_head`: the **xarray** layout (X1). The node type is `xa_node`; if the table has none, `radix_tree_node` (R5 lets a table name the node by its old spelling).
3. Otherwise it has `rnode`: the **radix** layout (R1). The node type is `radix_tree_node`.
4. Otherwise, or with no node type: an error wrapping `ErrUnsupported`.
5. The node type must have `shift` and `slots`. `slots` must be an array of 16 or 64 elements (X3, R2); its length is the fan-out, and its base-2 logarithm the chunk shift.

### 4.2 Classifying an entry

| Layout | Low bits | Kind |
|---|---|---|
| xarray | 00, not null | pointer |
| xarray | x1 | value, not a pointer (X4) |
| xarray | 10, entry > 4096 | node, at entry − 2 (X5) |
| xarray | 10, entry ≤ 4096 | sibling, retry, zero or reserved; not an entry (X5) |
| radix | 00, not null | pointer |
| radix | 10 | exceptional, not a pointer (R3) |
| radix | 11 | reserved, not a pointer (R3) |
| radix | 01, equal to 1 | retry; not an entry (R3) |
| radix | 01, pointing into the current node's `slots` | sibling; not an entry (R3) |
| radix | 01, otherwise | node, at entry with bit 0 cleared (R3) |

The classification uses the raw value read from the slot, before the address form; the address form applies to the pointer and node addresses that result.

### 4.3 Walk

1. Read the root's head (`xa_head` or `rnode`). Null: an empty tree. A pointer: one entry at index 0 (X6, R4). A value, retry or other non-node: no entries.
2. A node at the head is the top node. Its shift must be a multiple of the chunk shift and less than 8 × the pointer width: an index is an `unsigned long`, so a larger shift would place every slot past the first outside the index range (X7).
3. Visit a node at a known base index and an expected shift (any valid shift for the top node, the parent's shift minus the chunk shift for a child):
   1. A node already visited is counted as **revisited** and not walked again.
   2. If its `shift` and `slots` do not read, count one **unread** node.
   3. If its shift is not the expected one, count one **inconsistent** node and do not walk it: the indexes beneath it would be wrong and the depth would not fall.
   4. If its `parent`, `offset` or `array`/`root` does not match where it was reached, count one **mismatched** node but walk it. The kernel's lookup (X6, R4) follows only slots and shift, so the entries beneath are the ones the kernel itself would find.
   5. For slot *i*, the index is `base + (i << shift)`. A pointer at shift 0 is an entry at that index. A node at shift > 0 is visited at that index. A pointer at shift > 0 is a multi-index entry and is recorded at its first index. Values, siblings, retry and zero entries are skipped. Values, and in the radix layout exceptional and reserved entries, are counted as values. A node in a slot of a shift-0 node is counted inconsistent.
4. Entries are listed in index order: slots are visited in increasing order, depth first.

### 4.4 IDR walk

1. `struct idr` must have `idr_rt` with a named type (I1). Otherwise an error wrapping `ErrUnsupported`: the layered IDR of v4.10 and earlier is not walked (section 10).
2. Walk the tree at `idr + offset(idr, idr_rt)` (4.3).
3. When `idr` has `idr_base` and it reads, add it to each index to give the ID (I2). When it does not read, count one **unread** node and keep the tree indexes.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| The layout is the root type's, by its members. | R5 makes the name unreliable; the members are not. | `ErrUnsupported`. |
| Fan-out is 16 or 64. | X3, R2 | `ErrUnsupported`. |
| A child's shift is its parent's minus the chunk shift. | X6, R4 | Counted inconsistent; not walked. |
| No node is walked twice. | An image can link a node twice or in a loop. | Counted revisited. |
| Non-pointer entries are never returned as pointers. | X4, X5, R3 | Skipped. |

## 6. Failure modes

- A missing type or member: an error wrapping `ErrUnsupported`.
- An unreadable head: an empty walk with one unread node counted.
- Every other memory failure is counted, never an error. Strict mode belongs to the caller, as in S01 section 6.

## 7. Result schema

| Field | Meaning |
|---|---|
| Entries | Pointer entries, in the address form, in index order. |
| Indexes | The index of each entry (the ID, for an IDR). |
| Revisited, Unread, Inconsistent, Mismatched, Values | Counts from 4.3. |
| Capped | True when a limit ended the walk. |

## 8. Limits

- At most `MaxTableEntries` entries and at most `MaxTableEntries` nodes visited.
- Depth is at most `ceil(8 × pointer width / chunk shift)` by 4.3 step 3.3, and never more than `MaxRecursionDepth`.

## 9. Acceptance

- Fixtures for both layouts: an empty tree, a single entry at the head, a two-level tree with entries at known indexes, sibling, retry, zero and value entries skipped.
- A node linked twice is walked once and counted; a node that points at itself is counted and ends.
- A child with the wrong shift is counted inconsistent and not walked; a wrong `parent` is counted mismatched and walked.
- `MaxTableEntries` caps entries and nodes with `Capped`.
- An IDR adds `idr_base`; a v4.10-style IDR is refused with `ErrUnsupported`.
- A fuzz target over the bytes of a tree of each layout: no panic, termination, at most `MaxTableEntries` entries.

## 10. Open points

- Q7, the oldest supported kernel, is undecided. Radix-tree nodes with no `shift` member (none of the tags checked here has such a node), and the layered IDR of v4.10 and earlier, are refused with `ErrUnsupported`. No current caller needs them on a 4.11 or later kernel.

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| Q7 | Refuse with ErrUnsupported |

## 11. Provenance

Sources: the Linux kernel source at tags v4.10, v4.11, v4.19, v4.20, v6.14 and v6.17, files as cited in section 3, from git.kernel.org, accessed 2026-11-11. Author: the project.
