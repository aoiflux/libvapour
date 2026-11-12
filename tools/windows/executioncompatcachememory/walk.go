package executioncompatcachememory

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
	"github.com/aoiflux/libvapour/util"
)

type treeShape struct {
	root, count             uint64
	parent, left, right     uint64
	linksSize, linksReadLen uint64
}

func readTreeShape(ctx tools.Context) (treeShape, error) {
	var s treeShape
	fields := []struct {
		typ, name string
		into      *uint64
	}{
		{"_RTL_AVL_TABLE", "BalancedRoot", &s.root},
		{"_RTL_AVL_TABLE", "NumberGenericTableElements", &s.count},
		{"_RTL_BALANCED_LINKS", "Parent", &s.parent},
		{"_RTL_BALANCED_LINKS", "LeftChild", &s.left},
		{"_RTL_BALANCED_LINKS", "RightChild", &s.right},
	}
	for _, f := range fields {
		fl, err := ctx.Symbols.Field(f.typ, f.name)
		if err != nil {
			return treeShape{}, fmt.Errorf("%w: %s.%s: %w", ErrTypeMissing, f.typ, f.name, err)
		}
		*f.into = fl.Offset
	}
	st, err := ctx.Symbols.Struct("_RTL_BALANCED_LINKS")
	if err != nil || st.Size == 0 {
		return treeShape{}, fmt.Errorf("%w: _RTL_BALANCED_LINKS size", ErrTypeMissing)
	}
	s.linksSize = st.Size
	s.linksReadLen = max(s.parent, s.left, s.right) + 8
	return s, nil
}

type collector struct {
	ctx    tools.Context
	mem    memory.MemoryReader
	bounds limits.Limits
	strict bool
	key    util.UnicodeStringLayout
	first  error
}

func (c *collector) fail(err error) {
	if c.first == nil {
		c.first = err
	}
}

func readU64(m memory.MemoryReader, at uint64) (uint64, error) {
	b, err := m.ReadAt(at, 8)
	if err != nil {
		return 0, err
	}
	if len(b) < 8 {
		return 0, fmt.Errorf("%w: %d of 8 bytes at 0x%x", ErrShort, len(b), at)
	}
	return binary.LittleEndian.Uint64(b), nil
}

func readFull(m memory.MemoryReader, at, n uint64) ([]byte, error) {
	b, err := m.ReadAt(at, n)
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) < n {
		return nil, fmt.Errorf("%w: %d of %d bytes at 0x%x", ErrShort, len(b), n, at)
	}
	return b, nil
}

func collect(ctx tools.Context, handle uint64) ([]CacheEntry, error) {
	shape, err := readTreeShape(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	layout, err := winkernel.NativeListLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	c := &collector{ctx: ctx, mem: ctx.Memory, bounds: ctx.Bounds(), strict: ctx.StrictMode(),
		key: util.ResolveUnicodeStringLayout(ctx.Symbols)}

	cache, err := readU64(c.mem, handle)
	if err != nil || cache == 0 {
		return nil, fmt.Errorf("%s: %s at 0x%x: %w: %v", Name, handleSymbol, handle, ErrCacheUnread, err)
	}
	store, err := readU64(c.mem, cache+cacheStoreOffset)
	if err != nil || store == 0 {
		return nil, fmt.Errorf("%s: cache at 0x%x: %w: store pointer: %v", Name, cache, ErrCacheUnread, err)
	}
	countBytes, err := readFull(c.mem, store+shape.count, 4)
	if err != nil {
		return nil, fmt.Errorf("%s: cache at 0x%x: %w: element count: %v", Name, store, ErrCacheUnread, err)
	}
	counted := binary.LittleEndian.Uint32(countBytes)

	inTree, nodes, limitErr := c.walkTree(store, shape)
	if limitErr != nil && c.strict {
		c.fail(limitErr)
	}

	w := winkernel.ListWalker{Tool: Name, Memory: c.mem, Layout: layout, Limit: c.bounds.MaxListEntries,
		Strict: c.strict, Report: ctx.AddDiagnostic}
	walk, err := w.WalkRecovering(store+storeListOffset, "cache list")
	if err != nil {
		return nil, err
	}

	var rows []CacheEntry
	listed := map[uint64]bool{}
	ahead := walk.Entries[:len(walk.Entries)-walk.Backward]
	behind := walk.Entries[len(walk.Entries)-walk.Backward:]
	for i, e := range ahead {
		fromTail := -1
		if walk.Forward == nil {
			fromTail = len(ahead) - 1 - i
		}
		rows = append(rows, CacheEntry{Position: i, PositionFromTail: fromTail, InList: true, Address: e})
		listed[e] = true
	}
	for j := len(behind) - 1; j >= 0; j-- {
		rows = append(rows, CacheEntry{Position: -1, PositionFromTail: j, InList: true, Address: behind[j]})
		listed[behind[j]] = true
	}
	onlyList := 0
	for i := range rows {
		rows[i].InTable = inTree[rows[i].Address]
		if !rows[i].InTable {
			onlyList++
		}
	}
	var treeOnly []CacheEntry
	for e := range inTree {
		if !listed[e] {
			treeOnly = append(treeOnly, CacheEntry{Position: -1, PositionFromTail: -1, InTable: true, Address: e})
		}
	}
	for i := range rows {
		c.fill(&rows[i])
	}
	for i := range treeOnly {
		c.fill(&treeOnly[i])
	}
	sort.Slice(treeOnly, func(i, j int) bool {
		a, b := strings.ToUpper(treeOnly[i].Key), strings.ToUpper(treeOnly[j].Key)
		if a != b {
			return a < b
		}
		return treeOnly[i].Address < treeOnly[j].Address
	})
	rows = append(rows, treeOnly...)

	if len(treeOnly) > 0 || onlyList > 0 || uint64(nodes) != uint64(counted) {
		ctx.AddDiagnostic("%s: cache at 0x%x: %d entries only in the tree, %d only in the list, %d tree nodes reached of %d counted",
			Name, store, len(treeOnly), onlyList, nodes, counted)
	}
	if c.strict && c.first != nil {
		return rows, c.first
	}
	return rows, nil
}

// Each node's user data follows its links (S41 L11); a misparented child is
// still walked, because the list order alone cannot place what the tree holds.
func (c *collector) walkTree(store uint64, s treeShape) (map[uint64]bool, int, error) {
	out := map[uint64]bool{}
	sentinel := store + s.root
	top, err := readU64(c.mem, sentinel+s.right)
	if err != nil {
		c.ctx.AddDiagnostic("%s: tree root at 0x%x: links do not read: %v", Name, sentinel, err)
		return out, 0, nil
	}
	type visit struct{ node, parent uint64 }
	stack := []visit{}
	if top != 0 {
		stack = append(stack, visit{top, sentinel})
	}
	seen := map[uint64]bool{}
	reached := 0
	limit := c.bounds.MaxTableEntries
	for len(stack) > 0 {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[v.node] {
			continue
		}
		if len(seen) >= limit {
			err := fmt.Errorf("%s: tree at 0x%x: more than %d nodes: %w", Name, sentinel, limit, ErrLimit)
			c.ctx.AddDiagnostic("%v", err)
			return out, reached, err
		}
		seen[v.node] = true
		links, err := readFull(c.mem, v.node, s.linksReadLen)
		if err != nil {
			c.ctx.AddDiagnostic("%s: tree node at 0x%x: links do not read: %v", Name, v.node, err)
			continue
		}
		reached++
		if p := binary.LittleEndian.Uint64(links[s.parent:]); p != v.parent {
			c.ctx.AddDiagnostic("%s: tree node at 0x%x: Parent is 0x%x, not the node above, 0x%x", Name, v.node, p, v.parent)
		}
		if user := v.node + s.linksSize; user > v.node {
			out[user] = true
		}
		for _, off := range []uint64{s.right, s.left} {
			if child := binary.LittleEndian.Uint64(links[off:]); child != 0 {
				stack = append(stack, visit{child, v.node})
			}
		}
	}
	return out, reached, nil
}

func (c *collector) fill(r *CacheEntry) {
	b, err := readFull(c.mem, r.Address, elementSize)
	if err != nil {
		r.KeyUnreadable, r.DataUnreadable = true, true
		c.report(r.Address, "element does not read", err)
		return
	}
	el, err := decodeElement(b, c.key)
	if err != nil {
		r.KeyUnreadable = true
		c.report(r.Address, "key not read", err)
	} else {
		c.readKey(r, el)
	}
	c.readData(r, el.data)
}

func (c *collector) readKey(r *CacheEntry, el element) {
	if el.keyLength == 0 {
		return
	}
	if int64(el.keyLength) > c.bounds.MaxNameBytes {
		r.KeyUnreadable = true
		c.report(r.Address, "key not read", fmt.Errorf("%w: %d bytes", ErrKeyTooLong, el.keyLength))
		return
	}
	raw, err := readFull(c.mem, el.keyBuffer, uint64(el.keyLength))
	if err != nil {
		r.KeyUnreadable = true
		c.report(r.Address, "key not read", err)
		return
	}
	r.Key = util.DecodeUTF16LE(raw)
}

func (c *collector) readData(r *CacheEntry, at uint64) {
	b, err := readFull(c.mem, at, dataObjectSize)
	if err != nil {
		r.DataUnreadable = true
		c.report(r.Address, "data not read", err)
		return
	}
	d, err := decodeEntryData(b)
	if err != nil {
		r.DataUnreadable = true
		c.report(r.Address, "data not read", err)
		return
	}
	if t, ok := util.FiletimeToTime(d.fileTime); ok {
		r.FileLastWrite = t
	}
	r.DataSize = d.size
	if d.size == 0 {
		return
	}
	if int64(d.size) > c.bounds.MaxBufferBytes {
		r.DataUnreadable = true
		c.report(r.Address, "data not read", fmt.Errorf("%w: %d bytes", ErrDataTooLarge, d.size))
		return
	}
	raw, err := readFull(c.mem, d.buffer, uint64(d.size))
	if err != nil {
		r.DataUnreadable = true
		c.report(r.Address, "data not read", err)
		return
	}
	r.Data = append([]byte(nil), raw...)
}

func (c *collector) report(at uint64, what string, err error) {
	wrapped := fmt.Errorf("%s: entry at 0x%x: %s: %w", Name, at, what, err)
	c.ctx.AddDiagnostic("%v", wrapped)
	c.fail(wrapped)
}
