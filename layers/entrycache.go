package layers

import (
	"sync"

	"github.com/aoiflux/libvapour/limits"
)

// Entries are cached by physical address, so the cache is correct only over
// bytes that never change; callers enable it only on an immutable snapshot.
// Eviction is second-chance: a slot read since the hand last passed survives
// one more pass. One process layer is shared by many readers, hence the lock.
type entryCache struct {
	mu    sync.Mutex
	where map[uint64]int
	slots []cacheSlot
	hand  int
}

type cacheSlot struct {
	addr, value uint64
	used        bool
}

func newEntryCache(capacity int) *entryCache {
	if capacity <= 0 {
		capacity = limits.DefaultPTECacheEntries
	}
	return &entryCache{where: make(map[uint64]int, capacity), slots: make([]cacheSlot, 0, capacity)}
}

func (c *entryCache) lookup(addr uint64) (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	i, ok := c.where[addr]
	if !ok {
		return 0, false
	}
	c.slots[i].used = true
	return c.slots[i].value, true
}

func (c *entryCache) store(addr, value uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i, ok := c.where[addr]; ok {
		c.slots[i].value, c.slots[i].used = value, true
		return
	}
	if len(c.slots) < cap(c.slots) {
		c.where[addr] = len(c.slots)
		c.slots = append(c.slots, cacheSlot{addr: addr, value: value})
		return
	}
	for c.slots[c.hand].used {
		c.slots[c.hand].used = false
		c.hand = (c.hand + 1) % len(c.slots)
	}
	delete(c.where, c.slots[c.hand].addr)
	c.slots[c.hand] = cacheSlot{addr: addr, value: value}
	c.where[addr] = c.hand
	c.hand = (c.hand + 1) % len(c.slots)
}

func (c *entryCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.slots)
}
