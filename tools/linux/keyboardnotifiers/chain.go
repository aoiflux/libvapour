package keyboardnotifiers

import "github.com/aoiflux/libvapour/tools/linuxwalk"

type block struct {
	at, call, next uint64
	priority       int64
}

type chain struct {
	blocks []block
	end    linuxwalk.End
	at     uint64
}

// KN3: a chain ends at a null next pointer. A block seen twice or more than
// most blocks means memory that no longer holds a chain, so the walk stops.
func walkChain(first uint64, most int, read func(at uint64) (block, error)) chain {
	var c chain
	seen := map[uint64]bool{}
	for at := first; at != 0; {
		if seen[at] {
			c.end, c.at = linuxwalk.Revisited, at
			return c
		}
		if len(c.blocks) >= most {
			c.end, c.at = linuxwalk.Capped, at
			return c
		}
		b, err := read(at)
		if err != nil {
			c.end, c.at = linuxwalk.EntryUnreadable, at
			return c
		}
		seen[at] = true
		c.blocks = append(c.blocks, b)
		at = b.next
	}
	c.end = linuxwalk.Closed
	return c
}

// KN4: notifier_chain_register keeps a chain in non-increasing priority, so
// a block above its predecessor was not placed by it.
func outOfOrder(blocks []block) []int {
	var out []int
	for i := 1; i < len(blocks); i++ {
		if blocks[i].priority > blocks[i-1].priority {
			out = append(out, i)
		}
	}
	return out
}
