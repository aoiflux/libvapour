package symbols

import (
	"fmt"
	"math"
	"strings"
)

// Brings the members of embedded records up into the records that embed
// them (FORMAT.md, Records). The whole table is counted first: n embedded
// members of a record with n of its own, k levels deep, bring up n^k, so a
// crafted file could ask for more memory than it took to read.
type embedder struct {
	records map[string]Record
	counted map[string]uint64
	failed  map[string]error
	path    []string
}

func newEmbedder(records []Record) *embedder {
	e := &embedder{
		records: make(map[string]Record, len(records)),
		counted: map[string]uint64{},
		failed:  map[string]error{},
	}
	for _, r := range records {
		e.records[r.Name] = r
	}
	return e
}

func (e *embedder) count(name string) (uint64, error) {
	if n, ok := e.counted[name]; ok {
		return n, nil
	}
	if err, ok := e.failed[name]; ok {
		return 0, err
	}
	for i, p := range e.path {
		if p == name {
			return 0, fmt.Errorf("%q holds itself through embedded members: %s > %s",
				name, strings.Join(e.path[i:], " > "), name)
		}
	}
	e.path = append(e.path, name)
	n, err := e.countMembers(e.records[name])
	e.path = e.path[:len(e.path)-1]
	if err != nil {
		e.failed[name] = err
		return 0, err
	}
	e.counted[name] = n
	return n, nil
}

func (e *embedder) countMembers(r Record) (uint64, error) {
	var n uint64
	for _, m := range r.Members {
		if m.Embeds == "" {
			n = addSaturating(n, 1)
			continue
		}
		if _, ok := e.records[m.Embeds]; !ok {
			return 0, fmt.Errorf("anonymous member %q embeds %q, which the table does not hold", m.Name, m.Embeds)
		}
		c, err := e.count(m.Embeds)
		if err != nil {
			return 0, fmt.Errorf("anonymous member %q embeds %q: %w", m.Name, m.Embeds, err)
		}
		n = addSaturating(n, c)
	}
	return n, nil
}

func addSaturating(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// Called only after count succeeded for the record, so every embedded record
// exists and none holds itself.
func (e *embedder) fields(r Record, capacity uint64) ([]Field, error) {
	out := make([]Field, 0, min(capacity, uint64(len(r.Members))*4))
	slot := map[string]int{}
	if err := e.bringUp(r, 0, &out, slot); err != nil {
		return nil, err
	}
	return out, nil
}

func (e *embedder) bringUp(r Record, base uint64, out *[]Field, slot map[string]int) error {
	for _, m := range r.Members {
		at := base + m.Offset
		if at < base {
			return fmt.Errorf("member %q at offset %d past %d is beyond the 64-bit address space", m.Name, m.Offset, base)
		}
		if m.Embeds != "" {
			if err := e.bringUp(e.records[m.Embeds], at, out, slot); err != nil {
				return fmt.Errorf("anonymous member %q embeds %q: %w", m.Name, m.Embeds, err)
			}
			continue
		}
		f := Field{Name: m.Name, Offset: at, Type: m.Type}
		if i, ok := slot[m.Name]; ok {
			(*out)[i] = f
			continue
		}
		slot[m.Name] = len(*out)
		*out = append(*out, f)
	}
	return nil
}

func embeds(r Record) bool {
	for _, m := range r.Members {
		if m.Embeds != "" {
			return true
		}
	}
	return false
}
