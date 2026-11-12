package tools

import (
	"slices"
	"strconv"
	"strings"
)

// A Windows PID is a DWORD and a Linux one stays under PID_MAX_LIMIT, so a
// larger value can name no process.
const maxPID = 1<<32 - 1

type PIDSet struct {
	pids []uint64
	// Keeps nothing, so a tool that skipped Validate never widens to every
	// process on a filter it could not read.
	unread bool
}

func (s PIDSet) All() bool { return s.pids == nil && !s.unread }

func (s PIDSet) Keep(pid uint64) bool {
	switch {
	case s.unread:
		return false
	case s.pids == nil:
		return true
	}
	_, found := slices.BinarySearch(s.pids, pid)
	return found
}

func (s PIDSet) Key() string {
	switch {
	case s.unread:
		return "unread"
	case s.pids == nil:
		return ""
	}
	parts := make([]string, len(s.pids))
	for i, pid := range s.pids {
		parts[i] = strconv.FormatUint(pid, 10)
	}
	return strings.Join(parts, ",")
}

func (c Context) PIDs() PIDSet {
	s, err := c.pidSet()
	if err != nil {
		return PIDSet{unread: true}
	}
	return s
}

const pidForms = "one PID or a list: an integer of 0 or more, a []uint64 or []int, or text of decimal or " +
	"0x hexadecimal PIDs separated by commas, at least one PID, no empty item, each at most 0xffffffff"

func (c Context) pidSet() (PIDSet, error) {
	v, ok := c.Options[optionPID]
	if !ok {
		return PIDSet{}, nil
	}
	pids, ok := pidList(v)
	if !ok || len(pids) == 0 {
		return PIDSet{}, wrongForm(optionPID, v, pidForms)
	}
	for _, pid := range pids {
		if pid > maxPID {
			return PIDSet{}, wrongForm(optionPID, v, pidForms)
		}
	}
	slices.Sort(pids)
	return PIDSet{pids: slices.Compact(pids)}, nil
}

func pidList(v any) ([]uint64, bool) {
	switch x := v.(type) {
	case []uint64:
		return slices.Clone(x), true
	case []int:
		out := make([]uint64, len(x))
		for i, n := range x {
			if n < 0 {
				return nil, false
			}
			out[i] = uint64(n)
		}
		return out, true
	case string:
		items := strings.Split(x, ",")
		out := make([]uint64, len(items))
		for i, item := range items {
			n, ok := parseUintText(item)
			if !ok {
				return nil, false
			}
			out[i] = n
		}
		return out, true
	}
	n, ok := toUint(v)
	if !ok {
		return nil, false
	}
	return []uint64{n}, true
}
