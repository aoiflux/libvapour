package consolelist

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
)

var (
	ErrCapacity       = errors.New("consolelist: history buffer size is zero or not the one searched for")
	ErrHistoryFull    = errors.New("consolelist: history holds more commands than its buffer size")
	ErrNoApplication  = errors.New("consolelist: history names no application")
	ErrRecallPosition = errors.New("consolelist: recall position lies outside the commands")
)

type Command struct {
	Index      int
	Address    uint64
	Text       string
	Unreadable bool
}

// One command history buffer: the commands typed into one application in
// one console, oldest first (S33 F10, F11).
type History struct {
	Address               uint64
	Application           string
	ApplicationUnreadable bool
	BufferSize            uint64
	RecallPosition        int64
	OwnerRecord           uint64
	OwnerPID              uint64
	OwnerPIDKnown         bool
	Commands              []Command
	CommandsIncomplete    bool
}

// What a candidate history at Address showed, rule by rule (S33 5). Err is
// the first rule that failed.
type Verdict struct {
	Address uint64
	Rule    string
	Err     error
}

func (v Verdict) Accepted() bool { return v.Err == nil }

const (
	RuleLinked      = "H1 node links"
	RuleBufferSize  = "H2 buffer size"
	RuleCommandSpan = "H3 command vector"
	RuleCount       = "H4 command count"
	RuleApplication = "H5 application"
	RuleRecall      = "H6 recall position"
)

func (l *Layout) commandCount(s Space, node uint64) (vectorSpan, uint64, error) {
	v, err := l.vectorAt(s, s.member(node, l.history.commands), l.text.size)
	if err != nil {
		return v, 0, err
	}
	return v, v.count(l.text.size), nil
}

// want 0 accepts any nonzero buffer size: a history reached through its
// console's list is checked by that list, not by a searched value.
func (l *Layout) InspectHistory(s Space, node uint64, want uint64, b limits.Limits) Verdict {
	fail := func(rule string, err error) Verdict {
		return Verdict{Address: node, Rule: rule, Err: err}
	}
	if err := l.linkedNode(s, node); err != nil {
		return fail(RuleLinked, err)
	}
	return l.InspectHistoryShape(s, node, want, b)
}

// Every rule but H1, for a history that may no longer be on a list.
func (l *Layout) InspectHistoryShape(s Space, node uint64, want uint64, b limits.Limits) Verdict {
	fail := func(rule string, err error) Verdict {
		return Verdict{Address: node, Rule: rule, Err: err}
	}
	size, err := s.value(node, l.history.capacity)
	if err != nil {
		return fail(RuleBufferSize, err)
	}
	if size <= 0 || want != 0 && uint64(size) != want {
		return fail(RuleBufferSize, fmt.Errorf("history 0x%x: buffer size %d: %w", node, size, ErrCapacity))
	}
	_, count, err := l.commandCount(s, node)
	if err != nil {
		return fail(RuleCommandSpan, err)
	}
	if count > uint64(size) {
		return fail(RuleCount, fmt.Errorf("history 0x%x: %d commands, buffer size %d: %w", node, count, size, ErrHistoryFull))
	}
	app, err := l.wideString(s, s.member(node, l.history.application), b.MaxTextBytes)
	if err != nil {
		return fail(RuleApplication, err)
	}
	if app.Length == 0 {
		return fail(RuleApplication, fmt.Errorf("history 0x%x: %w", node, ErrNoApplication))
	}
	pos, err := s.value(node, l.history.lastDisplayed)
	if err != nil {
		return fail(RuleRecall, err)
	}
	if pos < -1 || pos >= int64(max(count, 1)) {
		return fail(RuleRecall, fmt.Errorf("history 0x%x: recall position %d, %d commands: %w", node, pos, count, ErrRecallPosition))
	}
	return Verdict{Address: node}
}

// Called only on a history InspectHistory accepted.
func (l *Layout) ReadHistory(s Space, node uint64, b limits.Limits) History {
	h := History{Address: node}
	if v, err := s.value(node, l.history.capacity); err == nil {
		h.BufferSize = uint64(v)
	}
	if v, err := s.value(node, l.history.lastDisplayed); err == nil {
		h.RecallPosition = v
	}
	if app, err := l.wideString(s, s.member(node, l.history.application), b.MaxTextBytes); err == nil {
		h.Application = app.Text
	} else {
		h.ApplicationUnreadable = true
	}
	if owner, err := s.pointer(s.member(node, l.history.process)); err == nil {
		h.OwnerRecord = owner
		if pid, err := l.recordPID(s, owner); err == nil {
			h.OwnerPID, h.OwnerPIDKnown = pid, true
		}
	}
	v, count, err := l.commandCount(s, node)
	if err != nil {
		h.CommandsIncomplete = true
		return h
	}
	if b.MaxRowsPerObject > 0 && count > uint64(b.MaxRowsPerObject) {
		count, h.CommandsIncomplete = uint64(b.MaxRowsPerObject), true
	}
	for i := range count {
		at := v.Begin + i*l.text.size
		c := Command{Index: int(i), Address: at}
		if w, err := l.wideString(s, at, b.MaxTextBytes); err == nil {
			c.Text = w.Text
		} else {
			c.Unreadable = true
		}
		h.Commands = append(h.Commands, c)
	}
	return h
}

// An attached process's record: the history's owner member points at one
// (S33 M7).
func (l *Layout) recordPID(s Space, record uint64) (uint64, error) {
	if record == 0 {
		return 0, fmt.Errorf("null record: %w", ErrOutside)
	}
	pid, err := s.value(record, l.process.pid)
	if err != nil {
		return 0, err
	}
	return uint64(pid), nil
}
