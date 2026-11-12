package timeline

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

type Event string

const (
	Created  Event = "created"
	Exited   Event = "exited"
	Loaded   Event = "loaded"
	Unloaded Event = "unloaded"
	Modified Event = "modified"
	Accessed Event = "accessed"
	Changed  Event = "changed"
	Written  Event = "written"
	Ran      Event = "ran"
	Launched Event = "launched"
	Linked   Event = "linked"
	Entered  Event = "entered"
	Booted   Event = "booted"
)

type Entry struct {
	Time     time.Time
	Event    Event
	Tool     string
	Field    string
	Subject  string
	Address  uint64
	Physical uint64
}

type SourceSummary struct {
	Tool        string
	Rows        int
	Entries     int
	Absent      int
	BeforeEpoch int
	Elapsed     time.Duration
	Failure     error
}

type Result struct {
	Entries []Entry
	Sources []SourceSummary
}

func Compare(a, b Entry) int {
	if c := a.Time.Compare(b.Time); c != 0 {
		return c
	}
	if c := strings.Compare(a.Tool, b.Tool); c != 0 {
		return c
	}
	if c := strings.Compare(a.Field, b.Field); c != 0 {
		return c
	}
	if c := strings.Compare(a.Subject, b.Subject); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Address, b.Address); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Physical, b.Physical); c != 0 {
		return c
	}
	return strings.Compare(string(a.Event), string(b.Event))
}

// Stable, so entries equal in every field keep the order their sources gave.
func Sort(entries []Entry) { slices.SortStableFunc(entries, Compare) }

var unixEpoch = time.Unix(0, 0).UTC()

// A time before the epoch has no defined seconds-since-the-epoch value.
func BeforeEpoch(t time.Time) bool { return t.Before(unixEpoch) }
