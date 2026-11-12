package timeline

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var allEvents = []Event{Created, Exited, Loaded, Unloaded, Modified, Accessed, Changed, Written, Ran, Launched,
	Linked, Entered, Booted}

func TestEveryEventHasOneBodyColumn(t *testing.T) {
	if len(columnOf) != len(allEvents) {
		t.Fatalf("%d columns for %d events", len(columnOf), len(allEvents))
	}
	for _, ev := range allEvents {
		if _, ok := columnOf[ev]; !ok {
			t.Errorf("%s has no column", ev)
		}
	}
}

func TestBodyLinePutsTheTimeInItsEventColumn(t *testing.T) {
	at := time.Date(2026, 1, 30, 8, 26, 26, 999999900, time.UTC)
	secs := "1769761586"
	for ev, col := range map[Event]int{Accessed: 7, Modified: 8, Changed: 9, Created: 10, Ran: 7, Exited: 8, Booted: 10} {
		line, ok := BodyLine(Entry{Time: at, Event: ev, Tool: "t", Field: "F", Subject: "s"})
		if !ok {
			t.Fatalf("%s: no line", ev)
		}
		f := strings.Split(line, "|")
		if len(f) != 11 {
			t.Fatalf("%s: %d fields in %q", ev, len(f), line)
		}
		for i, v := range f {
			switch {
			case i == 1:
				if v != "t "+string(ev)+" F: s" {
					t.Errorf("%s: name %q", ev, v)
				}
			case i == col:
				if v != secs {
					t.Errorf("%s: column %d = %q, want whole seconds %s", ev, i, v, secs)
				}
			default:
				if v != "0" {
					t.Errorf("%s: column %d = %q, want 0", ev, i, v)
				}
			}
		}
	}
}

func TestBodyLineLeavesOutTimesBeforeTheEpochAndUnknownEvents(t *testing.T) {
	for _, e := range []Entry{
		{Time: time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC), Event: Created},
		{Time: time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC), Event: Created},
		{Event: Created},
		{Time: time.Unix(10, 0), Event: "other"},
		{Time: time.Unix(0, 0), Event: Created},
		{Time: time.Unix(0, 999999999), Event: Created},
	} {
		if line, ok := BodyLine(e); ok {
			t.Errorf("%+v gave %q", e, line)
		}
	}
	if line, ok := BodyLine(Entry{Time: time.Unix(1, 0), Event: Created}); !ok || !strings.HasSuffix(line, "|1") {
		t.Errorf("second 1 is a time: %q %v", line, ok)
	}
}

func TestBodyNameEscapesWhatWouldBreakTheLine(t *testing.T) {
	got := BodyName(Entry{Tool: "t", Event: Entered, Field: "F", Subject: "a|b\nc\rd\x00\x7f\xffé\\x", Address: 0x10})
	want := `t entered F: a\x7cb\x0ac\x0dd\x00\x7f\xffé\x at 0x10`
	if got != want {
		t.Errorf("name %q, want %q", got, want)
	}
	if got := BodyName(Entry{Tool: "t", Event: Created, Field: "F", Subject: "s", Physical: 0x20}); got != "t created F: s physical 0x20" {
		t.Errorf("physical name %q", got)
	}
}

func TestWriteBodyNeverReplacesAFileAndCountsLeftOutEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, BodyfileName), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries := []Entry{
		{Time: time.Unix(5, 0).UTC(), Event: Created, Tool: "t", Field: "F", Subject: "a"},
		{Time: time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC), Event: Created, Tool: "t", Field: "F", Subject: "b"},
	}
	w, err := writeBody(dir, entries, 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if w.name != "timeline-1.body" || w.lines != 1 || w.skipped != 1 {
		t.Errorf("wrote %+v", w)
	}
	data, err := os.ReadFile(filepath.Join(dir, w.name))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "0|t created F: a|0|0|0|0|0|0|0|0|5\n" {
		t.Errorf("body %q", data)
	}
	if kept, _ := os.ReadFile(filepath.Join(dir, BodyfileName)); string(kept) != "keep" {
		t.Errorf("existing file now %q", kept)
	}
}

func TestWriteBodyOverTheLimitLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	entries := []Entry{{Time: time.Unix(5, 0), Event: Created, Tool: "t", Field: "F", Subject: strings.Repeat("x", 100)}}
	if _, err := writeBody(dir, entries, 50, 4); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("error %v, want ErrBodyTooLarge", err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("left %d files", len(left))
	}
}
