package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/timeline"
)

func TestTheToolsFlagGivesOnlyRealWords(t *testing.T) {
	if got := words(" , "); got != nil {
		t.Errorf("words(\" , \") = %q", got)
	}
	if got := words("any.process.list, windows.thread.list,,scan"); !slices.Equal(got,
		[]string{"any.process.list", "windows.thread.list", "scan"}) {
		t.Errorf("words = %q", got)
	}
}

func TestOptionsAskOnlyForWhatTheFlagsName(t *testing.T) {
	if got := options(nil, ""); len(got) != 0 {
		t.Errorf("no flags gave options %v", got)
	}
	got := options([]string{"scan"}, "out")
	if !slices.Equal(got[timeline.OptionToolFilter].([]string), []string{"scan"}) ||
		got[timeline.OptionCreateBodyfile] != true || got[tools.OptionOutputDir] != "out" {
		t.Errorf("options = %v", got)
	}
}

func TestAnEntryPrintsItsTimeFirst(t *testing.T) {
	var out strings.Builder
	printEntries(&out, []timeline.Entry{{
		Time: time.Date(2026, 1, 30, 8, 26, 26, 0, time.UTC), Event: timeline.Created,
		Tool: "any.process.list", Field: "CreateTime", Subject: "process explorer.exe pid 4348",
	}})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if f := strings.Fields(lines[1]); !slices.Equal(f[:4], []string{"2026-01-30T08:26:26Z", string(timeline.Created),
		"any.process.list", "CreateTime"}) {
		t.Errorf("entry printed %q", lines[1])
	}
}
