package consolelist

import (
	"errors"
	"testing"
)

// Offsets from S67 section 3 (conhost.exe, build 19045, PDB F020B0E2).
var s67Members = map[string]int64{
	"node.next": 0, "node.prev": 8, "node.value": 0x10,
	"history.commands": 0x10, "history.capacity": 0x28, "history.application": 0x30,
	"history.process": 0x50, "history.lastDisplayed": 0x5c, "history.end": 0x60,
	"process.pid": 0x1c,
	"text.chars":  0, "text.pointer": 0, "text.length": 0x10, "text.capacity": 0x18, "text.size": 0x20,
	"vector.begin": 0, "vector.end": 8, "vector.capacityEnd": 0x10,
	"console.screenWidth": 0x20, "console.screenHeight": 0x22,
	"console.historySize": 0x90, "console.historyMax": 0x94,
	"console.processList": 0x558, "console.processCount": 0x560, "console.screenList": 0x570,
	"console.title": 0x698, "console.originalTitle": 0x6d8, "console.activeScreen": 0x718,
	"console.aliases": 0x2310, "console.historyList": 0x2368, "console.historyCount": 0x2370,
	"processNode.process": 0x10, "aliasEntry.name": 0x10, "aliasEntry.aliases": 0x38,
	"alias.source": 0x10, "alias.target": 0x30,
	"screen.textBuffer": 0x38, "screen.next": 0x40,
	"textBuffer.rows": 8, "textBuffer.rowCount": 0x20, "textBuffer.firstRow": 0x58,
	"row.cells": 8, "row.width": 0x50,
}

func TestThe19041LayoutHoldsTheMeasuredOffsets(t *testing.T) {
	for _, build := range []uint64{19041, 19045} {
		l, err := LayoutFor(true, 10, 0, build)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, m := range l.Members() {
			seen[m.Name] = true
			want, ok := s67Members[m.Name]
			if !ok {
				t.Errorf("member %s is not in the measurement", m.Name)
				continue
			}
			if m.Offset != want {
				t.Errorf("%s at 0x%x, want 0x%x", m.Name, m.Offset, want)
			}
		}
		for name := range s67Members {
			if !seen[name] {
				t.Errorf("measured member %s missing", name)
			}
		}
	}
}

func TestTheHistoryFitsInsideItsNodeAndTheSettingsAreAdjacent(t *testing.T) {
	l, _ := LayoutFor(true, 10, 0, 19045)
	h := l.history
	if uint64(h.lastDisplayed.off)+h.lastDisplayed.size > h.size || uint64(h.process)+pointerBytes > h.size {
		t.Errorf("history members overrun the node of %d bytes", h.size)
	}
	if uint64(h.application)+l.text.size > uint64(h.process) {
		t.Error("application string overlaps the owner pointer")
	}
	c := l.console
	if c.historyMax.off != c.historySize.off+int64(c.historySize.size) || c.historySize.off%8 != 0 {
		t.Error("history settings are not an aligned adjacent pair")
	}
	if c.processCount.off != c.processList+pointerBytes || c.historyCount.off != c.historyList+pointerBytes {
		t.Error("a list size does not follow its head")
	}
}

func TestUnmeasuredConhostBuildsAreRefused(t *testing.T) {
	for _, build := range []uint64{14393, 17763, 22000, 22631, 26100} {
		if _, err := LayoutFor(true, 10, 0, build); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("build %d: %v", build, err)
		}
	}
}
