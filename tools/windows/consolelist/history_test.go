package consolelist

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

func TestALoneHistoryIsFoundByItsBufferSize(t *testing.T) {
	for _, build := range []uint64{19041} {
		l, err := LayoutFor(true, 10, 0, build)
		if err != nil {
			t.Fatal(err)
		}
		f := newFixture(l)
		owner := f.record(77)
		node := f.loneHistory(historySpec{app: "powershell.exe", commands: []string{"Get-Process", "ipconfig /all"}, recall: -1, owner: owner})
		f.m.put(fixtureHeap+0x100000, l.history.capacity, 50)
		found, err := l.FindHistories(f.space(), []uint64{50}, limits.Default())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(found.Accepted, []uint64{node}) || found.RejectedBy[RuleLinked] != 1 {
			t.Fatalf("build %d: accepted %x, rejected %v", build, found.Accepted, found.RejectedBy)
		}
		h := l.ReadHistory(f.space(), node, limits.Default())
		if h.Application != "powershell.exe" || h.RecallPosition != -1 || h.OwnerPID != 77 || !h.OwnerPIDKnown ||
			!reflect.DeepEqual(commandTexts(h), []string{"Get-Process", "ipconfig /all"}) {
			t.Errorf("build %d: history %+v", build, h)
		}
		if h.Commands[1].Address != h.Commands[0].Address+l.text.size || h.Commands[1].Index != 1 {
			t.Errorf("build %d: command addresses %+v", build, h.Commands)
		}
	}
}

func TestEachHistoryRuleRejectsWhatBreaksIt(t *testing.T) {
	cases := []struct {
		name   string
		rule   string
		err    error
		want   uint64
		mutate func(f *fixture, l *Layout, node uint64)
	}{
		{"unlinked", RuleLinked, ErrListLink, 50, func(f *fixture, l *Layout, node uint64) {
			f.m.u64(node, node)
		}},
		{"other buffer size", RuleBufferSize, ErrCapacity, 25, func(*fixture, *Layout, uint64) {}},
		{"zero buffer size", RuleBufferSize, ErrCapacity, 0, func(f *fixture, l *Layout, node uint64) {
			f.m.put(node+uint64(l.history.capacity.off), l.history.capacity, 0)
		}},
		{"vector out of order", RuleCommandSpan, ErrVectorShape, 50, func(f *fixture, l *Layout, node uint64) {
			f.m.u64(node+uint64(l.history.commands+l.vector.end), 1)
		}},
		{"vector not whole strings", RuleCommandSpan, ErrVectorShape, 50, func(f *fixture, l *Layout, node uint64) {
			at := node + uint64(l.history.commands+l.vector.end)
			end, _ := f.space().pointer(at)
			f.m.u64(at, end-8)
		}},
		{"more commands than the buffer holds", RuleCount, ErrHistoryFull, 0, func(f *fixture, l *Layout, node uint64) {
			f.m.put(node+uint64(l.history.capacity.off), l.history.capacity, 1)
		}},
		{"no application", RuleApplication, ErrNoApplication, 50, func(f *fixture, l *Layout, node uint64) {
			f.m.u64(node+uint64(l.history.application+l.text.length.off), 0)
		}},
		{"recall past the commands", RuleRecall, ErrRecallPosition, 50, func(f *fixture, l *Layout, node uint64) {
			f.m.put(node+uint64(l.history.lastDisplayed.off), l.history.lastDisplayed, 2)
		}},
		{"recall below -1", RuleRecall, ErrRecallPosition, 50, func(f *fixture, l *Layout, node uint64) {
			f.m.put(node+uint64(l.history.lastDisplayed.off), l.history.lastDisplayed, -2)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, l := layout19041Fixture(t)
			node := f.loneHistory(historySpec{app: "cmd.exe", commands: []string{"dir", "cls"}, recall: 0})
			tc.mutate(f, l, node)
			v := l.InspectHistory(f.space(), node, tc.want, limits.Default())
			if v.Accepted() || v.Rule != tc.rule || !errors.Is(v.Err, tc.err) {
				t.Errorf("verdict %s: %v, want %s: %v", v.Rule, v.Err, tc.rule, tc.err)
			}
		})
	}
}

func TestAnEmptyHistoryHasNoCommandsAndRecallsNothing(t *testing.T) {
	f, l := layout19041Fixture(t)
	node := f.loneHistory(historySpec{app: "powershell.exe", recall: -1})
	if v := l.InspectHistory(f.space(), node, 50, limits.Default()); !v.Accepted() {
		t.Fatalf("%s: %v", v.Rule, v.Err)
	}
	h := l.ReadHistory(f.space(), node, limits.Default())
	if len(h.Commands) != 0 || h.CommandsIncomplete || h.OwnerPIDKnown {
		t.Errorf("history %+v", h)
	}
}

func TestACommandThatDoesNotReadIsKeptAndMarked(t *testing.T) {
	f, l := layout19041Fixture(t)
	node := f.loneHistory(historySpec{app: "cmd.exe", commands: []string{"a command long enough for the heap", "ver"}, recall: 0})
	s := f.space()
	begin, _ := s.pointer(node + uint64(l.history.commands+l.vector.begin))
	f.m.u64(begin+uint64(l.text.pointer), 0x40)
	h := l.ReadHistory(s, node, limits.Default())
	if len(h.Commands) != 2 || !h.Commands[0].Unreadable || h.Commands[1].Text != "ver" {
		t.Errorf("commands %+v", h.Commands)
	}
}

func TestCommandsPastMaxRowsPerObjectAreCut(t *testing.T) {
	f, l := layout19041Fixture(t)
	node := f.loneHistory(historySpec{app: "cmd.exe", commands: []string{"1", "2", "3"}, recall: 0})
	b := limits.Default()
	b.MaxRowsPerObject = 2
	h := l.ReadHistory(f.space(), node, b)
	if len(h.Commands) != 2 || !h.CommandsIncomplete {
		t.Errorf("history %+v", h)
	}
}
