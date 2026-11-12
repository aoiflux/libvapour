package timeline

import (
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

func TestCompareOrdersByTimeThenEveryOtherField(t *testing.T) {
	base := Entry{Time: t1, Event: Created, Tool: "b", Field: "F", Subject: "s", Address: 2, Physical: 2}
	later := []Entry{
		{Time: t2, Event: Created, Tool: "a", Field: "A", Subject: "a"},
		{Time: t1, Event: Created, Tool: "c", Field: "A", Subject: "a"},
		{Time: t1, Event: Created, Tool: "b", Field: "G", Subject: "a"},
		{Time: t1, Event: Created, Tool: "b", Field: "F", Subject: "t"},
		{Time: t1, Event: Created, Tool: "b", Field: "F", Subject: "s", Address: 3},
		{Time: t1, Event: Created, Tool: "b", Field: "F", Subject: "s", Address: 2, Physical: 3},
		{Time: t1, Event: Exited, Tool: "b", Field: "F", Subject: "s", Address: 2, Physical: 2},
	}
	for _, e := range later {
		if Compare(base, e) >= 0 || Compare(e, base) <= 0 {
			t.Errorf("%+v does not sort after %+v", e, base)
		}
	}
	if Compare(base, base) != 0 {
		t.Error("an entry is not equal to itself")
	}
	if Compare(Entry{Time: t1.In(time.FixedZone("x", 7200))}, Entry{Time: t1}) != 0 {
		t.Error("the same instant in two zones compares unequal")
	}
}

func TestSortGivesOneOrderWhateverTheInputOrder(t *testing.T) {
	var entries []Entry
	for i := range 200 {
		entries = append(entries, Entry{Time: t1.Add(time.Duration(i%7) * time.Second), Event: Created,
			Tool: string(rune('a' + i%3)), Field: "F", Subject: string(rune('a' + i%5))})
	}
	want := slices.Clone(entries)
	Sort(want)
	rng := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		got := slices.Clone(entries)
		rng.Shuffle(len(got), func(i, j int) { got[i], got[j] = got[j], got[i] })
		Sort(got)
		if !slices.Equal(got, want) {
			t.Fatal("the order depends on the input order")
		}
	}
	if !slices.IsSortedFunc(want, Compare) {
		t.Error("not sorted")
	}
}

func TestSortKeepsTheSourceOrderOfEqualEntries(t *testing.T) {
	a := Entry{Time: t1, Event: Created, Tool: "t", Subject: "s"}
	entries := []Entry{a, a, a}
	entries[0].Time = t1.In(time.FixedZone("first", 60))
	Sort(entries)
	if entries[0].Time.Location().String() != "first" {
		t.Error("equal entries were reordered")
	}
}

func TestBeforeEpoch(t *testing.T) {
	if !BeforeEpoch(time.Unix(-1, 999999999)) || BeforeEpoch(time.Unix(0, 0)) || !BeforeEpoch(t3) {
		t.Error("epoch boundary")
	}
}
