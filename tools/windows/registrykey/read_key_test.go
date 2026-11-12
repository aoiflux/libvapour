package registrykey

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

func newLister(path string, recurse, strict bool) (*lister, *[]string) {
	var diags []string
	ctx := tools.Context{Options: map[string]any{"diagnostics": &diags, "strict": strict}}
	return &lister{ctx: ctx, path: path, recurse: recurse}, &diags
}

var id = hiveID{path: `\REGISTRY\MACHINE\SYSTEM`, address: 0x1000}

var fxTime = time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)

func filetime(t time.Time) uint64 { return uint64(t.Unix()+11644473600) * 10_000_000 }

func TestAKeyListsItsSubkeysThenItsValues(t *testing.T) {
	h := registrytest.NewFakeHive("ROOT")
	sel := h.Path(`Select`)
	sel.LastWrite = filetime(fxTime)
	h.Key(sel, "Sub")
	h.Values[sel] = []registryhive.Value{registrytest.DWORD("Current", 1), {Name: "Odd", Type: 0x10001, Raw: []byte{1}, Length: 1}}
	l, _ := newLister(`select`, false, false)
	l.listHive(h, id)
	if len(l.out) != 3 {
		t.Fatalf("items %+v", l.out)
	}
	k, v, odd := l.out[0], l.out[1], l.out[2]
	if k.Kind != KindKey || k.Name != "Sub" || k.Path != "Select" || k.HivePath != id.path || k.HiveAddress != id.address {
		t.Errorf("key item %+v: the path takes the stored names", k)
	}
	if v.Kind != KindValue || v.Name != "Current" || v.Type != "REG_DWORD" || v.TypeCode != 4 || v.Data != "0x1" ||
		!v.LastWrite.Equal(fxTime) {
		t.Errorf("value item %+v", v)
	}
	if odd.Type != "type 0x10001" {
		t.Errorf("an undocumented type is named %q", odd.Type)
	}
}

func TestRecursionGoesDepthFirstAndStopsAtRepeatsAndCycles(t *testing.T) {
	h := registrytest.NewFakeHive("ROOT")
	a := h.Path(`A`)
	b := h.Key(a, "B")
	c := h.Key(b, "C")
	h.Values[c] = []registryhive.Value{registrytest.SZ("v", "x")}
	h.Subkeys[c] = append(h.Subkeys[c], b)
	h.Subkeys[a] = append(h.Subkeys[a], c)
	l, diags := newLister(`A`, true, false)
	l.listHive(h, id)
	var got []string
	for _, it := range l.out {
		got = append(got, string(it.Kind)+":"+it.Path+":"+it.Name)
	}
	want := `key:A:B key:A\B:C key:A\B\C:B value:A\B\C:v key:A:C`
	if strings.Join(got, " ") != want {
		t.Errorf("order %q, want %q", strings.Join(got, " "), want)
	}
	joined := strings.Join(*diags, "\n")
	if !strings.Contains(joined, "its own ancestor") || !strings.Contains(joined, "second parent") {
		t.Errorf("diagnostics %q", *diags)
	}
	if l.out[1].Depth != 1 || l.out[3].Depth != 2 {
		t.Errorf("depths %d %d", l.out[1].Depth, l.out[3].Depth)
	}
}

func TestTheDepthLimitStopsTheWalk(t *testing.T) {
	h := registrytest.NewFakeHive("ROOT")
	k := h.Root
	for i := 0; i < maxLevels+2; i++ {
		k = h.Key(k, "k")
	}
	l, _ := newLister(``, true, true)
	l.listHive(h, id)
	if len(l.out) != maxLevels {
		t.Fatalf("%d items, want %d", len(l.out), maxLevels)
	}
	if !errors.Is(l.firstErr, ErrIncomplete) {
		t.Errorf("err %v", l.firstErr)
	}
}

func TestAMissingOrUnreadableKeyGivesOneItemThatSaysSo(t *testing.T) {
	h := registrytest.NewFakeHive("ROOT")
	h.Path(`A`)
	l, diags := newLister(`A\Missing`, false, false)
	l.listHive(h, id)
	if len(l.out) != 1 || !l.out[0].KeyNotRead || l.out[0].Path != `A\Missing` || !strings.Contains(l.out[0].Reason, "not found") {
		t.Fatalf("items %+v", l.out)
	}
	if l.firstErr != nil || len(*diags) != 1 {
		t.Errorf("a missing key is not a read failure: %v %q", l.firstErr, *diags)
	}
	h.SubkeysIncomplete[h.Root] = true
	l, _ = newLister(`B`, false, false)
	l.listHive(h, id)
	if len(l.out) != 1 || !l.out[0].KeyNotRead || !errors.Is(l.firstErr, ErrIncomplete) {
		t.Fatalf("items %+v err %v", l.out, l.firstErr)
	}
	l, _ = newLister(``, false, false)
	l.listHive(&registrytest.FakeHive{}, id)
	if len(l.out) != 1 || !l.out[0].KeyNotRead {
		t.Fatalf("an unreadable root gives %+v", l.out)
	}
}

func TestIncompleteListsAndUnreadNamesAreReported(t *testing.T) {
	h := registrytest.NewFakeHive("ROOT")
	h.UnnamedKey(h.Root)
	h.ValuesIncomplete[h.Root] = true
	h.Values[h.Root] = []registryhive.Value{{Name: "cut", Type: 3, Raw: []byte{1}, Length: 4}}
	l, diags := newLister(``, true, true)
	l.listHive(h, id)
	if len(l.out) != 2 || !l.out[0].NameUnreadable || !l.out[1].DataUnreadable {
		t.Fatalf("items %+v", l.out)
	}
	if len(*diags) != 2 || !errors.Is(l.firstErr, ErrIncomplete) {
		t.Errorf("diagnostics %q err %v", *diags, l.firstErr)
	}
}

func TestVolatileKeysAreMarked(t *testing.T) {
	k := &registryhive.KeyNode{CellIndex: 0x80000020, LastWriteUnreadable: true}
	w := walk{id: id}
	it := w.keyItem("", 0, k)
	if !it.Volatile || !it.LastWriteUnreadable || !it.LastWrite.IsZero() {
		t.Errorf("%+v", it)
	}
}

func TestOptionsOfTheWrongTypeAreErrors(t *testing.T) {
	ctx := tools.Context{Options: map[string]any{OptionRecurse: 5}}
	if _, err := readOptions(ctx); err == nil {
		t.Fatal("a string recurse option was accepted")
	}
}

func FuzzTypeName(f *testing.F) {
	f.Add(uint32(1))
	f.Add(uint32(0xffff0012))
	f.Fuzz(func(t *testing.T, code uint32) {
		if TypeName(code) == "" {
			t.Fatal("empty type name")
		}
	})
}
