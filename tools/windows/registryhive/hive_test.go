package registryhive

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
)

func keyNames(keys []*KeyNode) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.Name
	}
	return out
}

func TestACellIndexWalksDirectoryTableAndEntryWithTheFlagBitsCleared(t *testing.T) {
	img := newFxImage()
	h, cells := standardHive(img)
	l := h.layer(t, img.context(nil))
	for _, c := range []uint32{h.root, cells["Alpha"], cells["Gamma"]} {
		got, err := l.cellAddress(c)
		if err != nil {
			t.Fatal(err)
		}
		if want := h.address(c); got != want {
			t.Errorf("cell 0x%x at 0x%x, want 0x%x", c, got, want)
		}
	}
}

func TestACellPastItsStorageOrWithoutAMapEntryIsRefused(t *testing.T) {
	img := newFxImage()
	h, _ := standardHive(img)
	l := h.layer(t, img.context(nil))
	if _, err := l.cellAddress(0x7ffff000); !errors.Is(err, ErrCellOutside) {
		t.Errorf("outside: %v", err)
	}
	img.mem.u64(h.storage[0].mapD, 0)
	l = h.layer(t, img.context(nil))
	if _, err := l.cellAddress(h.root); !errors.Is(err, ErrCellUnmapped) {
		t.Errorf("null table: %v", err)
	}
}

func TestAFreeCellIsNotRead(t *testing.T) {
	img := newFxImage()
	h, cells := standardHive(img)
	img.mem.u32(h.address(cells["Beta"]), 0x60)
	l := h.layer(t, img.context(nil))
	if _, err := l.KeyNode(cells["Beta"]); !errors.Is(err, ErrCellFree) {
		t.Fatalf("free cell: %v", err)
	}
	root, _ := l.KeyNode(h.root)
	keys, complete := l.SubkeysChecked(root)
	if complete || !slices.Equal(keyNames(keys), []string{"Alpha", "Gamma"}) {
		t.Errorf("subkeys %v complete %v", keyNames(keys), complete)
	}
}

func TestBinHeaderCheckingComparesTheSignatureAndTheFileOffset(t *testing.T) {
	img := newFxImage()
	h, _ := standardHive(img)
	l := h.layer(t, img.context(nil))
	l.SetBinValidation(true)
	if _, err := l.KeyNode(h.root); err != nil {
		t.Fatalf("whole bin: %v", err)
	}
	img.mem.u32(h.storage[0].bin+4, 0x2000)
	l.SetBinValidation(true)
	if _, err := l.KeyNode(h.root); !errors.Is(err, ErrBinHeader) {
		t.Errorf("wrong FileOffset: %v", err)
	}
	l.SetBinValidation(false)
	if _, err := l.KeyNode(h.root); err != nil {
		t.Errorf("checking off: %v", err)
	}
}

func TestKeyNamesDecodeInBothEncodings(t *testing.T) {
	img := newFxImage()
	_, cells := standardHive(img)
	l := img.hives[0].layer(t, img.context(nil))
	for name, want := range map[string]string{"Alpha": "Alpha", "Beta": "Beta"} {
		k, err := l.KeyNode(cells[name])
		if err != nil || k.Name != want || k.NameUnreadable {
			t.Errorf("%s: %+v %v", name, k, err)
		}
	}
}

func TestAKeyNameThatBreaksALearnRuleIsNotTaken(t *testing.T) {
	img := newFxImage()
	h := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\X`})
	h.root = h.key(0, fxKey{name: "ROOT", flags: keyHiveRoot})
	long := h.key(0, fxKey{name: strings.Repeat("k", maxKeyNameChars+1)})
	slash := h.key(0, fxKey{name: `a\b`})
	odd := h.key(0, fxKey{name: "ab", utf16Name: true})
	binary.LittleEndian.PutUint16(h.payload(odd)[0x48:], 3)
	h.commit()
	l := h.layer(t, img.context(nil))
	for _, c := range []uint32{long, slash, odd} {
		k, err := l.KeyNode(c)
		if err != nil || !k.NameUnreadable || k.Name != "" {
			t.Errorf("cell 0x%x: %+v %v", c, k, err)
		}
	}
}

func TestAMemberOnAMissingPageIsMarkedAndTheRestRead(t *testing.T) {
	img := newFxImage()
	h := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\X`})
	h.root = h.key(0, fxKey{name: "ROOT", flags: keyHiveRoot})
	for len(h.storage[0].data)%fxBlock != fxBlock-0x10 {
		h.storage[0].data = append(h.storage[0].data, 0)
	}
	k := h.key(0, fxKey{name: "Split", lastWrite: 5})
	h.commit()
	img.mem.drop(h.address(k) + 0x40)
	l := h.layer(t, img.context(nil))
	node, err := l.KeyNode(k)
	if err != nil {
		t.Fatal(err)
	}
	if node.LastWriteUnreadable || node.LastWrite != 5 || !node.SubkeysUnreadable || !node.NameUnreadable || !node.ValuesUnreadable {
		t.Errorf("split key %+v", node)
	}
}

func TestSubkeysCoverBothStoragesInListOrder(t *testing.T) {
	img := newFxImage()
	h, _ := standardHive(img)
	l := h.layer(t, img.context(nil))
	root, err := l.KeyNode(h.root)
	if err != nil {
		t.Fatal(err)
	}
	keys, complete := l.SubkeysChecked(root)
	if !complete || !slices.Equal(keyNames(keys), []string{"Alpha", "Beta", "Gamma"}) {
		t.Errorf("subkeys %v complete %v", keyNames(keys), complete)
	}
	if got := l.Subkeys(root); len(got) != 3 {
		t.Errorf("Subkeys %d", len(got))
	}
}

func TestAnIndexRootListsLeavesButNotAnotherRoot(t *testing.T) {
	img := newFxImage()
	h := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\X`})
	h.root = h.key(0, fxKey{name: "ROOT", flags: keyHiveRoot})
	a := h.key(0, fxKey{name: "A", parent: h.root})
	b := h.key(0, fxKey{name: "B", parent: h.root})
	c := h.key(0, fxKey{name: "C", parent: h.root})
	inner := h.index(0, sigRoot, h.index(0, sigFastLeaf, c))
	top := h.index(0, sigRoot, h.index(0, sigFastLeaf, a), h.index(0, sigHashLeaf, b), inner)
	h.setU32(h.root, 0x14, 3)
	h.setU32(h.root, 0x1c, top)
	h.commit()
	l := h.layer(t, img.context(nil))
	root, _ := l.KeyNode(h.root)
	keys, complete := l.SubkeysChecked(root)
	if complete || !slices.Equal(keyNames(keys), []string{"A", "B"}) {
		t.Errorf("subkeys %v complete %v", keyNames(keys), complete)
	}
}

func TestAListThatBreaksARuleIsIncomplete(t *testing.T) {
	cases := map[string]func(h *fxHive, kids []uint32) uint32{
		"unknown signature": func(h *fxHive, kids []uint32) uint32 { return h.index(0, "li", kids...) },
		"wrong parent": func(h *fxHive, kids []uint32) uint32 {
			h.setU32(kids[1], 0x10, 0x1234)
			return h.index(0, sigHashLeaf, kids...)
		},
		"repeated entry": func(h *fxHive, kids []uint32) uint32 { return h.index(0, sigHashLeaf, kids[0], kids[0], kids[1]) },
		"not a key node": func(h *fxHive, kids []uint32) uint32 {
			return h.index(0, sigHashLeaf, kids[0], h.index(0, sigHashLeaf))
		},
		"count above the list": func(h *fxHive, kids []uint32) uint32 {
			h.setU32(h.root, 0x14, 3)
			return h.index(0, sigHashLeaf, kids...)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			img := newFxImage()
			h := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\X`})
			h.root = h.key(0, fxKey{name: "ROOT", flags: keyHiveRoot})
			kids := []uint32{h.key(0, fxKey{name: "A", parent: h.root}), h.key(0, fxKey{name: "B", parent: h.root})}
			h.setU32(h.root, 0x14, 2)
			h.setU32(h.root, 0x1c, build(h, kids))
			h.commit()
			l := h.layer(t, img.context(nil))
			root, _ := l.KeyNode(h.root)
			if _, complete := l.SubkeysChecked(root); complete {
				t.Error("list reported complete")
			}
		})
	}
}

func TestTheSubkeyCapCutsTheList(t *testing.T) {
	img := newFxImage()
	h, _ := standardHive(img)
	ctx := img.context(nil)
	ctx.Limits = limits.Limits{MaxListEntries: 2}
	l := h.layer(t, ctx)
	root, _ := l.KeyNode(h.root)
	keys, complete := l.SubkeysChecked(root)
	if complete || len(keys) != 2 {
		t.Errorf("%d keys complete %v", len(keys), complete)
	}
}

func TestValuesReadResidentCellAndUnnamedData(t *testing.T) {
	img := newFxImage()
	h, cells := standardHive(img)
	l := h.layer(t, img.context(nil))
	k, _ := l.KeyNode(cells["Alpha"])
	if k.LastWrite != 133000000000000000 {
		t.Errorf("last write %d", k.LastWrite)
	}
	vals, complete := l.ValuesChecked(k)
	if !complete || len(vals) != 3 {
		t.Fatalf("%d values complete %v", len(vals), complete)
	}
	if v := vals[0]; v.Name != "Path" || v.Data != `C:\x` || v.Unreadable() {
		t.Errorf("Path %+v", v)
	}
	if v := vals[1]; v.Name != "Count" || v.Data != "0x7" || len(v.Raw) != 4 {
		t.Errorf("Count %+v", v)
	}
	if v := vals[2]; v.Name != unnamedValueName || v.Data != "01 02 03 04 05 06" {
		t.Errorf("unnamed %+v", v)
	}
	v, found, unreadable := l.ValueByNameChecked(k, "count")
	if !found || unreadable || v.Name != "Count" {
		t.Errorf("by name %+v %v %v", v, found, unreadable)
	}
	if _, ok := l.ValueByName(k, "absent"); ok {
		t.Error("absent value found")
	}
	if len(l.Values(k)) != 3 {
		t.Error("Values")
	}
}

func TestResidentDataLongerThanTheFieldIsUnreadable(t *testing.T) {
	img := newFxImage()
	h := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\X`})
	v := h.valueCell(0, fxValue{name: "x", typ: regBinary, length: 5 | dataResident, data: 1})
	h.root = h.key(0, fxKey{name: "ROOT", flags: keyHiveRoot, values: 1, valueList: h.valueList(0, v)})
	h.commit()
	l := h.layer(t, img.context(nil))
	root, _ := l.KeyNode(h.root)
	vals, _ := l.ValuesChecked(root)
	if len(vals) != 1 || !vals[0].Unreadable() {
		t.Errorf("%+v", vals)
	}
}

func bigValue(h *fxHive, data []byte) uint32 {
	var segs []uint32
	for off := 0; off < len(data); off += bigDataSegmentBytes {
		seg := make([]byte, bigDataSegmentBytes+4)
		copy(seg, data[off:min(off+bigDataSegmentBytes, len(data))])
		segs = append(segs, h.cell(0, seg))
	}
	list := h.valueList(0, segs...)
	head := make([]byte, 8)
	copy(head, sigBigData)
	binary.LittleEndian.PutUint16(head[2:], uint16(len(segs)))
	binary.LittleEndian.PutUint32(head[4:], list)
	db := h.cell(0, head)
	return h.valueCell(0, fxValue{name: "Big", typ: regBinary, length: uint32(len(data)), data: db})
}

func TestBigDataJoinsSegmentsOf16344Bytes(t *testing.T) {
	data := make([]byte, 2*bigDataSegmentBytes+100)
	for i := range data {
		data[i] = byte(i % 251)
	}
	img := newFxImage()
	h := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\X`})
	v := bigValue(h, data)
	h.root = h.key(0, fxKey{name: "ROOT", flags: keyHiveRoot, values: 1, valueList: h.valueList(0, v)})
	h.commit()
	l := h.layer(t, img.context(nil))
	root, _ := l.KeyNode(h.root)
	vals, _ := l.ValuesChecked(root)
	if len(vals) != 1 || vals[0].Unreadable() || !slices.Equal(vals[0].Raw, data) {
		t.Fatalf("big value: %d values, raw %d bytes", len(vals), len(vals[0].Raw))
	}

	listCell := binary.LittleEndian.Uint32(h.payload(binary.LittleEndian.Uint32(h.payload(v)[8:]))[4:])
	last := binary.LittleEndian.Uint32(h.payload(listCell)[8:])
	img.mem.drop(h.address(last) + 4)
	l = h.layer(t, img.context(nil))
	root, _ = l.KeyNode(h.root)
	vals, _ = l.ValuesChecked(root)
	if len(vals) != 1 || !vals[0].Unreadable() || len(vals[0].Raw) <= bigDataSegmentBytes ||
		!slices.Equal(vals[0].Raw, data[:len(vals[0].Raw)]) {
		t.Errorf("missing page: raw %d bytes", len(vals[0].Raw))
	}
}

func TestDataText(t *testing.T) {
	cases := []struct {
		typ  uint32
		raw  []byte
		want string
	}{
		{regSZ, utf16le("abc\x00junk"), "abc"},
		{regExpandSZ, utf16le("%PATH%\x00"), "%PATH%"},
		{regLink, utf16le(`\Registry\Machine\X`), `\Registry\Machine\X`},
		{regMultiSZ, utf16le("one\x00two\x00\x00three\x00"), "one\ntwo"},
		{regDWORD, []byte{0x78, 0x56, 0x34, 0x12}, "0x12345678"},
		{regDWORDBigEndian, []byte{0x12, 0x34, 0x56, 0x78}, "0x12345678"},
		{regQWORD, []byte{8, 7, 6, 5, 4, 3, 2, 1}, "0x102030405060708"},
		{regDWORD, []byte{1, 2}, "01 02"},
		{regBinary, []byte{0xab, 0x01}, "ab 01"},
		{regNone, nil, ""},
		{regResourceList, []byte{0}, "00"},
	}
	for _, c := range cases {
		if got := renderData(c.typ, c.raw); got != c.want {
			t.Errorf("type %d %x: %q, want %q", c.typ, c.raw, got, c.want)
		}
	}
}

func TestClassDataReadsOrIsNil(t *testing.T) {
	img := newFxImage()
	h := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\X`})
	class := h.cell(0, utf16le("CLS"))
	h.root = h.key(0, fxKey{name: "ROOT", flags: keyHiveRoot, class: class, classBytes: 6})
	h.commit()
	l := h.layer(t, img.context(nil))
	root, _ := l.KeyNode(h.root)
	if got := l.ClassData(root); !slices.Equal(got, utf16le("CLS")) {
		t.Errorf("class %x", got)
	}
	if l.ClassData(&KeyNode{}) != nil {
		t.Error("class data of a key without one")
	}
}

func TestTheRootComesFromTheBaseBlockThenTheKcbThenTheFirstCell(t *testing.T) {
	img := newFxImage()
	h, _ := standardHive(img)
	l := h.layer(t, img.context(nil))
	if r, err := l.RootCell(); err != nil || r != h.root {
		t.Fatalf("base block: 0x%x %v", r, err)
	}

	img.mem.u32(h.base, 0)
	kcb := img.alloc(0x138)
	img.mem.u64(h.cmhive+fxRootKcb, kcb)
	img.mem.u32(kcb+fxKcbKeyCell, h.root)
	if r, err := h.layer(t, img.context(nil)).RootCell(); err != nil || r != h.root {
		t.Fatalf("kcb: 0x%x %v", r, err)
	}

	img.mem.u64(h.cmhive+fxRootKcb, 0)
	*img.diags = nil
	if r, err := h.layer(t, img.context(nil)).RootCell(); err != nil || r != fxRootCellSize {
		t.Fatalf("first cell: 0x%x %v", r, err)
	}
	if len(*img.diags) != 1 || !strings.Contains((*img.diags)[0], "first after the bin header") {
		t.Errorf("diagnostics %q", *img.diags)
	}

	binary.LittleEndian.PutUint16(h.payload(h.root)[2:], keyNameCompressed)
	img.mem.write(h.address(h.root)+4, h.payload(h.root)[:4])
	if _, err := h.layer(t, img.context(nil)).RootCell(); !errors.Is(err, ErrNoRootCell) {
		t.Errorf("no root flag: %v", err)
	}
}

func TestOpenKeyTellsAbsentFromUnreadable(t *testing.T) {
	img := newFxImage()
	h, cells := standardHive(img)
	l := h.layer(t, img.context(nil))
	if k, err := l.OpenKey(`\alpha\`); err != nil || k.Name != "Alpha" {
		t.Fatalf("alpha: %v", err)
	}
	if _, err := l.OpenKey(`Delta`); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("absent: %v", err)
	}
	img.mem.u32(h.address(cells["Beta"]), 0x60)
	l = h.layer(t, img.context(nil))
	if _, err := l.OpenKey(`Delta`); !errors.Is(err, ErrKeyUnreadable) {
		t.Errorf("incomplete list: %v", err)
	}
	if k, err := l.OpenKey(`Gamma`); err != nil || k.Name != "Gamma" {
		t.Errorf("volatile key: %v", err)
	}
}

func TestFindSubkeyAndFindValueLeaveTheAnswerOpenOnAnUnreadName(t *testing.T) {
	keys := []*KeyNode{{Name: "A"}, {NameUnreadable: true}}
	if k, found, maybe := FindSubkey(keys, true, "a"); !found || maybe || k.Name != "A" {
		t.Error("found")
	}
	if _, found, maybe := FindSubkey(keys, true, "b"); found || !maybe {
		t.Error("unread name")
	}
	if _, found, maybe := FindSubkey(keys[:1], true, "b"); found || maybe {
		t.Error("absent")
	}
	if _, found, maybe := FindSubkey(keys[:1], false, "b"); found || !maybe {
		t.Error("incomplete")
	}
	vals := []Value{{Name: "X"}, {NameUnreadable: true}}
	if _, found, maybe := FindValue(vals, true, "y"); found || !maybe {
		t.Error("value unread name")
	}
	if v, found, _ := FindValue(vals, true, "x"); !found || v.Name != "X" {
		t.Error("value found")
	}
}

func TestTheCurrentControlSetComesFromSelect(t *testing.T) {
	img := newFxImage()
	h := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\SYSTEM`})
	h.root = h.key(0, fxKey{name: "ROOT", flags: keyHiveRoot})
	sel := h.key(0, fxKey{name: "Select", parent: h.root, values: 1,
		valueList: h.valueList(0, h.value(0, "Current", regDWORD, []byte{2, 0, 0, 0}))})
	h.setU32(h.root, 0x14, 1)
	h.setU32(h.root, 0x1c, h.index(0, sigHashLeaf, sel))
	h.commit()
	l := h.layer(t, img.context(nil))
	if name, read := CurrentControlSetChecked(l); name != "ControlSet002" || !read {
		t.Errorf("%s %v", name, read)
	}
	img.mem.drop(h.address(sel))
	l = h.layer(t, img.context(nil))
	*img.diags = nil
	if name := CurrentControlSet(l); name != defaultControlSet || len(*img.diags) != 1 {
		t.Errorf("%s %q", name, *img.diags)
	}
	if name, read := CurrentControlSetChecked(nil); name != defaultControlSet || read {
		t.Error("nil hive")
	}
}

func TestLastPathComponent(t *testing.T) {
	for in, want := range map[string]string{`\a\b\SYSTEM`: "SYSTEM", `a/b/`: "b", "x": "x", "": ""} {
		if got := LastPathComponent(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestAHiveWithoutItsSignatureOrStorageIsRefused(t *testing.T) {
	img := newFxImage()
	h, _ := standardHive(img)
	img.mem.u32(h.cmhive, 0)
	if _, err := NewHiveLayer(img.context(nil), h.cmhive); !errors.Is(err, ErrNotHive) {
		t.Errorf("signature: %v", err)
	}
	if _, err := NewHiveLayer(img.context(nil), 0x1000); !errors.Is(err, ErrNotHive) {
		t.Errorf("unread: %v", err)
	}
}

func TestTheLayoutComesFromTheTable(t *testing.T) {
	tbl := fxTable()
	if _, err := loadLayout(tbl); err != nil {
		t.Fatal(err)
	}
	broken := fxTable()
	broken.AddStruct(symbols.StructType{Name: "_HMAP_TABLE", Size: 0x1800, Fields: []symbols.Field{fxArray("Table", 0, 256, "_HMAP_ENTRY")}})
	if _, err := loadLayout(broken); !errors.Is(err, ErrLayout) {
		t.Errorf("short table: %v", err)
	}
	if _, err := loadLayout(nil); !errors.Is(err, ErrLayout) {
		t.Errorf("nil table: %v", err)
	}
}
