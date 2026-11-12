package registryhive

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/extract"
)

const fuzzCellAddr = 0x10000

func fuzzView(b []byte, gapAt, gapLen uint16) cellView {
	c := cellView{index: 0x20, addr: fuzzCellAddr, b: b}
	if gapLen > 0 {
		c.gaps = extract.GapMap{{Start: fuzzCellAddr + uint64(gapAt), Length: uint64(gapLen)}}
	}
	return c
}

func fuzzLayout(t testing.TB) *layout {
	l, err := loadLayout(fxTable())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func FuzzDecodeKey(f *testing.F) {
	nk := make([]byte, 0x50)
	copy(nk, sigKeyNode)
	binary.LittleEndian.PutUint16(nk[2:], keyNameCompressed)
	binary.LittleEndian.PutUint16(nk[0x48:], 4)
	copy(nk[0x4c:], "ROOT")
	f.Add(nk, uint16(0), uint16(0))
	f.Add(nk, uint16(0x40), uint16(0x10))
	l := fuzzLayout(f)
	f.Fuzz(func(t *testing.T, b []byte, gapAt, gapLen uint16) {
		k, err := decodeKey(fuzzView(b, gapAt, gapLen), l.key)
		if err != nil {
			return
		}
		if !k.NameUnreadable && len([]rune(k.Name)) > maxKeyNameChars {
			t.Fatalf("name of %d characters", len([]rune(k.Name)))
		}
	})
}

func FuzzDecodeValue(f *testing.F) {
	vk := make([]byte, 0x18)
	copy(vk, sigValue)
	binary.LittleEndian.PutUint16(vk[2:], 1)
	binary.LittleEndian.PutUint32(vk[4:], 4|dataResident)
	binary.LittleEndian.PutUint16(vk[0x10:], valueNameCompressed)
	vk[0x14] = 'x'
	f.Add(vk, uint16(0), uint16(0))
	l := fuzzLayout(f)
	f.Fuzz(func(t *testing.T, b []byte, gapAt, gapLen uint16) {
		v, _, err := decodeValue(fuzzView(b, gapAt, gapLen), l.value)
		if err != nil {
			return
		}
		if v.Length&dataResident != 0 {
			t.Fatal("resident bit left in the length")
		}
		_ = renderData(v.Type, b)
	})
}

func FuzzDecodeIndex(f *testing.F) {
	lh := []byte{'l', 'h', 2, 0, 0x80, 0, 0, 0, 1, 2, 3, 4, 0xe0, 0, 0, 0, 5, 6, 7, 8}
	f.Add(lh, uint16(0), uint16(0))
	f.Add([]byte("ri\x01\x00\x20\x00\x00\x00"), uint16(4), uint16(2))
	l := fuzzLayout(f)
	f.Fuzz(func(t *testing.T, b []byte, gapAt, gapLen uint16) {
		c := fuzzView(b, gapAt, gapLen)
		kind, count, err := decodeIndexHead(c, l.index)
		if err != nil {
			return
		}
		cells, complete := decodeIndexEntries(c, l.index, kind, count)
		if len(cells) > int(count) || complete && len(cells) != int(count) {
			t.Fatalf("%d cells of %d, complete %v", len(cells), count, complete)
		}
	})
}

// Arbitrary stable storage behind a valid map: the walk must end and never
// list a key twice under one parent.
func FuzzHiveWalk(f *testing.F) {
	img := newFxImage()
	h, _ := standardHive(img)
	f.Add(h.storage[0].data[fxRootCellSize:])
	f.Fuzz(func(t *testing.T, body []byte) {
		img := newFxImage()
		h := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\F`})
		h.storage[0].data = append(h.storage[0].data, body[:min(len(body), 3*fxBlock)]...)
		h.root = fxRootCellSize
		h.commit()
		l, err := NewHiveLayer(img.context(nil), h.cmhive)
		if err != nil {
			t.Fatal(err)
		}
		root, err := l.KeyNode(fxRootCellSize)
		if err != nil {
			return
		}
		var walk func(k *KeyNode, depth int)
		walk = func(k *KeyNode, depth int) {
			if depth > 8 {
				return
			}
			keys, _ := l.SubkeysChecked(k)
			once := map[uint32]bool{}
			for _, sub := range keys {
				if once[sub.CellIndex] {
					t.Fatalf("cell 0x%x listed twice under 0x%x", sub.CellIndex, k.CellIndex)
				}
				once[sub.CellIndex] = true
				walk(sub, depth+1)
			}
			l.ValuesChecked(k)
			l.ClassData(k)
		}
		walk(root, 0)
	})
}
