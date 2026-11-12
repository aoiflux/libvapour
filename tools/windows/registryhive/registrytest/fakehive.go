package registrytest

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

// FakeHive stands in for a HiveLayer behind the reading methods callers use,
// so a tool's tests can build keys without a memory image.
type FakeHive struct {
	Root              *registryhive.KeyNode
	Subkeys           map[*registryhive.KeyNode][]*registryhive.KeyNode
	Values            map[*registryhive.KeyNode][]registryhive.Value
	SubkeysIncomplete map[*registryhive.KeyNode]bool
	ValuesIncomplete  map[*registryhive.KeyNode]bool

	next uint32
}

const (
	rootCell  = 0x20
	firstCell = 0x80
	cellStep  = 0x60
)

func NewFakeHive(name string) *FakeHive {
	return &FakeHive{
		Root:              &registryhive.KeyNode{CellIndex: rootCell, Name: name},
		Subkeys:           map[*registryhive.KeyNode][]*registryhive.KeyNode{},
		Values:            map[*registryhive.KeyNode][]registryhive.Value{},
		SubkeysIncomplete: map[*registryhive.KeyNode]bool{},
		ValuesIncomplete:  map[*registryhive.KeyNode]bool{},
		next:              firstCell,
	}
}

func (h *FakeHive) add(parent, k *registryhive.KeyNode) *registryhive.KeyNode {
	k.CellIndex = h.next
	h.next += cellStep
	h.Subkeys[parent] = append(h.Subkeys[parent], k)
	return k
}

func (h *FakeHive) Key(parent *registryhive.KeyNode, name string) *registryhive.KeyNode {
	return h.add(parent, &registryhive.KeyNode{Name: name})
}

func (h *FakeHive) UnnamedKey(parent *registryhive.KeyNode) *registryhive.KeyNode {
	return h.add(parent, &registryhive.KeyNode{NameUnreadable: true})
}

// Path makes every missing key on the way.
func (h *FakeHive) Path(path string) *registryhive.KeyNode {
	node := h.Root
	for _, part := range strings.Split(path, `\`) {
		if part == "" {
			continue
		}
		next, found, _ := registryhive.FindSubkey(h.Subkeys[node], true, part)
		if !found {
			next = h.Key(node, part)
		}
		node = next
	}
	return node
}

func (h *FakeHive) SubkeysChecked(n *registryhive.KeyNode) ([]*registryhive.KeyNode, bool) {
	return h.Subkeys[n], !h.SubkeysIncomplete[n]
}

func (h *FakeHive) ValuesChecked(n *registryhive.KeyNode) ([]registryhive.Value, bool) {
	return h.Values[n], !h.ValuesIncomplete[n]
}

func (h *FakeHive) Subkey(n *registryhive.KeyNode, name string) (*registryhive.KeyNode, error) {
	keys, complete := h.SubkeysChecked(n)
	k, found, maybe := registryhive.FindSubkey(keys, complete, name)
	switch {
	case found:
		return k, nil
	case maybe:
		return nil, fmt.Errorf("subkey %q of %q: %w: subkey list incomplete", name, n.Name, registryhive.ErrKeyUnreadable)
	default:
		return nil, fmt.Errorf("subkey %q of %q: %w", name, n.Name, registryhive.ErrKeyNotFound)
	}
}

func (h *FakeHive) ValueByNameChecked(n *registryhive.KeyNode, name string) (registryhive.Value, bool, bool) {
	values, complete := h.ValuesChecked(n)
	return registryhive.FindValue(values, complete, name)
}

func (h *FakeHive) OpenKey(path string) (*registryhive.KeyNode, error) {
	if h.Root == nil {
		return nil, fmt.Errorf("key %q: root: %w", path, registryhive.ErrKeyUnreadable)
	}
	node := h.Root
	for _, part := range strings.Split(path, `\`) {
		if part == "" {
			continue
		}
		next, err := h.Subkey(node, part)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", path, err)
		}
		node = next
	}
	return node, nil
}

// SZ stores data as UTF-16LE with its terminating NUL, as the registry does.
func SZ(name, data string) registryhive.Value {
	units := append(utf16.Encode([]rune(data)), 0)
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	return registryhive.Value{Name: name, Type: 1, Data: data, Raw: raw, Length: uint32(len(raw))}
}

func DWORD(name string, v uint32) registryhive.Value {
	raw := binary.LittleEndian.AppendUint32(nil, v)
	return registryhive.Value{Name: name, Type: 4, Data: fmt.Sprintf("0x%x", v), Raw: raw, Length: 4}
}
