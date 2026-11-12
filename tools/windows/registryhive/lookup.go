package registryhive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Unreadable is not absent: a key on an incomplete list may still exist.
var (
	ErrKeyUnreadable = errors.New("registryhive: key not readable")
	ErrKeyNotFound   = errors.New("registryhive: key not found")
)

func (h *HiveLayer) OpenKey(path string) (*KeyNode, error) {
	root, err := h.RootCell()
	if err != nil {
		return nil, fmt.Errorf("key %q: %w: %w", path, ErrKeyUnreadable, err)
	}
	node, err := h.KeyNode(root)
	if err != nil {
		return nil, fmt.Errorf("key %q: root cell 0x%x: %w: %w", path, root, ErrKeyUnreadable, err)
	}
	for _, part := range pathParts(path) {
		if node, err = h.Subkey(node, part); err != nil {
			return nil, fmt.Errorf("key %q: %w", path, err)
		}
	}
	return node, nil
}

func pathParts(path string) []string {
	var out []string
	for _, p := range strings.Split(path, `\`) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (h *HiveLayer) Subkey(node *KeyNode, name string) (*KeyNode, error) {
	keys, complete := h.SubkeysChecked(node)
	k, found, maybe := FindSubkey(keys, complete, name)
	switch {
	case found:
		return k, nil
	case maybe:
		return nil, fmt.Errorf("subkey %q of %s: %w: subkey list incomplete", name, keyLabel(node), ErrKeyUnreadable)
	default:
		return nil, fmt.Errorf("subkey %q of %s: %w", name, keyLabel(node), ErrKeyNotFound)
	}
}

func keyLabel(k *KeyNode) string {
	if k == nil || k.NameUnreadable {
		return fmt.Sprintf("the key at cell 0x%x", cellOf(k))
	}
	return fmt.Sprintf("%q", k.Name)
}

func cellOf(k *KeyNode) uint32 {
	if k == nil {
		return 0
	}
	return k.CellIndex
}

// Learn: key names are not case sensitive. A key whose name did not read
// could be the one asked for, so it leaves the answer open.
func FindSubkey(keys []*KeyNode, complete bool, name string) (k *KeyNode, found, maybe bool) {
	open := !complete
	for _, key := range keys {
		if key.NameUnreadable {
			open = true
			continue
		}
		if strings.EqualFold(key.Name, name) {
			return key, true, false
		}
	}
	return nil, false, open
}

func FindValue(values []Value, complete bool, name string) (v Value, found, maybe bool) {
	open := !complete
	for _, val := range values {
		if val.NameUnreadable {
			open = true
			continue
		}
		if strings.EqualFold(val.Name, name) {
			return val, true, false
		}
	}
	return Value{}, false, open
}

func (h *HiveLayer) ValueByNameChecked(node *KeyNode, name string) (v Value, found, unreadable bool) {
	values, complete := h.ValuesChecked(node)
	return FindValue(values, complete, name)
}

// Deprecated: Use ValueByNameChecked and Value.Unreadable.
func (h *HiveLayer) ValueByName(node *KeyNode, name string) (Value, bool) {
	v, found, _ := h.ValueByNameChecked(node, name)
	return v, found
}

const defaultControlSet = "ControlSet001"

// The fallback is reported: the first set may not be the one in use.
func CurrentControlSet(hive *HiveLayer) string {
	name, read := CurrentControlSetChecked(hive)
	if !read && hive != nil {
		hive.ctx.AddDiagnostic("registryhive: hive at 0x%x: Select\\Current not readable: %s used as the current control set",
			hive.cmhive, name)
	}
	return name
}

func CurrentControlSetChecked(hive *HiveLayer) (string, bool) {
	if hive == nil {
		return defaultControlSet, false
	}
	sel, err := hive.OpenKey("Select")
	if err != nil {
		return defaultControlSet, false
	}
	v, found, _ := hive.ValueByNameChecked(sel, "Current")
	if !found || v.Unreadable() || len(v.Raw) != 4 {
		return defaultControlSet, false
	}
	n := binary.LittleEndian.Uint32(v.Raw)
	if n == 0 || n > 999 {
		return defaultControlSet, false
	}
	return fmt.Sprintf("ControlSet%03d", n), true
}

func LastPathComponent(path string) string {
	p := strings.TrimRight(path, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
