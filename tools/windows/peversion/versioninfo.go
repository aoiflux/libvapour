package peversion

import (
	"encoding/binary"
	"unicode/utf16"
)

// One node of the VS_VERSIONINFO tree: wLength, wValueLength, wType, a
// NUL-terminated UTF-16 key, padding to 32 bits, the value, padding to 32
// bits, then the children. wLength covers the node and its children.
type versionNode struct {
	key        string
	text       bool
	valueAt    int
	valueBytes int
	childrenAt int
	end        int
}

const nodeHeaderBytes = 6

// Alignment is to the address, not to the offset in b: base is the address
// of b[0].
func alignedAt(base uint64, off int) int {
	return off + int((4-(base+uint64(off))%4)%4)
}

func readNode(b []byte, base uint64, off int) (versionNode, bool) {
	if off < 0 || off+nodeHeaderBytes > len(b) {
		return versionNode{}, false
	}
	length := int(binary.LittleEndian.Uint16(b[off:]))
	valueLength := int(binary.LittleEndian.Uint16(b[off+2:]))
	wType := binary.LittleEndian.Uint16(b[off+4:])
	end := off + length
	if length < nodeHeaderBytes || end > len(b) {
		return versionNode{}, false
	}
	var units []uint16
	at := off + nodeHeaderBytes
	for ; ; at += 2 {
		if at+2 > end {
			return versionNode{}, false
		}
		u := binary.LittleEndian.Uint16(b[at:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	n := versionNode{key: string(utf16.Decode(units)), text: wType == 1, end: end}
	n.valueAt = alignedAt(base, at+2)
	n.valueBytes = valueLength
	if n.text {
		n.valueBytes = 2 * valueLength
	}
	n.childrenAt = alignedAt(base, min(n.valueAt+n.valueBytes, end))
	if n.valueAt > end {
		n.valueAt, n.valueBytes = end, 0
	}
	return n, true
}

func (n versionNode) children(b []byte, base uint64, visit func(versionNode) bool) {
	for at := n.childrenAt; at+nodeHeaderBytes <= n.end; {
		c, ok := readNode(b[:n.end], base, at)
		if !ok {
			return
		}
		if !visit(c) {
			return
		}
		at = alignedAt(base, c.end)
	}
}

// The value of a String node is text up to its NUL; wValueLength counts
// characters, and some writers count bytes, so the node's end bounds it.
func (n versionNode) textValue(b []byte) string {
	var units []uint16
	for at := n.valueAt; at+2 <= n.end; at += 2 {
		u := binary.LittleEndian.Uint16(b[at:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

// originalFilename walks VS_VERSIONINFO, StringFileInfo, each StringTable
// and its String nodes for the OriginalFilename value.
func originalFilename(b []byte, base uint64) (string, bool) {
	root, ok := readNode(b, base, 0)
	if !ok || root.key != versionInfoKey {
		return "", false
	}
	var name string
	found := false
	root.children(b, base, func(info versionNode) bool {
		if info.key != "StringFileInfo" {
			return true
		}
		info.children(b, base, func(table versionNode) bool {
			table.children(b, base, func(s versionNode) bool {
				if s.key == "OriginalFilename" {
					name, found = s.textValue(b), true
				}
				return !found
			})
			return !found
		})
		return !found
	})
	return name, found
}

const versionInfoKey = "VS_VERSION_INFO"
