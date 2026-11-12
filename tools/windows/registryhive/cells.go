package registryhive

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/util"
)

// Learn: a key name component is at most 255 characters and has no
// backslash; a value name is at most 16,383 characters.
const (
	maxKeyNameChars   = 255
	maxValueNameChars = 16383
	unnamedValueName  = "(Default)"
)

const (
	sigKeyNode  = "nk"
	sigValue    = "vk"
	sigFastLeaf = "lf"
	sigHashLeaf = "lh"
	sigRoot     = "ri"
	sigBigData  = "db"

	keyHiveRoot         = 0x4
	keyNameCompressed   = 0x20
	valueNameCompressed = 0x1
	dataResident        = 0x80000000
)

type indexKind int

const (
	indexNone indexKind = iota
	indexFastLeaf
	indexHashLeaf
	indexRoot
)

func signature(c cellView, at uint64) (string, bool) {
	if !c.has(at, 2) {
		return "", false
	}
	return string(c.b[at : at+2]), true
}

func expectSignature(c cellView, at uint64, want string) error {
	got, ok := signature(c, at)
	if !ok {
		return fmt.Errorf("%w: signature", ErrCellUnreadable)
	}
	if got != want {
		return fmt.Errorf("%w: %q, want %q", ErrCellSignature, got, want)
	}
	return nil
}

// A compressed name holds one byte per character; the others are UTF-16LE.
func decodeName(c cellView, at uint64, length uint16, compressed bool, maxChars int) (string, bool) {
	n := uint64(length)
	if !c.has(at, n) {
		return "", false
	}
	raw := c.b[at : at+n]
	if compressed {
		if len(raw) > maxChars {
			return "", false
		}
		r := make([]rune, len(raw))
		for i, b := range raw {
			r[i] = rune(b)
		}
		return string(r), true
	}
	if n%2 != 0 || int(n/2) > maxChars {
		return "", false
	}
	return util.DecodeUTF16LE(raw), true
}

func decodeKey(c cellView, kl keyCellLayout) (*KeyNode, error) {
	if err := expectSignature(c, kl.signature, sigKeyNode); err != nil {
		return nil, err
	}
	k := &KeyNode{CellIndex: c.index, Address: c.addr - 4}
	var ok bool
	k.LastWrite, ok = c.u64(kl.lastWrite)
	k.LastWriteUnreadable = !ok
	if kl.hasParent {
		k.parent, k.parentRead = c.u32(kl.parent)
	}
	for s := uint64(0); s < 2; s++ {
		k.counts[s], k.countRead[s] = c.u32(kl.subkeyCounts + 4*s)
		k.lists[s], k.listRead[s] = c.u32(kl.subkeyLists + 4*s)
		if !k.countRead[s] || !k.listRead[s] {
			k.SubkeysUnreadable = true
		}
	}
	count, countOK := c.u32(kl.valueCount)
	list, listOK := c.u32(kl.valueList)
	k.valueCount, k.valueList = count, list
	k.ValuesUnreadable = !countOK || (!listOK && count > 0)
	if cl, ok := c.u16(kl.classLength); ok && kl.hasClass {
		if cls, ok := c.u32(kl.class); ok {
			k.class, k.classLength = cls, cl
		}
	}
	flags, flagsOK := c.u16(kl.flags)
	k.flags = flags
	length, lengthOK := c.u16(kl.nameLength)
	if flagsOK && lengthOK {
		k.Name, ok = decodeName(c, kl.name, length, flags&keyNameCompressed != 0, maxKeyNameChars)
		if ok && strings.ContainsRune(k.Name, '\\') {
			k.Name, ok = "", false
		}
		k.NameUnreadable = !ok
	} else {
		k.NameUnreadable = true
	}
	return k, nil
}

type dataRef struct {
	field    uint32
	resident bool
}

func decodeValue(c cellView, vl valueCellLayout) (Value, dataRef, error) {
	if err := expectSignature(c, vl.signature, sigValue); err != nil {
		return Value{}, dataRef{}, err
	}
	var v Value
	var ok bool
	v.Type, ok = c.u32(vl.typ)
	v.TypeUnreadable = !ok
	length, lengthOK := c.u32(vl.dataLength)
	field, fieldOK := c.u32(vl.data)
	ref := dataRef{field: field, resident: length&dataResident != 0}
	v.Length = length &^ dataResident
	v.LengthUnreadable = !lengthOK || (!fieldOK && v.Length > 0)
	flags, flagsOK := c.u16(vl.flags)
	nameLength, nameOK := c.u16(vl.nameLength)
	switch {
	case !flagsOK || !nameOK:
		v.NameUnreadable = true
	case nameLength == 0:
		v.Name = unnamedValueName
	default:
		v.Name, ok = decodeName(c, vl.name, nameLength, flags&valueNameCompressed != 0, maxValueNameChars)
		v.NameUnreadable = !ok
	}
	return v, ref, nil
}

func decodeIndexHead(c cellView, il indexCellLayout) (indexKind, uint16, error) {
	sig, ok := signature(c, il.signature)
	if !ok {
		return indexNone, 0, fmt.Errorf("%w: index signature", ErrCellUnreadable)
	}
	kind := indexNone
	switch sig {
	case sigFastLeaf:
		kind = indexFastLeaf
	case sigHashLeaf:
		kind = indexHashLeaf
	case sigRoot:
		kind = indexRoot
	default:
		return indexNone, 0, fmt.Errorf("%w: index %q", ErrCellSignature, sig)
	}
	count, ok := c.u16(il.count)
	if !ok {
		return kind, 0, fmt.Errorf("%w: index count", ErrCellUnreadable)
	}
	return kind, count, nil
}

func decodeIndexEntries(c cellView, il indexCellLayout, kind indexKind, count uint16) ([]uint32, bool) {
	stride, at := uint64(4), uint64(0)
	if kind == indexFastLeaf || kind == indexHashLeaf {
		stride, at = il.leafStride, il.leafCell
	}
	out := make([]uint32, 0, count)
	complete := true
	for i := uint64(0); i < uint64(count); i++ {
		v, ok := c.u32(il.list + i*stride + at)
		if !ok {
			complete = false
			continue
		}
		out = append(out, v)
	}
	return out, complete
}
