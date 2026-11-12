package pe

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
)

const (
	DirectoryEntryResource = 2
	RTVersion              = 16
)

const (
	resourceTableSize      = 16
	resourceEntrySize      = 8
	resourceDataEntrySize  = 16
	offResourceNameEntries = 12
	offResourceIDEntries   = 14
	resourceSubdirectory   = uint32(1) << 31
)

var (
	ErrNoResourceDirectory = errors.New("pe: no resource directory")
	ErrNoResource          = errors.New("pe: resource type absent")
	ErrResourceLimit       = errors.New("pe: resource tree exceeds a limit")
)

type ResourceData struct {
	Name         uint32
	NameIsString bool
	Language     uint32
	RVA          uint32
	Size         uint32
	CodePage     uint32
}

type resourceEntry struct {
	id       uint32
	isString bool
	target   uint32
}

type resourceTree struct {
	read    ReadRVA
	base    uint64
	visited int
	limit   int
}

// Windows uses three levels, type, name and language, so a leaf is looked
// for only at the third. A subtree that does not read is passed over; if
// that leaves no leaf, the read error is returned rather than "absent".
func FindResources(read ReadRVA, dir DataDirectory, typeID uint16, l limits.Limits) ([]ResourceData, error) {
	if dir.VirtualAddress == 0 {
		return nil, ErrNoResourceDirectory
	}
	t := &resourceTree{read: read, base: uint64(dir.VirtualAddress), limit: l.Effective().MaxTableEntries}
	types, err := t.table(0)
	if err != nil {
		return nil, err
	}
	var typeEntry *resourceEntry
	for i := range types {
		if !types[i].isString && types[i].id == uint32(typeID) {
			typeEntry = &types[i]
			break
		}
	}
	if typeEntry == nil || typeEntry.target&resourceSubdirectory == 0 {
		return nil, fmt.Errorf("%w: type %d", ErrNoResource, typeID)
	}
	names, err := t.table(typeEntry.target &^ resourceSubdirectory)
	if err != nil {
		return nil, err
	}
	var out []ResourceData
	var skipped error
	for _, name := range names {
		if name.target&resourceSubdirectory == 0 {
			continue
		}
		languages, err := t.table(name.target &^ resourceSubdirectory)
		if err != nil {
			if errors.Is(err, ErrResourceLimit) {
				return nil, err
			}
			skipped = firstErr(skipped, err)
			continue
		}
		for _, lang := range languages {
			if lang.target&resourceSubdirectory != 0 {
				continue
			}
			leaf, err := readAt(read, t.base+uint64(lang.target), resourceDataEntrySize)
			if err != nil {
				skipped = firstErr(skipped, err)
				continue
			}
			out = append(out, ResourceData{
				Name: name.id, NameIsString: name.isString, Language: lang.id,
				RVA:      binary.LittleEndian.Uint32(leaf),
				Size:     binary.LittleEndian.Uint32(leaf[4:]),
				CodePage: binary.LittleEndian.Uint32(leaf[8:]),
			})
		}
	}
	if len(out) == 0 && skipped != nil {
		return nil, skipped
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: type %d has no leaf", ErrNoResource, typeID)
	}
	return out, nil
}

func firstErr(have, next error) error {
	if have != nil {
		return have
	}
	return next
}

// The first Number of Name Entries entries are named and the rest carry
// integer IDs; a named entry's field is an offset to its string.
func (t *resourceTree) table(offset uint32) ([]resourceEntry, error) {
	at := t.base + uint64(offset)
	head, err := readAt(t.read, at, resourceTableSize)
	if err != nil {
		return nil, fmt.Errorf("pe: resource table at rva 0x%x: %w", at, err)
	}
	named := int(binary.LittleEndian.Uint16(head[offResourceNameEntries:]))
	count := named + int(binary.LittleEndian.Uint16(head[offResourceIDEntries:]))
	if t.visited += count; t.visited > t.limit {
		return nil, fmt.Errorf("%w: more than %d entries", ErrResourceLimit, t.limit)
	}
	if count == 0 {
		return nil, nil
	}
	b, err := readAt(t.read, at+resourceTableSize, uint64(count)*resourceEntrySize)
	if err != nil {
		return nil, fmt.Errorf("pe: resource entries at rva 0x%x: %w", at+resourceTableSize, err)
	}
	out := make([]resourceEntry, count)
	for i := range out {
		e := b[i*resourceEntrySize:]
		id := binary.LittleEndian.Uint32(e)
		if i < named {
			id &^= resourceSubdirectory
		}
		out[i] = resourceEntry{id: id, isString: i < named, target: binary.LittleEndian.Uint32(e[4:])}
	}
	return out, nil
}
