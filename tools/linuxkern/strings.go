package linuxkern

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/util"
)

var (
	ErrNoString        = errors.New("linuxkern: string of no bytes")
	ErrStringUnread    = errors.New("linuxkern: string does not read to its end")
	ErrNotByteArray    = errors.New("linuxkern: member is not an array of bytes")
	ErrStringPastSpace = errors.New("linuxkern: string runs past the top of the address space")
)

// S54 4.5: at most count bytes, a page at a time, ending at the first NUL. A
// string cut short by a page that does not read is an error, not a shorter
// string, since the missing bytes may hold more than the NUL.
func ReadString(mem memory.MemoryReader, addr, count uint64) (string, error) {
	if count == 0 {
		return "", fmt.Errorf("%w: at %#x", ErrNoString, addr)
	}
	var out []byte
	for at, left := addr, count; left > 0; {
		chunk := min(PageSize-at%PageSize, left)
		b, err := mem.ReadAt(at, chunk)
		if err != nil || uint64(len(b)) < chunk {
			return "", fmt.Errorf("%w: %d-byte string at %#x: bytes at %#x: %w", ErrStringUnread, count, addr, at,
				errors.Join(err, shortRead(len(b), chunk)))
		}
		if i := bytes.IndexByte(b[:chunk], 0); i >= 0 {
			out = append(out, b[:i]...)
			break
		}
		out = append(out, b[:chunk]...)
		left -= chunk
		if left > 0 && at+chunk < at {
			return "", fmt.Errorf("%w: %d-byte string at %#x", ErrStringPastSpace, count, addr)
		}
		at += chunk
	}
	return util.DecodeUTF8Replace(out), nil
}

func shortRead(got int, want uint64) error {
	if uint64(got) >= want {
		return nil
	}
	return fmt.Errorf("%w: %d of %d", ErrShortRead, got, want)
}

// S54 4.5, T6: the whole array, cut at the first NUL. The kernel's copies
// always leave one, so a full array without one is returned whole and the
// bytes past the array are never read.
func ByteArrayLength(sym symbols.SymbolTable, parent string, f symbols.Field) (uint64, error) {
	if !f.Type.IsArray && f.Type.ArrayLength == 0 {
		return 0, fmt.Errorf("%w: %s.%s is not an array", ErrNotByteArray, parent, f.Name)
	}
	if f.Type.ArrayLength == 0 {
		return 0, fmt.Errorf("%w: %s.%s has no declared length", ErrNotByteArray, parent, f.Name)
	}
	elem, err := ElementSize(sym, f)
	if err != nil || elem != 1 {
		return 0, fmt.Errorf("%w: %s.%s has %d-byte elements", ErrNotByteArray, parent, f.Name, elem)
	}
	return f.Type.ArrayLength, nil
}

func (k *Kernel) StringAt(addr, count uint64) (string, error) { return ReadString(k.Mem, addr, count) }

func (k *Kernel) MemberString(addr uint64, typ, path string) (string, error) {
	m, err := k.Member(typ, path)
	if err != nil {
		return "", err
	}
	n, err := ByteArrayLength(k.Sym, m.Parent, m.Field)
	if err != nil {
		return "", err
	}
	return ReadString(k.Mem, addr+m.Offset, n)
}
