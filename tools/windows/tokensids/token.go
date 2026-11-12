package tokensids

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

var (
	ErrNotWindows      = errors.New("tokensids: profile is not windows")
	ErrLayout          = errors.New("tokensids: symbol table lacks a token member")
	ErrTokenUnread     = errors.New("tokensids: token does not read")
	ErrNoToken         = errors.New("tokensids: process has no token")
	ErrTokenNotSystem  = errors.New("tokensids: token is outside system space")
	ErrNoTokenUser     = errors.New("tokensids: token has no user entry")
	ErrTooManySIDs     = errors.New("tokensids: sid count exceeds the per-object limit")
	ErrGroupsMisplaced = errors.New("tokensids: group array is not at the token's variable part")
	ErrArrayMisplaced  = errors.New("tokensids: sid array is not where the token places it")
)

type Array string

const (
	UserAndGroups  Array = "UserAndGroups"
	RestrictedSids Array = "RestrictedSids"
	Capabilities   Array = "Capabilities"
)

type SIDArray struct {
	Array   Array
	Address uint64
	Count   uint32
	Err     error
}

type Token struct {
	Address uint64
	Arrays  []SIDArray
}

type TokenReader struct {
	mem      memory.MemoryReader
	table    symbols.SymbolTable
	pointer  uint64
	maxSIDs  uint64
	tokenAt  uint64
	refMask  uint64
	entry    uint64
	sidAt    uint64
	attrAt   uint64
	groups   arrayMembers
	restrict arrayMembers
	caps     arrayMembers
	hasCaps  bool
	variable uint64
	hasVar   bool
}

type arrayMembers struct{ count, array uint64 }

func NewTokenReader(ctx tools.Context) (TokenReader, error) {
	if ctx.Profile == nil || !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return TokenReader{}, ErrNotWindows
	}
	t := ctx.Symbols
	r := TokenReader{mem: ctx.Memory, table: t, pointer: uint64(t.PointerSize()), maxSIDs: uint64(ctx.Bounds().MaxRowsPerObject)}
	var missing []string
	offset := func(typ, name string) uint64 {
		f, err := t.Field(typ, name)
		if err != nil {
			missing = append(missing, typ+"."+name)
			return 0
		}
		return f.Offset
	}
	r.tokenAt = offset("_EPROCESS", "Token")
	r.groups = arrayMembers{offset("_TOKEN", "UserAndGroupCount"), offset("_TOKEN", "UserAndGroups")}
	r.restrict = arrayMembers{offset("_TOKEN", "RestrictedSidCount"), offset("_TOKEN", "RestrictedSids")}
	r.sidAt, r.attrAt = offset("_SID_AND_ATTRIBUTES", "Sid"), offset("_SID_AND_ATTRIBUTES", "Attributes")
	if ref, err := t.Field("_EX_FAST_REF", "RefCnt"); err != nil || ref.Type.BitLength == 0 {
		missing = append(missing, "_EX_FAST_REF.RefCnt bits")
	} else {
		r.refMask = uint64(1)<<ref.Type.BitLength - 1
	}
	if s, err := t.Struct("_SID_AND_ATTRIBUTES"); err != nil || s.Size == 0 {
		missing = append(missing, "_SID_AND_ATTRIBUTES size")
	} else {
		r.entry = s.Size
	}
	if len(missing) > 0 {
		return TokenReader{}, fmt.Errorf("%w: %s", ErrLayout, strings.Join(missing, ", "))
	}
	if f, err := t.Field("_TOKEN", "VariablePart"); err == nil {
		r.variable, r.hasVar = f.Offset, true
	}
	cc, err1 := t.Field("_TOKEN", "CapabilityCount")
	ca, err2 := t.Field("_TOKEN", "Capabilities")
	if err1 == nil && err2 == nil {
		r.caps, r.hasCaps = arrayMembers{cc.Offset, ca.Offset}, true
	}
	return r, nil
}

func (r TokenReader) inSystemSpace(addr uint64) bool {
	if r.pointer == 4 {
		return addr >= 0x80000000 && addr <= 0xFFFFFFFF
	}
	return addr>>63 == 1
}

func (r TokenReader) Token(eprocess uint64) (Token, error) {
	ref, err := r.table.ReadPointer(r.mem, eprocess+r.tokenAt)
	if err != nil {
		return Token{}, fmt.Errorf("%w: %w", ErrTokenUnread, err)
	}
	tok := Token{Address: ref &^ r.refMask}
	if tok.Address == 0 {
		return tok, ErrNoToken
	}
	if !r.inSystemSpace(tok.Address) {
		return tok, ErrTokenNotSystem
	}
	groups, err := r.array(tok.Address, r.groups, UserAndGroups)
	if err != nil {
		return tok, err
	}
	if groups.Count == 0 {
		return tok, ErrNoTokenUser
	}
	if r.hasVar && groups.Address != tok.Address+r.variable {
		return tok, fmt.Errorf("%w: 0x%x", ErrGroupsMisplaced, groups.Address)
	}
	tok.Arrays = append(tok.Arrays, groups)

	restricted, err := r.array(tok.Address, r.restrict, RestrictedSids)
	if err == nil && restricted.Count > 0 && restricted.Address != groups.Address+uint64(groups.Count)*r.entry {
		err = fmt.Errorf("%w: 0x%x", ErrArrayMisplaced, restricted.Address)
	}
	if err != nil || restricted.Count > 0 {
		restricted.Err = err
		tok.Arrays = append(tok.Arrays, restricted)
	}

	if r.hasCaps {
		caps, err := r.array(tok.Address, r.caps, Capabilities)
		if err == nil && caps.Count > 0 && !r.inSystemSpace(caps.Address) {
			err = fmt.Errorf("%w: 0x%x", ErrArrayMisplaced, caps.Address)
		}
		if err != nil || caps.Count > 0 {
			caps.Err = err
			tok.Arrays = append(tok.Arrays, caps)
		}
	}
	return tok, nil
}

func (r TokenReader) array(token uint64, m arrayMembers, name Array) (SIDArray, error) {
	a := SIDArray{Array: name}
	count, err := r.table.ReadUint32(r.mem, token+m.count)
	if err != nil {
		return a, fmt.Errorf("%w: %s count: %w", ErrTokenUnread, name, err)
	}
	a.Count = count
	if uint64(count) > r.maxSIDs {
		return a, fmt.Errorf("%w: %s count %d", ErrTooManySIDs, name, count)
	}
	if a.Address, err = r.table.ReadPointer(r.mem, token+m.array); err != nil {
		return a, fmt.Errorf("%w: %s: %w", ErrTokenUnread, name, err)
	}
	return a, nil
}

type sidEntry struct {
	address    uint64
	attributes uint32
	value      sid
}

func (r TokenReader) entryAt(a SIDArray, i uint32) (sidEntry, error) {
	at := a.Address + uint64(i)*r.entry
	var e sidEntry
	attr, err := r.table.ReadUint32(r.mem, at+r.attrAt)
	if err != nil {
		return e, fmt.Errorf("%w: attributes: %w", ErrSIDUnread, err)
	}
	e.attributes = attr
	if e.address, err = r.table.ReadPointer(r.mem, at+r.sidAt); err != nil {
		return e, fmt.Errorf("%w: pointer: %w", ErrSIDUnread, err)
	}
	if e.address == 0 || !r.inSystemSpace(e.address) {
		return e, ErrSIDPointer
	}
	head, err := r.mem.ReadAt(e.address, sidHeaderSize)
	if err != nil {
		return e, fmt.Errorf("%w: %w", ErrSIDUnread, err)
	}
	_, count, err := decodeSIDHeader(head)
	if err != nil {
		return e, err
	}
	full, err := r.mem.ReadAt(e.address, uint64(sidHeaderSize+4*count))
	if err != nil {
		return e, fmt.Errorf("%w: %w", ErrSIDUnread, err)
	}
	e.value, err = decodeSID(full)
	return e, err
}
