package tokensids

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	sidHeaderSize       = 8
	sidRevision         = 1
	maxSubAuthorities   = 15
	ntAuthority         = 5
	ntNonUniqueRID      = 21
	builtinDomainRID    = 32
	logonSessionRID     = 5
	serviceRID          = 80
	virtualMachineRID   = 83
	decimalAuthorityTop = uint64(1) << 32
)

var (
	ErrSIDPointer        = errors.New("tokensids: sid pointer is null or outside system space")
	ErrSIDUnread         = errors.New("tokensids: sid bytes do not read")
	ErrSIDRevision       = errors.New("tokensids: sid revision is not 1")
	ErrSIDSubAuthorities = errors.New("tokensids: sid has more than 15 sub-authorities")
)

type sid struct {
	authority uint64
	sub       []uint32
}

func decodeSIDHeader(b []byte) (authority uint64, count int, err error) {
	if len(b) < sidHeaderSize {
		return 0, 0, ErrSIDUnread
	}
	if b[0] != sidRevision {
		return 0, 0, fmt.Errorf("%w: revision %d", ErrSIDRevision, b[0])
	}
	if int(b[1]) > maxSubAuthorities {
		return 0, 0, fmt.Errorf("%w: %d", ErrSIDSubAuthorities, b[1])
	}
	for _, c := range b[2:sidHeaderSize] {
		authority = authority<<8 | uint64(c)
	}
	return authority, int(b[1]), nil
}

func decodeSID(b []byte) (sid, error) {
	authority, count, err := decodeSIDHeader(b)
	if err != nil {
		return sid{}, err
	}
	if len(b) < sidHeaderSize+4*count {
		return sid{}, ErrSIDUnread
	}
	s := sid{authority: authority, sub: make([]uint32, count)}
	for i := range s.sub {
		s.sub[i] = binary.LittleEndian.Uint32(b[sidHeaderSize+4*i:])
	}
	return s, nil
}

func (s sid) String() string {
	var b strings.Builder
	b.WriteString("S-1-")
	if s.authority < decimalAuthorityTop {
		b.WriteString(strconv.FormatUint(s.authority, 10))
	} else {
		fmt.Fprintf(&b, "0x%012X", s.authority)
	}
	for _, v := range s.sub {
		b.WriteByte('-')
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

func (s sid) bytes() []byte {
	b := make([]byte, sidHeaderSize+4*len(s.sub))
	b[0], b[1] = sidRevision, byte(len(s.sub))
	for i := 0; i < 6; i++ {
		b[7-i] = byte(s.authority >> (8 * i))
	}
	for i, v := range s.sub {
		binary.LittleEndian.PutUint32(b[sidHeaderSize+4*i:], v)
	}
	return b
}

func (s sid) under(authority uint64, first uint32, count int) bool {
	return s.authority == authority && len(s.sub) == count && count > 0 && s.sub[0] == first
}

func (s sid) rid() uint32 { return s.sub[len(s.sub)-1] }
