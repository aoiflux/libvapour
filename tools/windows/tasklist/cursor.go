package tasklist

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/util"
)

// Fields of the Triggers value sit in 8-byte slots counted from the start of
// the record that holds them (S37 L1).
const slot = 8

type cursor struct {
	b    []byte
	at   int
	base int
}

func (c *cursor) left() int { return len(c.b) - c.at }

func (c *cursor) take(n uint64) ([]byte, error) {
	if n > uint64(c.left()) {
		return nil, fmt.Errorf("%w: %d bytes at offset 0x%x, %d left", ErrTruncated, n, c.at, c.left())
	}
	out := c.b[c.at : c.at+int(n)]
	c.at += int(n)
	return out, nil
}

func (c *cursor) pad() {
	if r := (c.at - c.base) % slot; r != 0 {
		c.at += slot - r
	}
	if c.at > len(c.b) {
		c.at = len(c.b)
	}
}

func (c *cursor) u16() (uint16, error) {
	b, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (c *cursor) u32() (uint32, error) {
	b, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (c *cursor) u64() (uint64, error) {
	b, err := c.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (c *cursor) slotByte() (byte, error) {
	b, err := c.take(1)
	if err != nil {
		return 0, err
	}
	c.pad()
	return b[0], nil
}

func (c *cursor) slotU16() (uint16, error) {
	v, err := c.u16()
	c.pad()
	return v, err
}

func (c *cursor) slotU32() (uint32, error) {
	v, err := c.u32()
	c.pad()
	return v, err
}

// A slotted byte string: its length in a slot of its own, then the bytes.
func (c *cursor) slotted() ([]byte, error) {
	n, err := c.slotU32()
	if err != nil {
		return nil, err
	}
	b, err := c.take(uint64(n))
	c.pad()
	return b, err
}

// A packed byte string: the length and the bytes back to back.
func (c *cursor) packed() ([]byte, error) {
	n, err := c.u32()
	if err != nil {
		return nil, err
	}
	b, err := c.take(uint64(n))
	c.pad()
	return b, err
}

func text(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("%w: text of %d bytes", ErrField, len(b))
	}
	return util.DecodeCountedUTF16LE(b), nil
}

// SID wire form: revision, sub-authority count, a 6-byte big-endian
// identifier authority, then the sub-authorities (MS-DTYP 2.4.2.2).
func sidString(b []byte) (string, error) {
	if len(b) == 0 {
		return "", nil
	}
	if len(b) < 8 || b[0] != 1 || len(b) != 8+4*int(b[1]) {
		return "", fmt.Errorf("%w: security identifier of %d bytes", ErrField, len(b))
	}
	var auth uint64
	for _, x := range b[2:8] {
		auth = auth<<8 | uint64(x)
	}
	var sb strings.Builder
	if auth < 1<<32 {
		fmt.Fprintf(&sb, "S-1-%d", auth)
	} else {
		fmt.Fprintf(&sb, "S-1-0x%012X", auth)
	}
	for i := 0; i < int(b[1]); i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return sb.String(), nil
}

// GUID text form with the first three groups little-endian (MS-DTYP 2.3.4).
func guidString(b []byte) string {
	return fmt.Sprintf("{%08X-%04X-%04X-%X-%X}", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]),
		binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}

const unsetSeconds = 0xFFFFFFFF

// The xs:duration form the task definition uses (MS-TSCH 2.5.1.1).
func duration(seconds uint32) string {
	if seconds == unsetSeconds {
		return ""
	}
	if seconds == 0 {
		return "PT0S"
	}
	d, rest := seconds/86400, seconds%86400
	h, m, s := rest/3600, rest%3600/60, rest%60
	var sb strings.Builder
	sb.WriteString("P")
	if d > 0 {
		fmt.Fprintf(&sb, "%dD", d)
	}
	if h+m+s > 0 {
		sb.WriteString("T")
		for _, part := range []struct {
			v    uint32
			unit string
		}{{h, "H"}, {m, "M"}, {s, "S"}} {
			if part.v > 0 {
				fmt.Fprintf(&sb, "%d%s", part.v, part.unit)
			}
		}
	}
	return sb.String()
}
