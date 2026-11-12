package socketlist

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var (
	ErrAddressLength = errors.New("socketlist: address length out of range")
	ErrShortAddress  = errors.New("socketlist: address bytes shorter than its length")
)

func IPv4(b []byte) (string, error) {
	if len(b) != 4 {
		return "", fmt.Errorf("%w: %d bytes for ipv4", ErrShortAddress, len(b))
	}
	return netip.AddrFrom4([4]byte(b)).String(), nil
}

func IPv6(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("%w: %d bytes for ipv6", ErrShortAddress, len(b))
	}
	return netip.AddrFrom16([16]byte(b)).String(), nil
}

// Port takes the two bytes of a __be16 as they sit in memory.
func Port(b []byte) (uint16, error) {
	if len(b) != 2 {
		return 0, fmt.Errorf("%w: %d bytes for a port", ErrShortAddress, len(b))
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

const sunPathMax = 108

// UnixPath renders the n name bytes of a unix_address, n being
// unix_address.len less the offset of sun_path, as the kernel's
// /proc/net/unix does (S13 U3): a path name loses its trailing NUL, an
// abstract name is shown with a leading '@' and every NUL in it as '@'. The
// kernel stores a 108-byte path with its NUL, so n reaches 109.
func UnixPath(n int64, path []byte) (string, error) {
	if n < 1 || n > sunPathMax+1 {
		return "", fmt.Errorf("%w: %d name bytes", ErrAddressLength, n)
	}
	if int64(len(path)) < n {
		return "", fmt.Errorf("%w: %d of %d sun_path bytes", ErrShortAddress, len(path), n)
	}
	end := int(n)
	var sb strings.Builder
	i := 0
	if path[0] != 0 {
		end--
	} else {
		sb.WriteByte('@')
		i = 1
	}
	for ; i < end; i++ {
		c := path[i]
		if c == 0 {
			c = '@'
		}
		sb.WriteByte(c)
	}
	return sb.String(), nil
}

// NetlinkGroupMask is the nl_groups value the kernel reports for a peer's
// dst_group (S13 L3).
func NetlinkGroupMask(group uint64) uint32 {
	if group == 0 || group > 32 {
		return 0
	}
	return 1 << (group - 1)
}

const vmaddrAny = 1<<32 - 1

// VsockWord renders svm_cid or svm_port, naming the wildcard (S13 V2).
func VsockWord(v uint64, wildcard string) string {
	if v == vmaddrAny {
		return wildcard
	}
	return strconv.FormatUint(v, 10)
}

func Hex32(v uint32) string { return fmt.Sprintf("0x%08x", v) }

func ethProtocol(v uint16) string {
	if s, ok := ethProtocolNames[uint64(v)]; ok {
		return s
	}
	return fmt.Sprintf("0x%04x", v)
}
