package linuxobj

import (
	"fmt"
	"math/bits"
	"strings"
)

// S46 P1: CAP_* by number, CAP_CHOWN 0 to CAP_CHECKPOINT_RESTORE 40.
var capabilityNames = [...]string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
	"CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE",
	"CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE",
	"CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT",
	"CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
	"CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
	"CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
}

// S46 P2: both kernel_cap_t layouts are 8 bytes.
const capSetBytes = 8

// S46 P4: the kernel's own name for the set of every valid capability.
const fullSetName = "CAP_FULL_SET"

type CapSource string

const (
	CapFromLastCap  CapSource = "cap_last_cap"
	CapFromInitCred CapSource = "init_cred.cap_bset"
	CapFromNames    CapSource = "named capabilities"
)

type CapFull struct {
	Last   int64
	Mask   uint64
	Source CapSource
}

func (f CapFull) Holds(v uint64) bool { return f.Mask != 0 && v == f.Mask }

func LastCapValue() int64 { return int64(len(capabilityNames) - 1) }

func CapabilityName(n int) (string, bool) {
	if n < 0 || n >= len(capabilityNames) {
		return "", false
	}
	return capabilityNames[n], true
}

func capMask(last int64) uint64 {
	if last >= 63 {
		return ^uint64(0)
	}
	return 1<<(last+1) - 1
}

// ok is false when the table has no cap_last_cap.
func (k *Kernel) CapLastCap() (last int64, ok bool, err error) {
	s, err := k.sym.LookupSymbol("cap_last_cap")
	if err != nil {
		return 0, false, nil
	}
	b, err := k.mem.ReadAt(s.Address, 4)
	if err != nil {
		return 0, false, fmt.Errorf("linuxobj: cap_last_cap at %#x: %w", s.Address, err)
	}
	if len(b) < 4 {
		return 0, false, fmt.Errorf("linuxobj: cap_last_cap at %#x: %w", s.Address, ErrShortRead)
	}
	return int64(int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)), true, nil
}

// S46 P3, P4: cap_last_cap is the running kernel's CAP_LAST_CAP and
// init_cred holds CAP_FULL_SET as its bounding set; the name table is the
// last resort.
func (k *Kernel) KernelCapFull() CapFull {
	if last, ok, err := k.CapLastCap(); err == nil && ok && last >= 0 && last < 64 {
		return CapFull{Last: last, Mask: capMask(last), Source: CapFromLastCap}
	}
	if s, err := k.sym.LookupSymbol("init_cred"); err == nil {
		if f, err := k.sym.Field("cred", "cap_bset"); err == nil {
			if v, err := k.Capabilities(s.Address+f.Offset, f.Type.Name); err == nil && v != 0 && v&(v+1) == 0 {
				return CapFull{Last: int64(bits.Len64(v)) - 1, Mask: v, Source: CapFromInitCred}
			}
		}
	}
	return CapFull{Last: LastCapValue(), Mask: capMask(LastCapValue()), Source: CapFromNames}
}

// S46 P2: on a little-endian machine the u64 val and the u32 cap[2] layout
// both read as one 64-bit value whose bit n is capability n.
func (k *Kernel) Capabilities(addr uint64, typeName string) (uint64, error) {
	if typeName != "" {
		if n, err := k.SizeOf(typeName); err == nil && n != capSetBytes {
			return 0, fmt.Errorf("%w: %s is %d bytes", ErrUnsupported, typeName, n)
		}
	}
	b, err := k.mem.ReadAt(addr, capSetBytes)
	if err != nil {
		return 0, fmt.Errorf("linuxobj: capability set at %#x: %w", addr, err)
	}
	if len(b) < capSetBytes {
		return 0, fmt.Errorf("linuxobj: capability set at %#x: %w", addr, ErrShortRead)
	}
	var v uint64
	for i := capSetBytes - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v, nil
}

func CapabilityNames(v uint64) (names []string, rest uint64) {
	for n := range capabilityNames {
		if v&(1<<n) != 0 {
			names = append(names, capabilityNames[n])
		}
	}
	return names, v &^ capMask(LastCapValue())
}

// S46 4.4 step 3: the empty set is empty text, the full set its kernel name, and any
// other set its names in bit order with bits that have no name in hex.
func DecodeCapabilities(v uint64, full CapFull) string {
	if full.Holds(v) {
		return fullSetName
	}
	names, rest := CapabilityNames(v)
	if rest != 0 {
		names = append(names, fmt.Sprintf("%#x", rest))
	}
	return strings.Join(names, ", ")
}
