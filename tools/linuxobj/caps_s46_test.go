package linuxobj_test

import (
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func TestCapabilityNumbersAreTheUAPIOnes(t *testing.T) {
	for n, want := range map[int]string{0: "CAP_CHOWN", 7: "CAP_SETUID", 21: "CAP_SYS_ADMIN", 31: "CAP_SETFCAP",
		35: "CAP_WAKE_ALARM", 37: "CAP_AUDIT_READ", 38: "CAP_PERFMON", 39: "CAP_BPF", 40: "CAP_CHECKPOINT_RESTORE"} {
		if got, ok := linuxobj.CapabilityName(n); !ok || got != want {
			t.Errorf("capability %d is %q, want %q", n, got, want)
		}
	}
	if _, ok := linuxobj.CapabilityName(41); ok {
		t.Error("capability 41 has a name")
	}
	if linuxobj.LastCapValue() != 40 {
		t.Errorf("last named capability %d", linuxobj.LastCapValue())
	}
}

func TestCapabilitySetsDecode(t *testing.T) {
	full := linuxobj.CapFull{Last: 40, Mask: 1<<41 - 1}
	for v, want := range map[uint64]string{
		0:             "",
		1<<41 - 1:     "CAP_FULL_SET",
		1<<10 | 1<<13: "CAP_NET_BIND_SERVICE, CAP_NET_RAW",
		1<<0 | 1<<45:  "CAP_CHOWN, 0x200000000000",
		1<<42 - 1:     "CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP, CAP_LINUX_IMMUTABLE, CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, CAP_NET_ADMIN, CAP_NET_RAW, CAP_IPC_LOCK, CAP_IPC_OWNER, CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_SYS_CHROOT, CAP_SYS_PTRACE, CAP_SYS_PACCT, CAP_SYS_ADMIN, CAP_SYS_BOOT, CAP_SYS_NICE, CAP_SYS_RESOURCE, CAP_SYS_TIME, CAP_SYS_TTY_CONFIG, CAP_MKNOD, CAP_LEASE, CAP_AUDIT_WRITE, CAP_AUDIT_CONTROL, CAP_SETFCAP, CAP_MAC_OVERRIDE, CAP_MAC_ADMIN, CAP_SYSLOG, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND, CAP_AUDIT_READ, CAP_PERFMON, CAP_BPF, CAP_CHECKPOINT_RESTORE, 0x20000000000",
		1 << 35:       "CAP_WAKE_ALARM",
	} {
		if got := linuxobj.DecodeCapabilities(v, full); got != want {
			t.Errorf("%#x decodes as %q, want %q", v, got, want)
		}
	}
	if linuxobj.DecodeCapabilities(0, linuxobj.CapFull{}) != "" {
		t.Error("an empty mask names the empty set")
	}
}

func capKernel(t *testing.T, lastCap int32, withLast bool, bset uint64, withInit bool) *linuxobj.Kernel {
	t.Helper()
	k := lt.NewKernel(1700000000, 0)
	if withLast {
		at := k.Alloc(8)
		k.Mem.U32(at, uint32(lastCap))
		k.Table.AddSymbol(symbols.Symbol{Name: "cap_last_cap", Address: at})
	}
	if withInit {
		cred := k.AddCred(lt.Cred{Caps: [5]uint64{0, bset, bset, bset, 0}})
		k.Table.AddSymbol(symbols.Symbol{Name: "init_cred", Address: cred})
	}
	return fixtureKernel(t, k)
}

func TestTheFullSetComesFromTheRunningKernel(t *testing.T) {
	for _, c := range []struct {
		name string
		k    *linuxobj.Kernel
		want linuxobj.CapFull
	}{
		{"cap_last_cap 37 (v4.19)", capKernel(t, 37, true, 0, false), linuxobj.CapFull{Last: 37, Mask: 1<<38 - 1, Source: linuxobj.CapFromLastCap}},
		{"cap_last_cap 40", capKernel(t, 40, true, 1<<38-1, true), linuxobj.CapFull{Last: 40, Mask: 1<<41 - 1, Source: linuxobj.CapFromLastCap}},
		{"cap_last_cap out of range, init_cred", capKernel(t, 99, true, 1<<41-1, true), linuxobj.CapFull{Last: 40, Mask: 1<<41 - 1, Source: linuxobj.CapFromInitCred}},
		{"init_cred only", capKernel(t, 0, false, 1<<38-1, true), linuxobj.CapFull{Last: 37, Mask: 1<<38 - 1, Source: linuxobj.CapFromInitCred}},
		{"init_cred not a full set", capKernel(t, 0, false, 0x5, true), linuxobj.CapFull{Last: 40, Mask: 1<<41 - 1, Source: linuxobj.CapFromNames}},
		{"neither", capKernel(t, 0, false, 0, false), linuxobj.CapFull{Last: 40, Mask: 1<<41 - 1, Source: linuxobj.CapFromNames}},
	} {
		if got := c.k.KernelCapFull(); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	if last, ok, err := capKernel(t, 40, true, 0, false).CapLastCap(); !ok || err != nil || last != 40 {
		t.Errorf("CapLastCap %d %t %v", last, ok, err)
	}
	if _, ok, err := capKernel(t, 0, false, 0, false).CapLastCap(); ok || err != nil {
		t.Errorf("absent cap_last_cap: %t %v", ok, err)
	}
}

func TestBothCapabilityLayoutsReadAsOneValue(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	at := k.Alloc(16)
	k.Mem.U32(at, 0x8000_0001)
	k.Mem.U32(at+4, 0x0000_0100)
	k.Table.AddStruct(symbols.StructType{Name: "kernel_cap_v419", Size: 8, Fields: []symbols.Field{{Name: "cap", Offset: 0,
		Type: symbols.TypeRef{Name: "__u32", IsArray: true, ArrayLength: 2, Element: &symbols.TypeRef{Name: "__u32"}}}}})
	k.Table.AddStruct(symbols.StructType{Name: "kernel_cap_wide", Size: 12})
	kk := fixtureKernel(t, k)
	for _, typ := range []string{"kernel_cap_t", "kernel_cap_v419", ""} {
		v, err := kk.Capabilities(at, typ)
		if err != nil || v != 0x100_8000_0001 {
			t.Errorf("%q: %#x, %v", typ, v, err)
		}
	}
	if _, err := kk.Capabilities(at, "kernel_cap_wide"); err == nil {
		t.Error("a 12-byte set reads")
	}
	if names, rest := linuxobj.CapabilityNames(0x100_8000_0001); len(names) != 3 || rest != 0 ||
		names[2] != "CAP_CHECKPOINT_RESTORE" || names[1] != "CAP_SETFCAP" {
		t.Errorf("names %v rest %#x", names, rest)
	}
}
