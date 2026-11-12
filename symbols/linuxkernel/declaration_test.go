package linuxkernel

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/btf"
	"github.com/aoiflux/libvapour/symbols/btf/btftest"
	lt "github.com/aoiflux/libvapour/symbols/linuxkernel/linuxtest"
)

const (
	banner   = "Linux version 6.17.0 (builder@host) (gcc 13.3.0) #1 SMP\n\x00"
	btfAt    = 0x10000
	bannerAt = 0x20000
	inArrays = lt.ArraysVA - lt.KernelBase
)

type edit func(records []string, offsets []uint32) ([]string, []uint32)

func imageWith(t *testing.T, release string, change edit) []byte {
	t.Helper()
	b := btftest.New()
	sint := b.Int("int", 4, btf.IntSigned)
	b.Struct("task_struct", 8, btftest.Member{Name: "pid", Type: sint, BitOffset: 32})
	blob := b.Bytes()
	records := []string{"T_stext", "Tfoo", "R__start_BTF", "R__stop_BTF", "Rlinux_banner", "B_end"}
	offsets := []uint32{0, 0x10, inArrays + btfAt, inArrays + btfAt + uint32(len(blob)), inArrays + bannerAt, inArrays + 0x30000}
	if change != nil {
		records, offsets = change(records, offsets)
	}
	buf := lt.Capture(0, records, offsets)
	copy(buf[lt.ArraysPA+btfAt:], blob)
	copy(buf[lt.ArraysPA+bannerAt:], banner)
	lt.PutNote(buf, 0x100, "OSRELEASE="+release+"\n"+lt.LayoutKeys(0)+lt.KallsymsKeys(0))
	return buf
}

func kernelOf(t *testing.T, buf []byte) Kernel {
	t.Helper()
	k, err := FindKernel(&lt.Memory{Buf: buf}, limits.Limits{})
	if err != nil {
		t.Fatalf("find kernel: %v", err)
	}
	return k
}

func TestTheTableComesFromTheImagesOwnKallsymsAndBTF(t *testing.T) {
	k := kernelOf(t, imageWith(t, "6.17.0", nil))
	d, report, err := k.Declaration()
	if err != nil {
		t.Fatalf("declaration: %v", err)
	}
	if !bytes.Equal(d.LinuxBanner, []byte(banner)) {
		t.Errorf("banner %q", d.LinuxBanner)
	}
	at := map[string]uint64{}
	for _, a := range d.Addresses {
		at[a.Name] = a.Address
	}
	if at["foo"] != lt.KernelBase+0x10 {
		t.Errorf("foo at 0x%x", at["foo"])
	}
	pid := false
	for _, r := range d.Records {
		for _, m := range r.Members {
			pid = pid || r.Name == "task_struct" && m.Name == "pid" && m.Offset == 4
		}
	}
	if !pid || report.Names != 6 || len(report.Ambiguous) != 0 {
		t.Errorf("task_struct.pid at 4: %v; report %+v", pid, report)
	}
	table, _, err := k.AssembledTable("assembled")
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if s, err := table.LookupSymbol("foo"); err != nil || s.Address != lt.KernelBase+0x10 {
		t.Errorf("foo %+v (%v)", s, err)
	}
	if _, err := symbols.ReadFile("assembled"); err == nil {
		t.Error("the assembled table was found as a file")
	}
}

func TestABackslashInTheReleaseStillMatchesTheBanner(t *testing.T) {
	buf := imageWith(t, `6.1\7.0`, nil)
	copy(buf[lt.ArraysPA+bannerAt:], "Linux version 6.1\\7.0 (b@h) #1 SMP\n\x00")
	k := kernelOf(t, buf)
	if e, _ := k.VMCoreInfo.Lookup("OSRELEASE"); e.Text != `6.1\\7.0` {
		t.Fatalf("OSRELEASE text %q", e.Text)
	}
	if _, _, err := k.Declaration(); err != nil {
		t.Errorf("declaration: %v", err)
	}
}

func drop(name string) edit {
	return func(rs []string, os []uint32) ([]string, []uint32) {
		for i, r := range rs {
			if r[1:] == name {
				return append(rs[:i:i], rs[i+1:]...), append(os[:i:i], os[i+1:]...)
			}
		}
		return rs, os
	}
}

func TestATableIsRefusedWhereTheImageDisagreesWithItself(t *testing.T) {
	for _, tc := range []struct {
		name, release string
		change        edit
		smear         func([]byte)
		want          string
	}{
		{"another release", "6.18.0", nil, nil, `linux_banner release "6.17.0" differs from VMCOREINFO OSRELEASE "6.18.0"`},
		{"no __start_BTF", "6.17.0", drop("__start_BTF"), nil, "kallsyms holds no __start_BTF"},
		{"no __stop_BTF", "6.17.0", drop("__stop_BTF"), nil, "kallsyms holds no __stop_BTF"},
		{"no linux_banner", "6.17.0", drop("linux_banner"), nil, "kallsyms holds no linux_banner"},
		{"two linux_banner", "6.17.0", func(rs []string, os []uint32) ([]string, []uint32) {
			return append(rs, "Rlinux_banner"), append(os, inArrays+0x40000)
		}, nil, "kallsyms holds linux_banner at both"},
		{"BTF that does not parse", "6.17.0", nil, func(b []byte) { b[lt.ArraysPA+btfAt] = 0 }, "read btf"},
		{"no banner at linux_banner", "6.17.0", nil, func(b []byte) { b[lt.ArraysPA+bannerAt] = 1 }, "linux_banner at"},
		{"kallsyms that does not decode", "6.17.0", nil, func(b []byte) { b[lt.ArraysPA] = 0 }, "decode kallsyms"},
	} {
		buf := imageWith(t, tc.release, tc.change)
		if tc.smear != nil {
			tc.smear(buf)
		}
		if _, _, err := kernelOf(t, buf).Declaration(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestTheTableIsCheckedAgainstTheBannerAndVMCoreInfo(t *testing.T) {
	buf := imageWith(t, "6.17.0", nil)
	lt.PutNote(buf, 0x100, "OSRELEASE=6.17.0\n"+lt.LayoutKeys(0)+lt.KallsymsKeys(0)+
		"SYMBOL(mem_section)=ffff8d7e7ffce000\nSYMBOL(missing_from_table)=ffffffff81000400\n")
	k := kernelOf(t, buf)
	table, _, err := k.AssembledTable("assembled")
	if err != nil {
		t.Fatal(err)
	}
	banner, _ := table.LinuxBanner()
	agreed, err := k.CheckTable(table, banner)
	if err != nil || agreed != 1 {
		t.Errorf("CheckTable = %d (%v), want _stext alone to agree", agreed, err)
	}
	if _, err := k.CheckTable(table, nil); !errors.Is(err, ErrNoBanner) {
		t.Errorf("no banner: %v", err)
	}
	other := []byte("Linux version 6.17.0 (other@host) (gcc 13.3.0) #2 SMP\n\x00")
	if _, err := k.CheckTable(table, other); err == nil || !strings.Contains(err.Error(), "differs from kernel banner") {
		t.Errorf("another banner: %v", err)
	}
	lt.PutNote(buf, 0x100, "OSRELEASE=6.17.0\n"+lt.LayoutKeys(0)+lt.KallsymsKeys(0)+"SYMBOL(foo)=ffffffff81000020\n")
	k = kernelOf(t, buf)
	if agreed, err := k.CheckTable(table, banner); err == nil || !strings.Contains(err.Error(), "foo at 0xffffffff81000020 in VMCOREINFO") {
		t.Errorf("a symbol that moved: %d, %v", agreed, err)
	}
}
