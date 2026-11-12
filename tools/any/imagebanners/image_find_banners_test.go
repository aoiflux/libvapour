package imagebanners

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	running617 = "Linux version 6.17.0-35-generic (buildd@lcy02-amd64-079) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 19:30:42 UTC 2 (Ubuntu 6.17.0-35.35~24.04.1-generic 6.17.13)"
	older612   = "Linux version 6.12.6-100.fc40.x86_64 (mockbuild@d6ec) (gcc (GCC) 14.2.1 20240912 (Red Hat 14.2.1-3), GNU ld version 2.41-38.fc40) #1 SMP PREEMPT_DYNAMIC Thu Dec 19 23:18:14 UTC 2024"
	kernelVA   = uint64(0xffff800000100000)
)

type fixture struct {
	pm     *testsupport.PagedMemory
	kernel *testsupport.AddressSpace
	table  *symbols.Table
}

func newFixture() *fixture {
	pm := testsupport.NewPagedMemory(4 << 20)
	return &fixture{pm: pm, kernel: pm.NewAddressSpace(), table: symbols.NewTable("t", 8)}
}

func (f *fixture) put(at uint64, b []byte) { f.pm.WriteAt(at, b) }

func (f *fixture) context(profile profiles.Profile, opts map[string]any) (tools.Context, *[]string) {
	diags := &[]string{}
	if opts == nil {
		opts = map[string]any{}
	}
	opts["diagnostics"] = diags
	opts[tools.OptionPhysicalMemory] = memory.MemoryReader(f.pm)
	return tools.Context{Memory: layers.NewProcessLayer(f.pm, f.kernel.DTB, 0), Symbols: f.table, Profile: profile,
		Options: opts}, diags
}

func mustRun(t *testing.T, ctx tools.Context) []Banner {
	t.Helper()
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func codeView(name string, guid byte, age uint32) []byte {
	b := append([]byte("RSDS"), make([]byte, 20)...)
	for i := range 16 {
		b[4+i] = guid + byte(i)
	}
	binary.LittleEndian.PutUint32(b[20:], age)
	return append(append(b, name...), 0)
}

func TestLinuxBannersAreFoundAndTheRunningCopyIsMarked(t *testing.T) {
	f := newFixture()
	pa := f.kernel.MapData(kernelVA, append([]byte(running617+"\n"), 0))
	f.table.AddSymbol(symbols.Symbol{Name: "linux_banner", Address: kernelVA})
	f.put(0x300000, []byte(running617+"\n\x00"))
	f.put(0x310000, []byte(older612+"\x00"))
	f.put(0x320000, []byte("Linux version 6.17.0-35-generic (buildd@lcy02-amd64-079) (x8\x01garbage"))
	f.put(0x330000, []byte("Linux version dependencies, see below\n"))
	f.put(0x340000, []byte("Linux version "+strings.Repeat("9", 65)+" (b@h) (cc) #1\n"))
	ctx, diags := f.context(profiles.LinuxX64Profile{}, nil)
	rows := mustRun(t, ctx)
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
	offsets := []uint64{}
	for _, r := range rows {
		offsets = append(offsets, r.Offset)
	}
	if want := []uint64{pa, 0x300000, 0x310000, 0x320000}; !slices.Equal(offsets, want) {
		t.Fatalf("offsets %#x, want %#x", offsets, want)
	}
	want := []Banner{
		{Offset: pa, Kind: KindLinux, Banner: running617, Release: "6.17.0-35-generic",
			Version:    "#35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 19:30:42 UTC 2 (Ubuntu 6.17.0-35.35~24.04.1-generic 6.17.13)",
			Terminated: true, RunningCopy: true, SameAsRunning: true},
		{Offset: 0x300000, Kind: KindLinux, Banner: running617, Release: "6.17.0-35-generic", Version: rows[0].Version,
			Terminated: true, SameAsRunning: true},
		{Offset: 0x310000, Kind: KindLinux, Banner: older612, Release: "6.12.6-100.fc40.x86_64",
			Version: "#1 SMP PREEMPT_DYNAMIC Thu Dec 19 23:18:14 UTC 2024"},
		{Offset: 0x320000, Kind: KindLinux, Banner: "Linux version 6.17.0-35-generic (buildd@lcy02-amd64-079) (x8",
			Release: "6.17.0-35-generic"},
	}
	if !slices.Equal(rows, want) {
		t.Fatalf("rows\n%+v\nwant\n%+v", rows, want)
	}
}

func peWithCodeView(record []byte) []byte {
	img := make([]byte, 0x1000)
	img[0], img[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(img[0x3c:], 0x80)
	copy(img[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(img[0x84:], 0x8664)
	binary.LittleEndian.PutUint16(img[0x84+16:], 240)
	opt := 0x98
	binary.LittleEndian.PutUint16(img[opt:], 0x20b)
	binary.LittleEndian.PutUint32(img[opt+108:], 16)
	binary.LittleEndian.PutUint32(img[opt+112+6*8:], 0x200)
	binary.LittleEndian.PutUint32(img[opt+112+6*8+4:], 28)
	binary.LittleEndian.PutUint32(img[0x200+12:], 2)
	binary.LittleEndian.PutUint32(img[0x200+16:], uint32(len(record)))
	binary.LittleEndian.PutUint32(img[0x200+20:], 0x300)
	copy(img[0x300:], record)
	return img
}

func TestKernelPDBRecordsAreFoundAndTheRunningOneIsMarked(t *testing.T) {
	f := newFixture()
	record := codeView("ntkrnlmp.pdb", 0x10, 1)
	pa := f.kernel.MapData(kernelVA, peWithCodeView(record))
	f.put(0x200000, record)
	f.put(0x210000, codeView(`d:\os\obj\ntoskrnl.pdb`, 0x40, 3))
	f.put(0x220000, codeView("hal.pdb", 0x50, 1))
	unterminated := codeView("ntkrnlmp.pdb", 0x60, 1)
	f.put(0x230000, append(unterminated[:len(unterminated)-1], []byte(strings.Repeat("x", 300))...))
	ctx, diags := f.context(profiles.WindowsX64Profile{}, map[string]any{tools.OptionKernelBase: kernelVA})
	rows := mustRun(t, ctx)
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
	running := "ntkrnlmp.pdb/131211101514171618191A1B1C1D1E1F-1"
	want := []Banner{
		{Offset: 0x200000, Kind: KindWindowsPDB, Banner: running, SameAsRunning: true},
		{Offset: 0x210000, Kind: KindWindowsPDB, Banner: "ntoskrnl.pdb/434241404544474648494A4B4C4D4E4F-3"},
		{Offset: pa + 0x300, Kind: KindWindowsPDB, Banner: running, RunningCopy: true, SameAsRunning: true},
	}
	slices.SortFunc(want, func(a, b Banner) int { return int(int64(a.Offset) - int64(b.Offset)) })
	if !slices.Equal(rows, want) {
		t.Fatalf("rows\n%+v\nwant\n%+v", rows, want)
	}
}

func TestWithoutTheRunningCopyNothingIsMarkedAndItIsSaid(t *testing.T) {
	f := newFixture()
	f.put(0x300000, []byte(running617+"\n"))
	ctx, diags := f.context(profiles.LinuxX64Profile{}, nil)
	rows := mustRun(t, ctx)
	if len(rows) != 1 || rows[0].RunningCopy || rows[0].SameAsRunning {
		t.Fatalf("rows %+v", rows)
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "running kernel's banner not read") {
		t.Fatalf("diagnostics %q", *diags)
	}
}

func TestAHitIsFoundOnceAcrossAWindowBoundary(t *testing.T) {
	f := newFixture()
	at := uint64(1<<20 - 10)
	f.put(at, []byte(older612+"\n"))
	ctx, _ := f.context(profiles.LinuxX64Profile{}, nil)
	ctx.Limits = limits.Limits{MaxBufferBytes: 1 << 20}
	rows := mustRun(t, ctx)
	if len(rows) != 1 || rows[0].Offset != at || rows[0].Banner != older612 || !rows[0].Terminated {
		t.Fatalf("rows %+v", rows)
	}
}

func TestAWindowFullOfHitsIsCut(t *testing.T) {
	f := newFixture()
	for i := range uint64(5) {
		f.put(0x100000+i*0x100, []byte("Linux version 1 (a@b) (c) #1\n"))
	}
	ctx, diags := f.context(profiles.LinuxX64Profile{}, nil)
	ctx.Limits = limits.Limits{MaxMatchesPerChunk: 3}
	rows := mustRun(t, ctx)
	if len(rows) != 3 || !slices.ContainsFunc(*diags, func(d string) bool { return strings.Contains(d, "MaxMatchesPerChunk (3)") }) {
		t.Fatalf("rows %d diags %q", len(rows), *diags)
	}
}

type failing struct{ memory.MemoryReader }

func (failing) ReadAt(uint64, uint64) ([]byte, error) { return nil, memory.ErrOutOfBounds }

func TestUnreadablePhysicalMemoryIsSaidOrFailsWhenStrict(t *testing.T) {
	f := newFixture()
	ctx, diags := f.context(profiles.LinuxX64Profile{}, nil)
	ctx.Options[tools.OptionPhysicalMemory] = memory.MemoryReader(failing{f.pm})
	if _, err := Run(ctx); err != nil || !slices.ContainsFunc(*diags, func(d string) bool { return strings.Contains(d, "scan windows") }) {
		t.Fatalf("err %v diags %q", err, *diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Fatal("strict mode passed over unreadable memory")
	}
	delete(ctx.Options, tools.OptionPhysicalMemory)
	if _, err := Run(ctx); !errors.Is(err, ErrNoPhysical) {
		t.Fatalf("no physical layer: %v", err)
	}
}
