package memorycode

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	pteRW         = uint64(1) << 1
	pteDirty      = uint64(1) << 6
	pteSavedDirty = uint64(1) << 58
	pteNoExec     = uint64(1) << 63

	flagsRX  = vmRead | vmExec
	flagsRWX = vmRead | vmWrite | vmExec
	flagsRW  = vmRead | vmWrite
)

// A page of compiled code: ENDBR64 then a return.
var codePage = []byte{0xf3, 0x0f, 0x1e, 0xfa, 0xc3}

type linuxPageSpec struct {
	at    uint64
	flags uint64
	data  []byte
}

type linuxAreaSpec struct {
	start, end, flags uint64
	file              string
	pages             []linuxPageSpec
	special           bool
}

type linuxFixture struct {
	t       *testing.T
	k       *lt.Kernel
	us      *lt.UserSpaces
	fs      *lt.RootFS
	special uint64
	tasks   []uint64
}

func newLinuxFixture(t *testing.T, release string) *linuxFixture {
	t.Helper()
	return newLinuxFixtureWith(t, release, true)
}

func newLinuxFixtureWith(t *testing.T, release string, specialTable bool) *linuxFixture {
	t.Helper()
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	lt.AddAreaOperations(k)
	f := &linuxFixture{t: t, k: k, us: k.NewUserSpaces(32 << 20), fs: k.NewRootFS()}
	f.special = k.Alloc(lt.S39OpsSize)
	if specialTable {
		k.Table.AddSymbol(symbols.Symbol{Name: "special_mapping_vmops", Address: f.special})
	}
	if release != "" {
		banner := "Linux version " + release + " (builder@host) (gcc 14.2.1, GNU ld 2.41) #1 SMP PREEMPT_DYNAMIC\n"
		k.Table.AddSymbol(symbols.Symbol{Name: "linux_banner", Address: k.Str(banner)})
	}
	return f
}

func (f *linuxFixture) process(pid int32, comm string, areas ...linuxAreaSpec) (task uint64, as *testsupport.AddressSpace) {
	f.t.Helper()
	pgd, as := f.us.New()
	vmas := make([]lt.VMA, len(areas))
	for i, a := range areas {
		vmas[i] = lt.VMA{Start: a.start, End: a.end, Flags: a.flags}
		if a.file != "" {
			vmas[i].File = f.fs.File(a.file, 1, int64(a.end-a.start))
		}
		for _, p := range a.pages {
			pa := as.MapPageFlags(p.at, p.flags)
			f.us.PM.WriteAt(pa, p.data)
		}
	}
	mm := f.k.AddMM(lt.MM{PGD: pgd, VMAs: vmas})
	for _, a := range areas {
		if a.special {
			f.k.Mem.U64(f.areaAt(mm, a.start)+lt.S39VMAOps, f.special)
		}
	}
	task = f.k.AddTask(lt.Task{PID: pid, TGID: pid, Comm: comm, MM: mm})
	f.fs.Enter(task)
	f.tasks = append(f.tasks, task)
	f.k.LinkTasks(f.tasks...)
	return task, as
}

func (f *linuxFixture) areaAt(mm, start uint64) uint64 {
	read := func(at uint64) uint64 {
		b, err := f.k.Mem.ReadAt(at, 8)
		if err != nil {
			f.t.Fatal(err)
		}
		return binary.LittleEndian.Uint64(b)
	}
	for vma := read(mm + lt.FSMMMmap); vma != 0; vma = read(vma + lt.FSVMANext) {
		if read(vma+lt.FSVMAStart) == start {
			return vma
		}
	}
	f.t.Fatalf("no area at %#x", start)
	return 0
}

func (f *linuxFixture) context(opts map[string]any) (tools.Context, *[]string) {
	return f.us.Context(opts)
}

func (f *linuxFixture) run(opts map[string]any) ([]LinuxFinding, []string, error) {
	f.t.Helper()
	ctx, diags := f.context(opts)
	rows, err := RunLinux(ctx)
	return rows, *diags, err
}

func mustRun(t *testing.T, f *linuxFixture, opts map[string]any) ([]LinuxFinding, []string) {
	t.Helper()
	rows, diags, err := f.run(opts)
	if err != nil {
		t.Fatal(err)
	}
	return rows, diags
}

func rulesOf(rows []LinuxFinding) map[uint64]Rule {
	out := map[uint64]Rule{}
	for _, r := range rows {
		out[r.Start] = r.Rule
	}
	return out
}

func hasDiag(diags []string, part string) bool {
	return slices.ContainsFunc(diags, func(d string) bool { return strings.Contains(d, part) })
}

func TestEachLinuxRuleTakesTheAreasItNames(t *testing.T) {
	f := newLinuxFixture(t, "6.17.0-35-generic")
	f.process(100, "gnome-shell",
		linuxAreaSpec{start: 0x10000, end: 0x12000, flags: flagsRX,
			pages: []linuxPageSpec{{at: 0x10000, flags: pteSavedDirty, data: codePage}}},
		linuxAreaSpec{start: 0x20000, end: 0x21000, flags: flagsRWX,
			pages: []linuxPageSpec{{at: 0x20000, flags: pteRW | pteDirty, data: codePage}}},
		linuxAreaSpec{start: 0x30000, end: 0x32000, flags: flagsRX, file: "/usr/lib/libpatched.so",
			pages: []linuxPageSpec{{at: 0x30000, data: codePage}, {at: 0x31000, flags: pteSavedDirty, data: codePage}}},
		linuxAreaSpec{start: 0x40000, end: 0x41000, flags: flagsRX, file: "/usr/lib/libclean.so",
			pages: []linuxPageSpec{{at: 0x40000, data: codePage}}},
		linuxAreaSpec{start: 0x50000, end: 0x52000, flags: flagsRW,
			pages: []linuxPageSpec{{at: 0x50000, flags: pteRW | pteNoExec, data: []byte{1}}, {at: 0x51000, flags: pteRW, data: codePage}}},
		linuxAreaSpec{start: 0x60000, end: 0x62000, flags: flagsRX, special: true,
			pages: []linuxPageSpec{{at: 0x60000, data: []byte("\x7fELF\x02\x01\x01")}}},
		linuxAreaSpec{start: 0x70000, end: 0x71000, flags: flagsRX,
			pages: []linuxPageSpec{{at: 0x70000, data: nil}}},
	)
	rows, diags := mustRun(t, f, nil)
	want := map[uint64]Rule{0x10000: RuleAnonymous, 0x20000: RuleWritable, 0x30000: RuleWrittenFile, 0x51000 &^ 0xffff: RulePage}
	if got := rulesOf(rows); !equalRules(got, want) {
		t.Fatalf("rules %v, want %v", got, want)
	}
	if !hasDiag(diags, "1 executable regions hold no readable nonzero byte") {
		t.Errorf("the area of zeros is not counted: %q", diags)
	}
	for _, r := range rows {
		switch r.Start {
		case 0x10000:
			if r.Protection != "r-xp" || r.Backing != BackingNone || r.End != 0x11fff || r.Pages != 2 ||
				r.ResidentPages != 1 || r.WrittenPages != 1 || r.ContentPages != 1 || r.FirstContent != 0x10000 {
				t.Errorf("anonymous row %+v", r)
			}
		case 0x30000:
			if r.Backing != BackingFile || r.Path != "/usr/lib/libpatched.so" || !r.PathAvailable ||
				r.WrittenPages != 1 || r.FirstWritten != 0x31000 || r.ContentPages != 2 {
				t.Errorf("written file row %+v", r)
			}
		case 0x50000:
			if r.ExecutablePages != 1 || r.FirstContent != 0x51000 || r.Protection != "rw-p" {
				t.Errorf("page row %+v", r)
			}
		}
		if r.PID != 100 || r.Process != "gnome-shell" || r.AreaAddress == 0 {
			t.Errorf("row identity %+v", r)
		}
	}
}

func equalRules(a, b map[uint64]Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestWritableAnonymousCodeIsTakenAsWritable(t *testing.T) {
	f := newLinuxFixture(t, "6.17.0")
	f.process(7, "jit", linuxAreaSpec{start: 0x10000, end: 0x11000, flags: flagsRWX | vmMayShare,
		pages: []linuxPageSpec{{at: 0x10000, flags: pteRW, data: codePage}}})
	rows, _ := mustRun(t, f, nil)
	if len(rows) != 1 || rows[0].Rule != RuleWritable || rows[0].Protection != "rwxs" {
		t.Fatalf("rows %+v", rows)
	}
}

func TestTheSavedDirtyBitCountsOnlyWhereItWasChecked(t *testing.T) {
	cases := []struct {
		release string
		written uint64
		diag    bool
	}{
		{"6.17.0-35-generic", 1, false},
		{"6.14.5-100.fc40.x86_64", 1, false},
		{"6.4.0", 0, false},
		{"4.19.0", 0, false},
		{"6.10.3", 0, true},
		{"", 0, true},
	}
	for _, c := range cases {
		f := newLinuxFixture(t, c.release)
		f.process(1, "p", linuxAreaSpec{start: 0x10000, end: 0x11000, flags: flagsRX,
			pages: []linuxPageSpec{{at: 0x10000, flags: pteSavedDirty, data: codePage}}})
		rows, diags := mustRun(t, f, nil)
		if len(rows) != 1 || rows[0].WrittenPages != c.written {
			t.Errorf("%q: rows %+v, want %d written", c.release, rows, c.written)
		}
		if got := hasDiag(diags, "pages written while read-only are not counted"); got != c.diag {
			t.Errorf("%q: diagnostic %v, want %v: %q", c.release, got, c.diag, diags)
		}
	}
}

func TestAFileAreaWrittenOnlyWithSavedDirtyIsUnlistedBeforeSixFourteen(t *testing.T) {
	f := newLinuxFixture(t, "6.1.0")
	f.process(1, "p", linuxAreaSpec{start: 0x10000, end: 0x11000, flags: flagsRX, file: "/bin/p",
		pages: []linuxPageSpec{{at: 0x10000, flags: pteSavedDirty, data: codePage}}})
	if rows, _ := mustRun(t, f, nil); len(rows) != 0 {
		t.Fatalf("rows %+v", rows)
	}
}

func TestEveryWrittenPageIsListedOnlyWhenAsked(t *testing.T) {
	f := newLinuxFixture(t, "6.17.0")
	f.process(1, "p", linuxAreaSpec{start: 0x10000, end: 0x13000, flags: flagsRX, file: "/bin/p",
		pages: []linuxPageSpec{{at: 0x10000, data: codePage}, {at: 0x11000, flags: pteDirty, data: codePage},
			{at: 0x12000, flags: pteSavedDirty, data: codePage}}})
	rows, _ := mustRun(t, f, nil)
	if len(rows) != 1 || rows[0].WrittenAddresses != nil || rows[0].FirstWritten != 0x11000 || rows[0].WrittenPages != 2 {
		t.Fatalf("default rows %+v", rows)
	}
	rows, _ = mustRun(t, f, map[string]any{OptionShowAllDirtyPages: true})
	if len(rows) != 1 || !slices.Equal(rows[0].WrittenAddresses, []uint64{0x11000, 0x12000}) {
		t.Fatalf("rows with the option %+v", rows)
	}
}

func TestWithoutAnyNoExecuteBitNoPageIsTakenAsMadeExecutable(t *testing.T) {
	f := newLinuxFixture(t, "6.17.0")
	f.process(1, "p", linuxAreaSpec{start: 0x10000, end: 0x11000, flags: flagsRW,
		pages: []linuxPageSpec{{at: 0x10000, flags: pteRW, data: codePage}}})
	if rows, _ := mustRun(t, f, nil); len(rows) != 0 {
		t.Fatalf("rows %+v", rows)
	}
}

func TestTheStartOfAnAreaGivesItsHeaderAndFirstTransfer(t *testing.T) {
	f := newLinuxFixture(t, "6.17.0")
	elf := make([]byte, 64)
	copy(elf, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(elf[18:], 62)
	jump := []byte{0xe9, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(jump[1:], uint32(0x40100-(0x20000+5)))
	f.process(1, "p",
		linuxAreaSpec{start: 0x10000, end: 0x11000, flags: flagsRWX, pages: []linuxPageSpec{{at: 0x10000, flags: pteRW, data: elf}}},
		linuxAreaSpec{start: 0x20000, end: 0x21000, flags: flagsRX, pages: []linuxPageSpec{{at: 0x20000, data: jump}}},
		linuxAreaSpec{start: 0x40000, end: 0x41000, flags: flagsRX, file: "/usr/lib/libc.so.6",
			pages: []linuxPageSpec{{at: 0x40000, data: codePage}}},
	)
	rows, _ := mustRun(t, f, nil)
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	if rows[0].Header != HeaderELF || rows[0].HeaderMachine != 62 {
		t.Errorf("header %q %d", rows[0].Header, rows[0].HeaderMachine)
	}
	if r := rows[1]; r.Header != HeaderNone || r.Transfer != TransferJumpRel32 || r.TransferTarget != 0x40100 ||
		r.TransferImage != "/usr/lib/libc.so.6" {
		t.Errorf("transfer row %+v", r)
	}
}

func TestThePreviewAndDumpFollowTheirOptions(t *testing.T) {
	f := newLinuxFixture(t, "6.17.0")
	f.process(9, "p", linuxAreaSpec{start: 0x10000, end: 0x12000, flags: flagsRX,
		pages: []linuxPageSpec{{at: 0x11000, data: codePage}}})
	dir := t.TempDir()
	rows, _ := mustRun(t, f, map[string]any{OptionHexdumpSize: uint64(4), OptionDumpRegions: true, tools.OptionOutputDir: dir})
	if len(rows) != 1 || !bytes.Equal(rows[0].Preview, codePage[:4]) || rows[0].Artifact == "" {
		t.Fatalf("rows %+v", rows)
	}
	got, err := os.ReadFile(filepath.Join(dir, rows[0].Artifact))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0x2000 || !bytes.Equal(got[0x1000:0x1005], codePage) || hasNonzero(got[:0x1000]) {
		t.Errorf("dump of %d bytes", len(got))
	}
	if _, _, err := f.run(map[string]any{OptionHexdumpSize: uint64(1) << 40}); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("an oversized preview: %v", err)
	}
	if _, _, err := f.run(map[string]any{OptionDumpRegions: true}); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("a dump without a directory: %v", err)
	}
	if _, _, err := f.run(map[string]any{OptionShowAllDirtyPages: "maybe"}); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("a string flag: %v", err)
	}
}

func TestATaskWithoutItsOwnSpaceIsPassedOver(t *testing.T) {
	f := newLinuxFixture(t, "6.17.0")
	kthread := f.k.AddTask(lt.Task{PID: 2, TGID: 2, Comm: "kthreadd"})
	f.tasks = append(f.tasks, kthread)
	pgd := f.k.Alloc(0x1000)
	mm := f.k.AddMM(lt.MM{PGD: pgd, VMAs: []lt.VMA{{Start: 0x10000, End: 0x11000, Flags: flagsRWX}}})
	lost := f.k.AddTask(lt.Task{PID: 3, TGID: 3, Comm: "lost", MM: mm})
	f.tasks = append(f.tasks, lost)
	f.k.LinkTasks(f.tasks...)
	rows, diags := mustRun(t, f, nil)
	if len(rows) != 0 || !hasDiag(diags, "pid 3 task_struct") || !hasDiag(diags, "address space not built") {
		t.Fatalf("rows %+v diags %q", rows, diags)
	}
	if _, _, err := f.run(map[string]any{"strict": true}); err == nil {
		t.Fatal("strict mode passed over a task it could not read")
	}
}

type noEntries struct{ memory.MemoryReader }

func TestALayerWithoutLeafEntriesSkipsTheTask(t *testing.T) {
	f := newLinuxFixture(t, "6.17.0")
	f.process(5, "p", linuxAreaSpec{start: 0x10000, end: 0x11000, flags: flagsRWX,
		pages: []linuxPageSpec{{at: 0x10000, flags: pteRW, data: codePage}}})
	ctx, diags := f.context(nil)
	inner := ctx.ProcessMemory
	ctx.ProcessMemory = func(dtb uint64) (memory.MemoryReader, error) {
		r, err := inner(dtb)
		return noEntries{r}, err
	}
	rows, err := RunLinux(ctx)
	if err != nil || len(rows) != 0 || !hasDiag(*diags, ErrNoPageEntries.Error()) {
		t.Fatalf("rows %+v err %v diags %q", rows, err, *diags)
	}
}

func TestTheWalkStopsAtTheRegionBudget(t *testing.T) {
	f := newLinuxFixture(t, "6.17.0")
	var pages []linuxPageSpec
	for at := uint64(0x10000); at < 0x14000; at += 0x1000 {
		pages = append(pages, linuxPageSpec{at: at, flags: pteRW, data: codePage})
	}
	f.process(5, "p", linuxAreaSpec{start: 0x10000, end: 0x14000, flags: flagsRWX, pages: pages})
	ctx, diags := f.context(nil)
	ctx.Limits = limits.Limits{MaxRegionScanBytes: 2 * 0x1000}
	rows, err := RunLinux(ctx)
	if err != nil || len(rows) != 1 || rows[0].ResidentPages != 2 || !hasDiag(*diags, ErrRegionScanCut.Error()) {
		t.Fatalf("rows %+v err %v diags %q", rows, err, *diags)
	}
	ctx.Options["strict"] = true
	if _, err := RunLinux(ctx); !errors.Is(err, ErrRegionScanCut) {
		t.Fatalf("strict: %v", err)
	}
}

func TestAMissingSpecialMappingTableIsSaid(t *testing.T) {
	f := newLinuxFixtureWith(t, "6.17.0", false)
	f.process(1, "p", linuxAreaSpec{start: 0x10000, end: 0x11000, flags: flagsRX, special: true,
		pages: []linuxPageSpec{{at: 0x10000, data: codePage}}})
	rows, diags := mustRun(t, f, nil)
	if len(rows) != 1 || !hasDiag(diags, "kernel-installed areas are not told apart") {
		t.Fatalf("rows %+v diags %q", rows, diags)
	}
}

func TestAnyDispatchesByProfile(t *testing.T) {
	f := newLinuxFixture(t, "6.17.0")
	ctx, _ := f.context(nil)
	got, err := RunAny(ctx)
	if _, ok := got.([]LinuxFinding); err != nil || !ok {
		t.Fatalf("linux profile gave %T, %v", got, err)
	}
	ctx.Profile = profiles.WindowsX64Profile{}
	if _, err := RunLinux(ctx); !errors.Is(err, ErrNotLinux) {
		t.Fatalf("windows profile in RunLinux: %v", err)
	}
}
