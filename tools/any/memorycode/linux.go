package memorycode

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/disasm"
	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	"github.com/aoiflux/libvapour/util"
)

const (
	OptionHexdumpSize       = "any.memory.find_code.hexdump_size"
	OptionShowAllDirtyPages = "any.memory.find_code.show_all_dirty_pages"
	OptionDumpRegions       = "any.memory.find_code.dump_regions"
)

var ErrNotLinux = errors.New("memorycode: profile os is not linux")

const (
	RuleWritable    Rule = "writable-executable"
	RuleAnonymous   Rule = "anonymous-executable"
	RuleWrittenFile Rule = "written-file-executable"
)

const HeaderELF Header = "elf"

// S47 L1.
const (
	vmRead     = uint64(0x1)
	vmWrite    = uint64(0x2)
	vmExec     = uint64(0x4)
	vmMayShare = uint64(0x80)
)

// The tables _install_special_mapping puts in vm_ops (S47 L7).
var specialMappingTables = []string{"special_mapping_vmops", "legacy_special_mapping_vmops"}

type LinuxFinding struct {
	PID           int64
	Process       string
	AreaAddress   uint64
	Start         uint64
	End           uint64
	Protection    string
	Backing       Backing
	Path          string
	PathAvailable bool
	Rule          Rule

	Pages            uint64
	ExecutablePages  uint64
	ResidentPages    uint64
	WrittenPages     uint64
	ContentPages     uint64
	FirstContent     uint64
	FirstWritten     uint64
	WrittenAddresses []uint64

	Header        Header
	HeaderMachine uint16

	Transfer             Transfer
	TransferTarget       uint64
	TransferTargetUnread bool
	TransferImage        string

	Preview  []byte
	Artifact string
}

type linuxRun struct {
	ctx     tools.Context
	k       *linuxobj.Kernel
	areas   *memoryranges.LinuxWalker
	opts    windowsOptions
	allDirt bool
	special map[uint64]bool
	written writtenBits
	budget  uint64

	withoutContent   int
	dumpFailed       int
	firstDumpFailure string
}

func RunLinux(ctx tools.Context) ([]LinuxFinding, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: %w: %q", Name, ErrNotLinux, ctx.Profile.OS())
	}
	opts, err := readWindowsOptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	allDirt, err := ctx.BoolOption(OptionShowAllDirtyPages)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := linuxobj.New(ctx)
	areas, err := memoryranges.NewLinuxWalker(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk, err := k.Walker().Tasks(false, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	r := &linuxRun{ctx: ctx, k: k, areas: areas, opts: opts, allDirt: allDirt, budget: regionBudget(ctx),
		special: map[uint64]bool{}}
	for _, name := range specialMappingTables {
		if sym, err := k.Symbol(name); err == nil {
			r.special[sym.Address] = true
		}
	}
	if len(r.special) == 0 {
		ctx.AddDiagnostic("%s: special_mapping_vmops: not in symbols, kernel-installed areas are not told apart", Name)
	}
	r.written = r.writtenBits()

	var out []LinuxFinding
	for _, task := range walk.Tasks {
		rows, err := r.task(linuxobj.Task{Addr: task})
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	if r.withoutContent > 0 {
		ctx.AddDiagnostic("%s: %d executable regions hold no readable nonzero byte in an executable page and are not listed", Name, r.withoutContent)
	}
	if r.dumpFailed > 0 {
		ctx.AddDiagnostic("%s: %d regions not written, first: %s", Name, r.dumpFailed, r.firstDumpFailure)
	}
	return out, nil
}

func (r *linuxRun) writtenBits() writtenBits {
	why := ""
	release, err := r.runningRelease()
	bits, settled := writtenBitsFor(release)
	switch {
	case err != nil:
		why = err.Error()
	case !settled:
		why = fmt.Sprintf("release %q: the written mark of read-only pages was not checked for it", release)
	}
	if why != "" {
		r.ctx.AddDiagnostic("%s: linux_banner: %s: pages written while read-only are not counted", Name, why)
	}
	return bits
}

func (r *linuxRun) runningRelease() (string, error) {
	sym, err := r.k.Symbol("linux_banner")
	if err != nil {
		return "", err
	}
	b, err := r.k.Memory().ReadAt(sym.Address, uint64(len(bannerPrefix))+releaseBytes)
	if err != nil {
		return "", fmt.Errorf("at 0x%x: %w", sym.Address, err)
	}
	release, ok := bannerRelease(string(b))
	if !ok {
		return "", fmt.Errorf("at 0x%x: no release after %q", sym.Address, bannerPrefix)
	}
	return release, nil
}

// UTS_RELEASE is at most 64 bytes (S47 B2), and one more holds its end.
const releaseBytes = 65

func (r *linuxRun) problem(object string, addr uint64, what string, err error) error {
	if r.ctx.StrictMode() {
		return fmt.Errorf("%s: %s at 0x%x: %s: %w", Name, object, addr, what, err)
	}
	r.ctx.AddDiagnostic("%s: %s at 0x%x: %s: %v", Name, object, addr, what, err)
	return nil
}

type linuxArea struct {
	vma   memoryranges.LinuxVMA
	flags uint64
	pages areaPages
}

func (r *linuxRun) task(t linuxobj.Task) ([]LinuxFinding, error) {
	k := r.k
	pid, err := k.PID(t)
	if err != nil {
		return nil, r.problem("task_struct", k.Masked(t.Addr), "pid not read", err)
	}
	object := fmt.Sprintf("pid %d task_struct", pid)
	layer, ok, why, err := k.ProcessLayer(t)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !ok {
		if why != nil {
			return nil, r.problem(object, k.Masked(t.Addr), "address space not built", why)
		}
		return nil, nil
	}
	le, ok := layer.Reader.(leafEntries)
	if !ok {
		return nil, r.problem(object, k.Masked(t.Addr), "page-table entries not read", ErrNoPageEntries)
	}
	comm, err := k.Comm(t)
	if err != nil {
		return nil, r.problem(object, k.Masked(t.Addr), "comm not read", err)
	}
	mm, vmas, walkErr := r.areas.TaskVMAs(t.Addr)
	if walkErr != nil {
		if err := r.problem(object, k.Masked(t.Addr), "memory areas walked in part", walkErr); err != nil {
			return nil, err
		}
	}

	areas := make([]linuxArea, 0, len(vmas))
	noExecInUse := false
	for _, v := range vmas {
		flags, err := k.Uint(k.Memory(), v.Addr, "vm_area_struct", "vm_flags")
		if err != nil {
			if err := r.problem(fmt.Sprintf("pid %d vm_area_struct", pid), k.Masked(v.Addr), "vm_flags not read", err); err != nil {
				return nil, err
			}
			continue
		}
		a := linuxArea{vma: v, flags: flags, pages: walkArea(le, v.Start, v.End-1, r.written, r.budget)}
		if a.pages.cut {
			what := fmt.Sprintf("page walk stopped after %d entries", r.budget)
			if err := r.problem(fmt.Sprintf("pid %d vm_area_struct", pid), k.Masked(v.Addr), what, ErrRegionScanCut); err != nil {
				return nil, err
			}
		}
		noExecInUse = noExecInUse || a.pages.noExecSet > 0
		areas = append(areas, a)
	}

	name := util.ReplaceInvalidUTF8(comm)
	var out []LinuxFinding
	for _, a := range areas {
		rule, ok := r.rule(a, noExecInUse)
		if !ok {
			continue
		}
		f, ok := r.finding(pid, name, mm, t, a, rule, layer.Reader, areas)
		if ok {
			out = append(out, f)
		}
	}
	return out, nil
}

func (r *linuxRun) rule(a linuxArea, noExecInUse bool) (Rule, bool) {
	exec, write := a.flags&vmExec != 0, a.flags&vmWrite != 0
	switch {
	case exec && write:
		return RuleWritable, true
	case exec && a.vma.File == 0:
		ops, err := r.k.Pointer(r.k.Memory(), a.vma.Addr, "vm_area_struct", "vm_ops")
		if err == nil && r.special[ops] {
			return "", false
		}
		return RuleAnonymous, true
	case exec:
		return RuleWrittenFile, a.pages.written > 0
	case noExecInUse && a.pages.executable > 0:
		return RulePage, true
	}
	return "", false
}

func (r *linuxRun) finding(pid int64, comm string, mm uint64, t linuxobj.Task, a linuxArea, rule Rule,
	space memory.MemoryReader, areas []linuxArea) (LinuxFinding, bool) {
	content, first := uint64(0), uint64(0)
	for _, at := range a.pages.executableAt {
		b, err := space.ReadAt(at, pageSize)
		if err != nil || !hasNonzero(b) {
			continue
		}
		if content == 0 {
			first = at
		}
		content++
	}
	if content == 0 {
		r.withoutContent++
		return LinuxFinding{}, false
	}
	v := a.vma
	f := LinuxFinding{
		PID: pid, Process: comm, AreaAddress: v.Addr, Start: v.Start, End: v.End - 1,
		Protection: mapsProtection(a.flags), Backing: BackingNone, Rule: rule,
		Pages: a.pages.pages, ExecutablePages: a.pages.executable, ResidentPages: a.pages.resident,
		WrittenPages: a.pages.written, ContentPages: content, FirstContent: first,
	}
	if v.File != 0 {
		f.Backing = BackingFile
	}
	if len(a.pages.writtenAt) > 0 {
		f.FirstWritten = a.pages.writtenAt[0]
		if r.allDirt {
			f.WrittenAddresses = a.pages.writtenAt
		}
	}
	f.Path, f.PathAvailable = r.areaName(t, mm, v)
	r.startFacts(&f, space, t, mm, areas)
	f.Preview, _ = extract.ReadPadded(space, first, r.opts.preview)
	if r.opts.dump {
		f.Artifact = r.dump(uint64(pid), space, f.Start, f.End)
	}
	return f, true
}

func (r *linuxRun) areaName(t linuxobj.Task, mm uint64, v memoryranges.LinuxVMA) (string, bool) {
	name, named, err := r.areas.AreaName(t.Addr, mm, v)
	if err != nil || !named || name == "" {
		return "", false
	}
	return name, true
}

func mapsProtection(flags uint64) string {
	out := []byte("---p")
	for i, bit := range []uint64{vmRead, vmWrite, vmExec} {
		if flags&bit != 0 {
			out[i] = "rwx"[i]
		}
	}
	if flags&vmMayShare != 0 {
		out[3] = 's'
	}
	return string(out)
}

// S47 L8: the ELF magic, then EI_CLASS 1 or 2; e_machine at 18 in both.
const (
	elfClassAt   = 4
	elfMachineAt = 18
)

var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

func elfHeader(b []byte) (Header, uint16, bool) {
	if len(b) < elfMachineAt+2 || !bytes.HasPrefix(b, elfMagic) || (b[elfClassAt] != 1 && b[elfClassAt] != 2) {
		return "", 0, false
	}
	return HeaderELF, binary.LittleEndian.Uint16(b[elfMachineAt:]), true
}

func (r *linuxRun) startFacts(f *LinuxFinding, space memory.MemoryReader, t linuxobj.Task, mm uint64, areas []linuxArea) {
	n := min(pageSize, f.End-f.Start+1)
	b, err := space.ReadAt(f.Start, n)
	if err != nil || uint64(len(b)) != n {
		f.Header = HeaderUnread
		return
	}
	if h, m, ok := elfHeader(b); ok {
		f.Header, f.HeaderMachine = h, m
	} else {
		f.Header, f.HeaderMachine = headerKind(b)
	}
	tr := firstTransfer(b, f.Start, disasm.Mode64, space)
	f.Transfer, f.TransferTarget, f.TransferTargetUnread = tr.kind, tr.target, tr.unread
	if tr.kind == TransferNone || tr.unread {
		return
	}
	for _, a := range areas {
		if a.vma.File != 0 && a.vma.Start <= tr.target && tr.target < a.vma.End {
			f.TransferImage, _ = r.areaName(t, mm, a.vma)
			return
		}
	}
}

func (r *linuxRun) dump(pid uint64, space memory.MemoryReader, start, end uint64) string {
	w := &windowsRun{ctx: r.ctx, opts: r.opts}
	name := w.dump(pid, space, start, end)
	if w.dumpFailed > 0 {
		r.dumpFailed++
		if r.firstDumpFailure == "" {
			r.firstDumpFailure = w.firstDumpFailure
		}
	}
	return name
}
