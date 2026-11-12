package processdump

import (
	"errors"
	"time"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/minidump"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/windows/handlelist"
	"github.com/aoiflux/libvapour/tools/windows/librarylist"
	"github.com/aoiflux/libvapour/tools/windows/threadlist"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

const (
	platformNT = uint32(2)

	productFirst = uint32(1)
	productLast  = uint32(3)

	// HRESULT_FROM_WIN32(ERROR_PARTIAL_COPY): part of the thread's state was
	// not readable.
	errorPartialCopy = uint32(0x8007012B)

	filetimeUnixEpoch = int64(116444736000000000)
)

func (g *gatherer) system() minidump.SystemInfo {
	ctx := g.ctx
	si := minidump.SystemInfo{PlatformID: platformNT}
	switch ctx.Symbols.PointerSize() {
	case 8:
		si.ProcessorArchitecture = minidump.ProcessorArchitectureAMD64
	case 4:
		si.ProcessorArchitecture = minidump.ProcessorArchitectureIntel
	default:
		si.ProcessorArchitecture = minidump.ProcessorArchitectureUnknown
	}
	b := winkernel.ReadBuild(Name, ctx.Memory, ctx.Symbols)
	if b.VersionErr == nil {
		si.MajorVersion, si.MinorVersion = b.Major, b.Minor
	} else {
		g.note("system version not read, written as 0.0: %v", b.VersionErr)
	}
	switch {
	case b.KernelErr == nil && b.Kernel != 0:
		si.BuildNumber = b.Kernel
	case b.SharedErr == nil && b.Shared != 0:
		si.BuildNumber = b.Shared
	default:
		g.note("build number not read, written as 0: %v", errors.Join(b.KernelErr, b.SharedErr))
	}

	shared := winkernel.SharedDataAddress(ctx.Symbols)
	if n, ok := g.sharedValue(shared, "ActiveProcessorCount"); ok && n >= 1 && n <= 0xFF {
		si.NumberOfProcessors = uint8(n)
	} else {
		g.note("_KUSER_SHARED_DATA.ActiveProcessorCount not read or outside 1-255, processor count written as 0")
	}
	if n, ok := g.sharedValue(shared, "NtProductType"); ok && n >= productFirst && n <= productLast {
		si.ProductType = uint8(n)
	} else {
		g.note("_KUSER_SHARED_DATA.NtProductType not read or outside 1-3, product type written as 0")
	}
	if n, ok := g.sharedValue(shared, "SuiteMask"); ok && n <= 0xFFFF {
		si.SuiteMask = uint16(n)
	}
	return si
}

func (g *gatherer) sharedValue(base uint64, member string) (uint32, bool) {
	f, err := g.ctx.Symbols.Field("_KUSER_SHARED_DATA", member)
	if err != nil {
		return 0, false
	}
	v, err := g.ctx.Symbols.ReadUint32(g.ctx.Memory, base+f.Offset)
	return v, err == nil
}

func (g *gatherer) modules() map[uint64][]minidump.Module {
	dlls, err := librarylist.Run(g.ctx)
	if err != nil {
		g.note("module list not read, no modules written: %v", err)
		return nil
	}
	out := map[uint64][]minidump.Module{}
	seen := map[[2]uint64]bool{}
	headersUnread, noSize := 0, 0
	for _, d := range dlls {
		key := [2]uint64{d.PID, d.Base}
		if !g.kept[d.PID] || d.Base == 0 || seen[key] {
			continue
		}
		seen[key] = true
		m := minidump.Module{Base: d.Base}
		switch {
		case !d.FullPathUnreadable && d.FullPath != "":
			m.Name = d.FullPath
		case !d.NameUnreadable:
			m.Name = d.Name
		}
		if !d.SizeUnreadable {
			m.Size = d.Size
		}
		if space := g.space(d.PID); space != nil {
			if h, err := extract.ReadHeaders(space, d.Base); err == nil {
				m.TimeDateStamp = h.File.TimeDateStamp
				m.CheckSum = h.Optional.CheckSum
				if m.Size == 0 {
					m.Size = uint64(h.Optional.SizeOfImage)
				}
			} else {
				headersUnread++
			}
		} else {
			headersUnread++
		}
		if m.Size == 0 {
			noSize++
			continue
		}
		out[d.PID] = append(out[d.PID], m)
	}
	if headersUnread > 0 {
		g.note("%d module headers not read, their TimeDateStamp and CheckSum written as 0", headersUnread)
	}
	if noSize > 0 {
		g.note("%d modules with no readable size left out", noSize)
	}
	return out
}

type stackLayout struct {
	tib, base, limit uint64
	ok               bool
}

func (g *gatherer) stackLayout() stackLayout {
	t := g.ctx.Symbols
	tib, err1 := t.Field("_TEB", "NtTib")
	base, err2 := t.Field("_NT_TIB", "StackBase")
	limit, err3 := t.Field("_NT_TIB", "StackLimit")
	if err := errors.Join(err1, err2, err3); err != nil {
		g.note("thread stacks not read: %v", err)
		return stackLayout{}
	}
	return stackLayout{tib: tib.Offset, base: base.Offset, limit: limit.Offset, ok: true}
}

// _NT_TIB.StackBase is the high end of the stack and StackLimit the low end;
// the dump wants the low end and the size.
func (g *gatherer) userStack(l stackLayout, pid, teb uint64) (low, size uint64, ok bool) {
	space := g.space(pid)
	if !l.ok || space == nil || teb == 0 {
		return 0, 0, false
	}
	high, err := g.ctx.Symbols.ReadPointer(space, teb+l.tib+l.base)
	if err != nil {
		return 0, 0, false
	}
	low, err = g.ctx.Symbols.ReadPointer(space, teb+l.tib+l.limit)
	if err != nil || low == 0 || high <= low || !g.insideOneRange(pid, low, high-1) {
		return 0, 0, false
	}
	return low, high - low, true
}

func (g *gatherer) insideOneRange(pid, first, last uint64) bool {
	for _, m := range g.ranges[pid] {
		if first >= m.Start && last <= m.End {
			return true
		}
	}
	return false
}

func filetime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	v := t.UnixNano()/100 + filetimeUnixEpoch
	if v < 0 {
		return 0
	}
	return uint64(v)
}

func (g *gatherer) threads() map[uint64][]minidump.Thread {
	list, err := threadlist.Run(g.ctx)
	if err != nil {
		g.note("thread list not read, no threads written: %v", err)
		return nil
	}
	l := g.stackLayout()
	contexts := g.ctx.Symbols.PointerSize() == 8
	if !contexts {
		g.note("thread registers not written: the AMD64 context needs a 64-bit kernel")
	}
	out := map[uint64][]minidump.Thread{}
	total, withContext, noFrame, kernelMode, unread, partial, noStack, rspOutside := 0, 0, 0, 0, 0, 0, 0, 0
	for _, t := range list {
		if !g.kept[t.PID] {
			continue
		}
		total++
		th := minidump.Thread{
			ID:           uint32(t.TID),
			SuspendCount: uint32(max(t.SuspendCount, 0)),
			Priority:     uint32(max(t.Priority, 0)),
		}
		if !t.TebUnreadable {
			th.Teb = t.Teb
		}
		if !t.CreateTimeUnreadable {
			th.CreateTime = filetime(t.CreateTime)
		}
		if !t.ExitTimeUnreadable {
			th.ExitTime = filetime(t.ExitTime)
		}
		if !t.Win32StartAddressUnreadable {
			th.StartAddress = t.Win32StartAddress
		}
		if t.TebUnreadable || t.SuspendCountUnreadable || t.PriorityUnreadable || t.TrapFrameUnreadable {
			th.DumpError = errorPartialCopy
			partial++
		}
		low, size, stackOK := g.userStack(l, t.PID, th.Teb)
		if stackOK {
			th.StackBase, th.StackSize = low, size
		} else {
			noStack++
		}
		if contexts && !t.TrapFrameUnreadable {
			regs, err := threadlist.ReadTrapFrame(g.ctx, t.TrapFrame)
			switch {
			case err == nil && stackOK && (regs.Rsp < low || regs.Rsp >= low+size):
				rspOutside++
			case err == nil:
				th.Context = amd64Context(regs).Bytes()
				withContext++
			case errors.Is(err, threadlist.ErrNoTrapFrame):
				noFrame++
			case errors.Is(err, threadlist.ErrKernelModeTrapFrame):
				kernelMode++
			default:
				unread++
				th.DumpError = errorPartialCopy
			}
		}
		out[t.PID] = append(out[t.PID], th)
	}
	if total > 0 {
		g.note("%d of %d threads with registers; without: %d no trap frame, %d kernel-mode trap frame, %d trap frame not read, %d stack pointer outside the stack",
			withContext, total, noFrame, kernelMode, unread, rspOutside)
	}
	if noStack > 0 {
		g.note("%d of %d threads without a stack range: TEB absent, not read, or StackLimit and StackBase not one ordered span inside a VAD", noStack, total)
	}
	if partial > 0 {
		g.note("%d of %d threads with a member not read, written as 0 with DumpError 0x%x", partial, total, errorPartialCopy)
	}
	return out
}

// A trap frame holds no R12 to R15, so the integer group is not claimed: a
// reader trusts every group the flags name.
func amd64Context(r threadlist.Registers) minidump.AMD64Context {
	return minidump.AMD64Context{
		Flags: minidump.ContextAMD64 | minidump.ContextControl | minidump.ContextSegments,
		Rax:   r.Rax, Rcx: r.Rcx, Rdx: r.Rdx, Rbx: r.Rbx,
		Rsp: r.Rsp, Rbp: r.Rbp, Rsi: r.Rsi, Rdi: r.Rdi,
		R8: r.R8, R9: r.R9, R10: r.R10, R11: r.R11,
		Rip: r.Rip, EFlags: r.EFlags, MxCsr: r.MxCsr,
		SegCs: r.SegCs, SegDs: r.SegDs, SegEs: r.SegEs, SegFs: r.SegFs, SegGs: r.SegGs, SegSs: r.SegSs,
	}
}

func (g *gatherer) handles() map[uint64][]minidump.Handle {
	list, err := handlelist.Run(g.ctx)
	if err != nil {
		g.note("handle list not read, no handles written: %v", err)
		return nil
	}
	out := map[uint64][]minidump.Handle{}
	for _, h := range list {
		if !g.kept[h.PID] {
			continue
		}
		out[h.PID] = append(out[h.PID], minidump.Handle{
			Handle:        h.HandleValue,
			TypeName:      h.TypeName,
			ObjectName:    objectName(h),
			GrantedAccess: uint32(h.GrantedAccess),
		})
	}
	return out
}

// Process and thread objects have no name; the handle list's label for them
// names the target, which is not an object name.
func objectName(h handlelist.Handle) string {
	if h.NameUnreadable || h.TypeName == "Process" || h.TypeName == "Thread" {
		return ""
	}
	return h.ObjectName
}

func (g *gatherer) regions() map[uint64][]minidump.Region {
	out := map[uint64][]minidump.Region{}
	limit := g.ctx.DumpLimit()
	unknown, overLimit := 0, 0
	for _, p := range g.procs {
		space := g.space(p.PID)
		for _, m := range g.ranges[p.PID] {
			size, ok := extract.RegionSize(m.Start, m.End)
			if !ok {
				continue
			}
			r := minidump.Region{BaseAddress: m.Start, AllocationBase: m.Start, Size: size,
				State: minidump.MemCommit, Type: regionType(m.Type)}
			protect, known := memoryranges.Win32Protection(m.Protection)
			if known {
				r.Protect, r.AllocationProtect = protect, protect
			} else {
				unknown++
			}
			switch {
			case !known || space == nil:
				out[p.PID] = append(out[p.PID], r)
			case size > limit:
				overLimit++
				out[p.PID] = append(out[p.PID], r)
			default:
				out[p.PID] = append(out[p.PID], residentPieces(space, r)...)
			}
		}
	}
	if unknown > 0 {
		g.note("%d VAD ranges with protection unknown listed without contents", unknown)
	}
	if overLimit > 0 {
		g.note("%d VAD ranges over the %d-byte dump limit listed without contents", overLimit, limit)
	}
	return out
}

// The format has no way to mark a hole inside a memory range, so a range is
// cut where its pages stop reading: written bytes are then always captured
// bytes, never zero fill for a page the capture does not hold.
func residentPieces(space memory.MemoryReader, r minidump.Region) []minidump.Region {
	var out []minidump.Region
	emit := func(base, end uint64, resident bool) {
		piece := r
		piece.BaseAddress, piece.Size, piece.Dumpable = base, end-base, resident
		out = append(out, piece)
	}
	runStart, runResident := r.BaseAddress, false
	for page := r.BaseAddress; page < r.BaseAddress+r.Size; page += tools.PageSize {
		_, err := space.ReadAt(page, 1)
		resident := err == nil
		if page == r.BaseAddress {
			runResident = resident
			continue
		}
		if resident != runResident {
			emit(runStart, page, runResident)
			runStart, runResident = page, resident
		}
	}
	emit(runStart, r.BaseAddress+r.Size, runResident)
	return out
}

func regionType(kind string) uint32 {
	switch kind {
	case memoryranges.KindImage:
		return minidump.MemImage
	case memoryranges.KindMapped:
		return minidump.MemMapped
	default:
		return minidump.MemPrivate
	}
}
