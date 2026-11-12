package processlist

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

// ImageFileName is UCHAR[15] in every measured kernel table (S25 T1).
const WindowsImageNameLength = 15

type listMembers struct {
	links     uint64
	pid       uint64
	name      symbols.CharArrayField
	pointer   uint64
	listShape winkernel.ListLayout
}

func resolveListMembers(ctx tools.Context) (listMembers, error) {
	links, err := ctx.Symbols.Field("_EPROCESS", "ActiveProcessLinks")
	if err != nil {
		return listMembers{}, fmt.Errorf("%s: _EPROCESS.ActiveProcessLinks: %w: %w", Name, ErrNoListMember, err)
	}
	pid, err := ctx.Symbols.Field("_EPROCESS", "UniqueProcessId")
	if err != nil {
		return listMembers{}, fmt.Errorf("%s: _EPROCESS.UniqueProcessId: %w: %w", Name, ErrNoListMember, err)
	}
	name, err := symbols.ResolveCharArray(ctx.Symbols, "_EPROCESS", "ImageFileName", WindowsImageNameLength)
	if err != nil {
		return listMembers{}, fmt.Errorf("%s: _EPROCESS.ImageFileName: %w: %w", Name, ErrNoListMember, err)
	}
	shape, err := winkernel.NativeListLayout(ctx.Symbols)
	if err != nil {
		return listMembers{}, fmt.Errorf("%s: %w", Name, err)
	}
	return listMembers{links: links.Offset, pid: pid.Offset, name: name,
		pointer: uint64(ctx.Symbols.PointerSize()), listShape: shape}, nil
}

func runWindows(ctx tools.Context, opts runOptions) (Listing, error) {
	m, err := resolveListMembers(ctx)
	if err != nil {
		return Listing{}, err
	}
	entries, closed, err := walkActiveLinks(ctx, m, opts)
	if err != nil {
		return Listing{}, err
	}

	var check ProcessCheck
	if opts.sanity {
		check = NewProcessCheck(ctx)
	}
	var active ActiveProcessFilter
	if opts.activeOnly {
		active = ResolveActiveProcessFilter(ctx)
	}
	roots := NewUserSpaceDTBResolver(ctx)
	columns := NewColumnReader(ctx)

	out := make([]Process, 0, len(entries))
	for _, eprocess := range entries {
		p, err := readProcess(ctx, m, eprocess)
		if err != nil {
			if ctx.StrictMode() {
				return Listing{}, err
			}
			ctx.AddDiagnostic("%v", err)
			continue
		}
		p.DirectoryTableBase = roots.DTB(ctx, eprocess)
		if opts.sanity {
			if _, err := check.Check(ctx.Memory, eprocess); err != nil {
				ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: dropped by the sanity filter: %v", Name, eprocess, err)
				continue
			}
		}
		if opts.activeOnly {
			if err := active.Why(ctx, p); err != nil {
				ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: dropped by the active filter: %v", Name, eprocess, err)
				continue
			}
		}
		if opts.crossChecker != nil {
			confirmed, err := opts.crossChecker.Confirm(p)
			switch {
			case err != nil && ctx.StrictMode():
				return Listing{}, fmt.Errorf("%s: _EPROCESS at 0x%x: cross-checker failed: %w", Name, eprocess, err)
			case err != nil:
				ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: cross-checker failed, kept: %v", Name, eprocess, err)
			case !confirmed:
				ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: not confirmed by the cross-checker", Name, eprocess)
				continue
			}
		}
		p.Columns = columns.Read(ctx, ctx.Memory, eprocess)
		out = append(out, p)
	}
	return Listing{Processes: out, Closed: closed}, nil
}

func walkActiveLinks(ctx tools.Context, m listMembers, opts runOptions) ([]uint64, bool, error) {
	w := winkernel.ListWalker{Tool: Name, Memory: ctx.Memory, Layout: m.listShape, Limit: ctx.Bounds().MaxListEntries,
		Strict: ctx.StrictMode(), Report: ctx.AddDiagnostic}
	head, headErr := ctx.Symbols.LookupSymbol("PsActiveProcessHead")
	useHead := headErr == nil && (inSystemSpace(head.Address, m.pointer) || !opts.startFlinkSet && head.Address != 0)
	if useHead {
		walk, err := w.WalkRecovering(head.Address, "PsActiveProcessHead")
		if err != nil {
			return nil, false, err
		}
		return containers(ctx, walk.Entries, m.links), closedWalk(walk, m.listShape), nil
	}
	if !opts.startFlinkSet {
		if headErr != nil {
			return nil, false, fmt.Errorf("%s: %w: %w", Name, ErrNoListHead, headErr)
		}
		return nil, false, fmt.Errorf("%s: %w", Name, ErrNoListHead)
	}
	walk, err := w.WalkRecovering(opts.startFlink, "start entry")
	if err != nil {
		return nil, false, err
	}
	ring := append([]uint64{opts.startFlink}, walk.Entries...)
	check := NewProcessCheck(ctx)
	out := make([]uint64, 0, len(ring))
	for _, eprocess := range containers(ctx, ring, m.links) {
		if _, err := check.Check(ctx.Memory, eprocess); err != nil {
			ctx.AddDiagnostic("%s: list entry at 0x%x: not a process, dropped from the ring walk: %v", Name, eprocess+m.links, err)
			continue
		}
		out = append(out, eprocess)
	}
	return out, closedWalk(walk, m.listShape), nil
}

// The Blink side closes a broken walk only when it ran and ended on an entry
// the Flink side had reached (S25 4.3).
func closedWalk(walk winkernel.ListWalk, shape winkernel.ListLayout) bool {
	if walk.Forward == nil {
		return true
	}
	return shape.HasBlink && !errors.Is(walk.Forward, winkernel.ErrListLimit) && walk.Back == nil
}

func containers(ctx tools.Context, entries []uint64, member uint64) []uint64 {
	out := make([]uint64, 0, len(entries))
	for _, e := range entries {
		eprocess, ok := winkernel.Container(e, member)
		if !ok {
			ctx.AddDiagnostic("%s: list entry at 0x%x: below the ActiveProcessLinks offset, skipped", Name, e)
			continue
		}
		out = append(out, eprocess)
	}
	return out
}

func readProcess(ctx tools.Context, m listMembers, eprocess uint64) (Process, error) {
	raw, err := ctx.Memory.ReadAt(eprocess+m.pid, m.pointer)
	if err == nil && uint64(len(raw)) < m.pointer {
		err = fmt.Errorf("short read of %d bytes", len(raw))
	}
	var name string
	if err == nil {
		name, err = m.name.Read(ctx.Memory, eprocess)
	}
	if err != nil {
		return Process{}, fmt.Errorf("%s: _EPROCESS at 0x%x: pid and image name do not read: %w", Name, eprocess, err)
	}
	pid := uint64(binary.LittleEndian.Uint32(raw))
	if m.pointer == 8 {
		pid = binary.LittleEndian.Uint64(raw)
	}
	return Process{PID: pid, Name: name, EPROCESS: eprocess}, nil
}

func ProcessAt(ctx tools.Context, eprocess uint64) (Process, error) {
	m, err := resolveListMembers(ctx)
	if err != nil {
		return Process{}, err
	}
	p, err := readProcess(ctx, m, eprocess)
	if err != nil {
		return Process{}, err
	}
	p.DirectoryTableBase = NewUserSpaceDTBResolver(ctx).DTB(ctx, eprocess)
	p.Columns = NewColumnReader(ctx).Read(ctx, ctx.Memory, eprocess)
	return p, nil
}
