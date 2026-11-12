package processenvironment

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

type blockMembers struct {
	peb, params, env uint64
	size             uint64
	sizeWidth        uint64
	hasSize          bool
}

func resolveBlockMembers(ctx tools.Context) (blockMembers, error) {
	var m blockMembers
	for _, f := range []struct {
		at        *uint64
		typ, name string
	}{
		{&m.peb, "_EPROCESS", "Peb"},
		{&m.params, "_PEB", "ProcessParameters"},
		{&m.env, "_RTL_USER_PROCESS_PARAMETERS", "Environment"},
	} {
		field, err := ctx.Symbols.Field(f.typ, f.name)
		if err != nil {
			return m, fmt.Errorf("%s: %s.%s: %w: %w", Name, f.typ, f.name, ErrNoEnvironmentMember, err)
		}
		*f.at = field.Offset
	}
	if f, err := ctx.Symbols.Field("_RTL_USER_PROCESS_PARAMETERS", "EnvironmentSize"); err == nil {
		m.size, m.hasSize, m.sizeWidth = f.Offset, true, uint64(ctx.Symbols.PointerSize())
		if sizer, ok := ctx.Symbols.(symbols.FieldSizer); ok {
			if n, err := sizer.FieldSize("_RTL_USER_PROCESS_PARAMETERS", "EnvironmentSize"); err == nil && (n == 4 || n == 8) {
				m.sizeWidth = n
			}
		}
	}
	return m, nil
}

func runWindows(ctx tools.Context) ([]EnvVar, error) {
	m, err := resolveBlockMembers(ctx)
	if err != nil {
		return nil, err
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	pids := ctx.PIDs()
	var out []EnvVar
	exited := 0
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		if !p.ExitTimeUnreadable && !p.ExitTime.IsZero() {
			exited++
			continue
		}
		rows, err := readProcessBlock(ctx, m, p)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	if exited > 0 {
		ctx.AddDiagnostic("%s: %d exited processes not read: their user space is released", Name, exited)
	}
	return out, nil
}

func readProcessBlock(ctx tools.Context, m blockMembers, p processlist.Process) ([]EnvVar, error) {
	say := func(format string, args ...any) {
		ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: pid %d: %s", Name, p.EPROCESS, p.PID, fmt.Sprintf(format, args...))
	}
	peb, err := ctx.Symbols.ReadPointer(ctx.Memory, p.EPROCESS+m.peb)
	if err != nil {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: _EPROCESS at 0x%x: pid %d: Peb does not read: %w", Name, p.EPROCESS, p.PID, err)
		}
		say("Peb does not read: %v", err)
		return nil, nil
	}
	if peb == 0 {
		return nil, nil
	}
	space, err := ctx.ProcessSpace(p.DirectoryTableBase)
	if err != nil {
		say("no process space: %v", err)
		return nil, nil
	}
	params, ok := pointer(ctx, space, peb+m.params, "ProcessParameters", say)
	if !ok {
		return nil, nil
	}
	block, ok := pointer(ctx, space, params+m.env, "Environment", say)
	if !ok {
		return nil, nil
	}
	limit := uint64(ctx.Bounds().MaxBufferBytes)
	size := limit
	if m.hasSize {
		if v, err := readWidth(space, params+m.size, m.sizeWidth); err == nil && v != 0 {
			size = v
		}
	}
	if size > limit {
		say("environment block at 0x%x: EnvironmentSize %d is over MaxBufferBytes, reading %d", block, size, limit)
		size = limit
	}
	raw := readPages(space, block, size)
	if len(raw) == 0 {
		say("environment block at 0x%x does not read", block)
		return nil, nil
	}
	split := splitWindowsBlock(raw)
	if uint64(len(raw)) < size && !split.terminated {
		say("environment block at 0x%x: 0x%x of 0x%x bytes read", block, len(raw), size)
	} else if !split.terminated {
		say("environment block at 0x%x: no terminator in 0x%x bytes", block, len(raw))
	}
	if split.unnamed > 0 {
		say("environment block at 0x%x: %d strings without a name, skipped", block, split.unnamed)
	}
	rows := make([]EnvVar, 0, len(split.vars))
	for _, v := range split.vars {
		rows = append(rows, EnvVar{PID: p.PID, Process: p.Name, EPROCESS: p.EPROCESS, Block: block, Variable: v.name, Value: v.value})
	}
	return rows, nil
}

func pointer(ctx tools.Context, r memory.MemoryReader, at uint64, member string, say func(string, ...any)) (uint64, bool) {
	v, err := ctx.Symbols.ReadPointer(r, at)
	switch {
	case err != nil:
		say("%s at 0x%x does not read: %v", member, at, err)
		return 0, false
	case v == 0:
		say("%s is 0", member)
		return 0, false
	}
	return v, true
}

func readWidth(r memory.MemoryReader, at, width uint64) (uint64, error) {
	b, err := r.ReadAt(at, width)
	if err != nil {
		return 0, err
	}
	if uint64(len(b)) < width {
		return 0, memory.ErrUnmapped
	}
	if width == 4 {
		return uint64(binary.LittleEndian.Uint32(b)), nil
	}
	return binary.LittleEndian.Uint64(b), nil
}
