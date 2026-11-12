package processarguments

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

type windowsOffsets struct {
	peb, parameters, commandLine uint64
	text                         util.UnicodeStringLayout
}

func resolveWindows(ctx tools.Context) (windowsOffsets, error) {
	var o windowsOffsets
	for _, m := range []struct {
		typ, member string
		to          *uint64
	}{
		{"_EPROCESS", "Peb", &o.peb},
		{"_PEB", "ProcessParameters", &o.parameters},
		{"_RTL_USER_PROCESS_PARAMETERS", "CommandLine", &o.commandLine},
	} {
		f, err := ctx.Symbols.Field(m.typ, m.member)
		if err != nil {
			return o, fmt.Errorf("%s: symbol table has no %s.%s: %w", Name, m.typ, m.member, err)
		}
		*m.to = f.Offset
	}
	o.text = util.ResolveUnicodeStringLayout(ctx.Symbols)
	return o, nil
}

func runWindows(ctx tools.Context) ([]ProcessCmdline, error) {
	o, err := resolveWindows(ctx)
	if err != nil {
		return nil, err
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	pids := ctx.PIDs()
	out := make([]ProcessCmdline, 0, len(procs))
	var missed unread
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		text, why := windowsCommandLine(ctx, o, p)
		if why != nil {
			missed.add("_EPROCESS", p.EPROCESS, why)
		}
		out = append(out, ProcessCmdline{PID: p.PID, Name: p.Name, Address: p.EPROCESS, Cmdline: text,
			CmdlineUnreadable: why != nil})
	}
	if err := missed.report(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// S61 N1, N2: the PEB and its parameters are user-mode memory of the process,
// so they are read only through its own page tables; a process with no PEB
// has no command line to read.
func windowsCommandLine(ctx tools.Context, o windowsOffsets, p processlist.Process) (string, error) {
	peb, err := ctx.Symbols.ReadPointer(ctx.Memory, p.EPROCESS+o.peb)
	if err != nil {
		return "", fmt.Errorf("member Peb: %w", err)
	}
	if peb == 0 {
		return "", nil
	}
	space, err := ctx.ProcessSpace(p.DirectoryTableBase)
	if err != nil {
		return "", err
	}
	params, err := ctx.Symbols.ReadPointer(space, peb+o.parameters)
	if err != nil {
		return "", fmt.Errorf("_PEB at %#x: ProcessParameters: %w", peb, err)
	}
	if params == 0 {
		return "", nil
	}
	s, err := util.ReadUnicodeString(space, params+o.commandLine, o.text, 0)
	if err != nil {
		return "", fmt.Errorf("_RTL_USER_PROCESS_PARAMETERS at %#x: CommandLine: %w", params, err)
	}
	return s.Text(), nil
}
