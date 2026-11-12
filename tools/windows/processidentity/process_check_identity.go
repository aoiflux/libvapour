package processidentity

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.process.check_identity"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "Compare the image path in each process's parameter block with the image name the kernel recorded at creation, " +
				"and flag image path and command line strings whose layout shows they were rewritten",
		},
		RunAny,
	)
}

type Parameters string

const (
	ParametersRead   Parameters = "read"
	ParametersAbsent Parameters = "absent"
	ParametersUnread Parameters = "unread"
)

type Row struct {
	PID                  uint64
	Process              string
	Address              uint64
	KernelPath           string
	KernelPathRead       bool
	Parameters           Parameters
	ImagePath            string
	ImagePathRead        bool
	CommandLineRead      bool
	NameDiffers          bool
	ImagePathDiffers     bool
	ImagePathRewritten   bool
	CommandLineRewritten bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	l, absent, err := resolveLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	for _, a := range absent {
		ctx.AddDiagnostic("%s: %s not in the symbol table, its check not made", Name, a)
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	pids := ctx.PIDs()
	c := &checker{ctx: ctx, l: l}
	var out []Row
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		row, err := c.check(p)
		if err != nil {
			if ctx.StrictMode() {
				return nil, err
			}
			ctx.AddDiagnostic("%v", err)
		}
		out = append(out, row)
	}
	c.report()
	return out, nil
}

type checker struct {
	ctx      tools.Context
	l        layout
	unread   map[string]int
	examples map[string]string
}

func (c *checker) miss(what string, p processlist.Process, err error) {
	if c.unread == nil {
		c.unread, c.examples = map[string]int{}, map[string]string{}
	}
	if c.unread[what] == 0 {
		c.examples[what] = fmt.Sprintf("pid %d _EPROCESS at 0x%x: %v", p.PID, p.EPROCESS, err)
	}
	c.unread[what]++
}

func (c *checker) report() {
	for _, what := range []string{"kernel image name", "parameter block", "ImagePathName", "CommandLine"} {
		if n := c.unread[what]; n > 0 {
			c.ctx.AddDiagnostic("%s: %d processes whose %s did not read, first: %s", Name, n, what, c.examples[what])
		}
	}
}

func (c *checker) check(p processlist.Process) (Row, error) {
	row := Row{PID: p.PID, Process: util.ReplaceInvalidUTF8(p.Name), Address: p.EPROCESS, Parameters: ParametersUnread}
	if path, ok, err := c.kernelPath(p); err != nil {
		c.miss("kernel image name", p, err)
	} else if ok {
		row.KernelPath, row.KernelPathRead = path, true
		row.NameDiffers = nameDiffers(p.Name, path)
	}

	space, params, state, err := c.parameters(p)
	row.Parameters = state
	if err != nil {
		c.miss("parameter block", p, err)
		if c.ctx.StrictMode() {
			return row, fmt.Errorf("%s: pid %d _EPROCESS at 0x%x: parameter block not read: %w", Name, p.PID, p.EPROCESS, err)
		}
	}
	if state != ParametersRead {
		return row, nil
	}
	block := c.blockEnd(space, params)
	if c.l.imagePath.ok {
		s, err := readString(space, c.l, params+c.l.imagePath.at)
		if err != nil {
			c.miss("ImagePathName", p, err)
		} else {
			row.ImagePath, row.ImagePathRead = util.ReplaceInvalidUTF8(s.Text()), true
			row.ImagePathRewritten = rewritten(s, params, block, false)
			if row.KernelPathRead {
				row.ImagePathDiffers = pathsDiffer(s.Text(), row.KernelPath)
			}
		}
	}
	if c.l.commandLine.ok {
		s, err := readString(space, c.l, params+c.l.commandLine.at)
		if err != nil {
			c.miss("CommandLine", p, err)
		} else {
			row.CommandLineRead = true
			row.CommandLineRewritten = rewritten(s, params, block, true)
		}
	}
	return row, nil
}

func (c *checker) kernelPath(p processlist.Process) (string, bool, error) {
	if !c.l.audit.ok {
		return "", false, nil
	}
	info, err := c.ctx.Symbols.ReadPointer(c.ctx.Memory, p.EPROCESS+c.l.audit.at)
	if err != nil {
		return "", false, err
	}
	if info == 0 {
		return "", false, nil
	}
	s, err := util.ReadUnicodeString(c.ctx.Memory, info+c.l.auditName.at, c.l.strings, util.MaxUnicodeStringBytes)
	if err != nil {
		return "", false, err
	}
	return util.ReplaceInvalidUTF8(s.Text()), true, nil
}

// The parameter block is user memory, read under the process's own root.
func (c *checker) parameters(p processlist.Process) (memory.MemoryReader, uint64, Parameters, error) {
	t := c.ctx.Symbols
	peb, err := t.ReadPointer(c.ctx.Memory, p.EPROCESS+c.l.peb.at)
	if err != nil {
		return nil, 0, ParametersUnread, err
	}
	if peb == 0 {
		return nil, 0, ParametersAbsent, nil
	}
	if p.DirectoryTableBase == 0 {
		return nil, 0, ParametersUnread, ErrNoRoot
	}
	space, err := c.ctx.ProcessSpace(p.DirectoryTableBase)
	if err != nil {
		return nil, 0, ParametersUnread, err
	}
	params, err := t.ReadPointer(space, peb+c.l.parameters.at)
	if err != nil {
		return nil, 0, ParametersUnread, err
	}
	if params == 0 {
		return nil, 0, ParametersAbsent, nil
	}
	return space, params, ParametersRead, nil
}

func (c *checker) blockEnd(space memory.MemoryReader, params uint64) uint64 {
	if !c.l.blockLength.ok {
		return 0
	}
	n, err := c.ctx.Symbols.ReadUint32(space, params+c.l.blockLength.at)
	if err != nil {
		return 0
	}
	return params + uint64(n)
}
