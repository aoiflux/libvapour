package memoryelffiles

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.memory.list_elf_files"

const OptionDump = "linux.memory.list_elf_files.dump"

var ErrNoOutputDir = errors.New("memoryelffiles: " + OptionDump + " needs the " + tools.OptionOutputDir + " option")

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the memory areas of each Linux process that begin with an ELF header",
		},
		RunAny,
	)
}

type ELF struct {
	PID          int64
	Process      string
	StartAddress uint64
	EndAddress   uint64
	Path         string
	PathRead     bool
	Artefact     string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

// S61 E1: e_ident begins with these four bytes.
var elfMagic = []byte("\x7fELF")

type tally struct {
	count int
	first string
}

func (t *tally) add(format string, args ...any) {
	if t.count == 0 {
		t.first = fmt.Sprintf(format, args...)
	}
	t.count++
}

func (t tally) report(ctx tools.Context, what string) {
	if t.count > 0 {
		ctx.AddDiagnostic("%s: %d %s, first: %s", Name, t.count, what, t.first)
	}
}

func Run(ctx tools.Context) ([]ELF, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	dump, err := ctx.BoolOption(OptionDump)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	var w *writer
	if dump {
		dir, ok := ctx.OutputDir()
		if !ok {
			return nil, ErrNoOutputDir
		}
		w = &writer{ctx: ctx, dir: dir, limit: ctx.DumpLimit()}
	}
	k := linuxobj.New(ctx)
	lw, err := memoryranges.NewLinuxWalker(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk, err := k.Walker().Tasks(false, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	var out []ELF
	var skipped, noSpace, cut, unnamed tally
	for _, addr := range walk.Tasks {
		t := linuxobj.Task{Addr: addr}
		comm, err := k.Comm(t)
		if err != nil {
			skipped.add("task_struct at %#x: %v", addr, err)
			continue
		}
		pid, err := k.TGID(t)
		if err != nil {
			skipped.add("task_struct at %#x: %v", addr, err)
			continue
		}
		layer, ok, why, err := k.ProcessLayer(t)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		if !ok {
			if why != nil {
				noSpace.add("task_struct at %#x: %v", addr, why)
			}
			continue
		}
		mm, areas, walkErr := lw.TaskVMAs(addr)
		if walkErr != nil {
			cut.add("task_struct at %#x: %v", addr, walkErr)
		}
		for _, a := range areas {
			head, err := layer.Reader.ReadAt(a.Start, uint64(len(elfMagic)))
			if err != nil || !bytes.Equal(head, elfMagic) {
				continue
			}
			row := ELF{PID: pid, Process: comm, StartAddress: a.Start, EndAddress: a.End}
			name, named, err := lw.AreaName(addr, mm, a)
			switch {
			case err != nil:
				unnamed.add("vm_area_struct at %#x: %v", a.Addr, err)
			case named:
				row.Path, row.PathRead = name, true
			}
			if w != nil {
				row.Artefact = w.write(layer.Reader, row)
			}
			out = append(out, row)
		}
	}
	noSpace.report(ctx, "processes without a usable address space")
	unnamed.report(ctx, "areas whose path was not built")
	if w != nil {
		w.failed.report(ctx, "images not written")
		w.padded.report(ctx, "images written with pages that did not read zero-filled")
	}
	for _, f := range []struct {
		what string
		t    tally
	}{{"processes not read", skipped}, {"area lists cut short", cut}} {
		if f.t.count > 0 && ctx.StrictMode() {
			return nil, fmt.Errorf("%s: strict mode: %d %s, first: %s", Name, f.t.count, f.what, f.t.first)
		}
		f.t.report(ctx, f.what)
	}
	return out, nil
}
