package moduledump

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linux/modulelist"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const Name = "linux.module.dump"

const OptionBase = "linux.module.dump.base"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "Rebuild a relocatable ELF file from the Linux module whose struct module is at a given address"},
		RunAny,
	)
}

type Row struct {
	Address   uint64
	Name      string
	Size      uint64
	Sections  int
	Dropped   int
	ZeroPages int
	File      string
}

var (
	ErrNoBase      = errors.New("moduledump: " + OptionBase + " not set; it takes the struct module address")
	ErrNoOutputDir = errors.New("moduledump: " + tools.OptionOutputDir + " not set")
)

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	base, set, err := ctx.UintOption(OptionBase)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !set {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoBase)
	}
	dir, ok := ctx.OutputDir()
	if !ok {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoOutputDir)
	}
	model, o, err := modulelist.Open(ctx, Name, "")
	if err != nil {
		return nil, err
	}
	mod, err := model.Read(base)
	if err != nil {
		return nil, fmt.Errorf("%s: module at %#x: %w", Name, base, err)
	}
	rb, err := model.RebuildELF(mod, ctx.DumpLimit())
	if err != nil {
		return nil, fmt.Errorf("%s: module %s at %#x: ELF rebuild: %w", Name, mod.Name, mod.Address, err)
	}
	linuxmodule.ReportRebuild(ctx.AddDiagnostic, Name, mod, rb)
	file := linuxmodule.FileName(mod, model.PointerWidth(), o.Canonical)
	if err := linuxmodule.WriteFile(dir, file, rb.File); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return []Row{{Address: mod.Address, Name: mod.Name, Size: uint64(len(rb.File)), Sections: rb.Sections,
		Dropped: len(rb.Dropped), ZeroPages: rb.ZeroPages, File: file}}, nil
}
