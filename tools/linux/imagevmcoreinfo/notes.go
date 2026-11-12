package imagevmcoreinfo

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
)

const Name = "linux.image.read_vmcoreinfo"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List every VMCOREINFO note in a Linux capture and its entries as the kernel wrote them; needs no symbols",
		},
		RunAny,
	)
}

type Row struct {
	Offset uint64
	Key    string
	Value  string
	Cut    bool
}

var ErrNoPhysical = errors.New("imagevmcoreinfo: the session has no physical memory")

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, ErrNoPhysical
	}
	scan, err := autoload.ScanVMCoreInfo(physical, ctx.Bounds())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if len(scan.Damaged) > 0 && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: %w", Name, &autoload.VMCoreInfoDamageError{Damaged: scan.Damaged})
	}
	for _, d := range scan.Damaged {
		ctx.AddDiagnostic("%s: %s", Name, d)
	}
	var rows []Row
	for _, note := range scan.Tables {
		cut := 0
		for _, e := range note.Entries {
			if e.Cut {
				cut++
			}
			rows = append(rows, Row{Offset: note.Offset, Key: e.Key, Value: e.Text, Cut: e.Cut})
		}
		if cut > 0 {
			ctx.AddDiagnostic("%s: VMCOREINFO note at 0x%x: %d lines were cut by the kernel's line or table size", Name, note.Offset, cut)
		}
	}
	return rows, nil
}
