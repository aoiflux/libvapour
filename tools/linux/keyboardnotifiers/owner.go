package keyboardnotifiers

import (
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

type owner struct {
	module, symbol string
	moduleAddress  uint64
	found          bool
}

type owners struct {
	model *linuxmodule.Model
	known []linuxmodule.Module
	namer linuxmodule.KernelNamer
	lossy bool
}

func newOwners(k *linuxkern.Kernel, diag func(string, ...any)) *owners {
	o := &owners{namer: func(addr uint64) []string {
		names, _ := k.SymbolsAt(addr)
		return names
	}}
	model, err := k.Modules()
	if err != nil {
		o.lossy = true
		diag("%s: module model: %v", Name, err)
		return o
	}
	vs, err := model.Views()
	if err != nil {
		o.lossy = true
		diag("%s: module views: %v", Name, err)
		return o
	}
	vs.Report(diag, Name)
	o.lossy = vs.Lossy()
	o.model, o.known = model, vs.Known()
	return o
}

func (o *owners) of(addr uint64) owner {
	if o.model == nil {
		return owner{}
	}
	found := o.model.Lookup(o.known, addr, o.namer)
	if !found.Found {
		return owner{}
	}
	var out owner
	out.module, out.symbol = found.Names()
	out.found = true
	if !found.Kernel {
		out.moduleAddress = found.Module.Address
	}
	return out
}
