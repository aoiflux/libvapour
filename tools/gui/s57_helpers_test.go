package gui_test

import (
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
)

func fingerprint(guid string, age uint32) autoload.Fingerprint {
	return autoload.Fingerprint{PDBName: "win32kbase.pdb", GUID: guid, Age: age}
}

type thirtyTwo struct{ symbols.SymbolTable }

func (thirtyTwo) PointerSize() uint8 { return 4 }

type linuxProfile struct{ profiles.Profile }

func (linuxProfile) OS() string { return "linux" }
