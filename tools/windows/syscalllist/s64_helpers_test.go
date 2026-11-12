package syscalllist

import (
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
)

func symbolAt(name string, at uint64) symbols.Symbol { return symbols.Symbol{Name: name, Address: at} }

func hex(v uint64) string { return fmt.Sprintf("%x", v) }

func negative(offset int32) uint32 { return uint32(offset << 4) }
