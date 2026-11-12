package threadaddress

import (
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

const systemProcessID = 4

// ThreadFlag is a bit of _KTHREAD or _ETHREAD placed relative to the
// _ETHREAD, so that a thread found by address or by pool scan reads it the
// same way.
type ThreadFlag struct {
	field symbols.IntField
	known bool
}

func ResolveThreadFlag(t symbols.SymbolTable, typ, member string) ThreadFlag {
	f, err := symbols.ResolveIntField(t, typ, member)
	if err != nil {
		return ThreadFlag{}
	}
	if typ == "_KTHREAD" {
		tcb, err := t.Field("_ETHREAD", "Tcb")
		if err != nil {
			return ThreadFlag{}
		}
		f.Offset += tcb.Offset
	}
	return ThreadFlag{field: f, known: true}
}

func (f ThreadFlag) Known() bool { return f.known }

func (f ThreadFlag) End() uint64 { return f.field.Offset + f.field.Width }

func (f ThreadFlag) Set(r memory.MemoryReader, ethread uint64) (bool, error) {
	v, err := f.field.Read(r, ethread)
	return v != 0, err
}

// Without the SystemThread member, a system thread is one of the initial
// system process, where PsCreateSystemThread puts a driver's threads.
func IsSystemThread(flag ThreadFlag, r memory.MemoryReader, ethread, pid uint64) (bool, error) {
	if !flag.known {
		return pid == systemProcessID, nil
	}
	return flag.Set(r, ethread)
}

func ResolveSystemThread(t symbols.SymbolTable) ThreadFlag {
	return ResolveThreadFlag(t, "_KTHREAD", "SystemThread")
}
