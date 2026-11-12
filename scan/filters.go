package scan

import "github.com/aoiflux/libvapour/symbols"

const (
	MutantObject  = 2
	ProcessObject = 3
	ThreadObject  = 6
)

const (
	IOTypeDriver = 4
	IOTypeFile   = 5
)

type PoolFilter struct {
	Tag          string
	Body         string
	PageType     PageType
	MinSize      uint64
	MaxSize      uint64
	MinIndex     uint64
	MaxIndex     uint64
	ObjectType   string
	SkipTypeTest bool
}

const kernelLoaderEntry = "_KLDR_DATA_TABLE_ENTRY"

// Each object filter's tag is the Key of its _OBJECT_TYPE. Freed
// allocations stay in: the scan exists to find what the lists no longer hold.
var (
	ProcessFilter = PoolFilter{Tag: "Proc", Body: "_EPROCESS", PageType: NonPagedPool | FreePool,
		ObjectType: "Process"}
	ThreadFilter = PoolFilter{Tag: "Thre", Body: "_ETHREAD", PageType: NonPagedPool | FreePool,
		ObjectType: "Thread"}
	FileFilter = PoolFilter{Tag: "File", Body: "_FILE_OBJECT", PageType: NonPagedPool | FreePool,
		ObjectType: "File"}
	MutantFilter = PoolFilter{Tag: "Muta", Body: "_KMUTANT", PageType: NonPagedPool | FreePool,
		ObjectType: "Mutant"}
	DriverFilter = PoolFilter{Tag: "Driv", Body: "_DRIVER_OBJECT", PageType: NonPagedPool | FreePool,
		ObjectType: "Driver"}
	ModuleFilter  = PoolFilter{Tag: "MmLd", Body: kernelLoaderEntry, PageType: NonPagedPool | FreePool}
	SymlinkFilter = PoolFilter{Tag: "Symb", Body: "_OBJECT_SYMBOLIC_LINK", PageType: PagedPool | FreePool,
		ObjectType: "SymbolicLink"}
	AtomTableFilter = PoolFilter{Tag: "AtmT", Body: "_RTL_ATOM_TABLE"}
	HiveFilter      = PoolFilter{Tag: "CM10", Body: "_CMHIVE", PageType: PagedPool | FreePool}
)

func ModuleEntryType(sym symbols.SymbolTable) (name string, ok bool) {
	if sym == nil {
		return "", false
	}
	for _, t := range []string{kernelLoaderEntry, "_LDR_DATA_TABLE_ENTRY"} {
		if _, err := sym.Struct(t); err == nil {
			return t, true
		}
	}
	return "", false
}

func ModuleFilterFor(sym symbols.SymbolTable) PoolFilter {
	f := ModuleFilter
	if t, ok := ModuleEntryType(sym); ok {
		f.Body = t
	}
	return f
}
