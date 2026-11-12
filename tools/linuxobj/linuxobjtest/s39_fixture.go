package linuxobjtest

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/symbols"
)

const (
	S39VMAOps         = 0x48
	S39VMAPrivate     = 0x68
	S39VMAAnonName    = 0x70
	S39OpsName        = 0x60
	S39OpsSize        = 0x80
	S39SpecialSize    = 0x28
	S39AnonNameString = 0x04
)

// AddAreaOperations gives the AddFS area type the members that name an area
// without a file: vm_ops, vm_private_data and anon_name (S39 R1 to R4).
func AddAreaOperations(k *Kernel) (namer uint64) {
	t := k.Table
	f := func(name string, off uint64, typ symbols.TypeRef) symbols.Field {
		return symbols.Field{Name: name, Offset: off, Type: typ}
	}
	voidp := symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: "void"}}
	vma, err := t.Struct("vm_area_struct")
	if err != nil {
		panic(err)
	}
	vma.Fields = append(vma.Fields, f("vm_ops", S39VMAOps, ptr("vm_operations_struct")),
		f("vm_private_data", S39VMAPrivate, voidp), f("anon_name", S39VMAAnonName, ptr("anon_vma_name")))
	t.AddStruct(vma)
	t.AddStruct(symbols.StructType{Name: "vm_operations_struct", Size: S39OpsSize, Fields: []symbols.Field{
		f("name", S39OpsName, voidp)}})
	t.AddStruct(symbols.StructType{Name: "vm_special_mapping", Size: S39SpecialSize, Fields: []symbols.Field{
		f("name", 0, ptr("char"))}})
	t.AddStruct(symbols.StructType{Name: "anon_vma_name", Size: S39AnonNameString, Fields: []symbols.Field{
		f("kref", 0, scalar("kref")), f("name", S39AnonNameString, array("char", 0))}})
	namer = k.Alloc(0x10)
	t.AddSymbol(symbols.Symbol{Name: "special_mapping_name", Address: namer})
	return namer
}

func (k *Kernel) areaAt(mm, start uint64) uint64 {
	read := func(at uint64) uint64 {
		b, err := k.Mem.ReadAt(at, 8)
		if err != nil {
			panic(err)
		}
		return binary.LittleEndian.Uint64(b)
	}
	for vma := read(mm + FSMMMmap); vma != 0; vma = read(vma + FSVMANext) {
		if read(vma+FSVMAStart) == start {
			return vma
		}
	}
	panic("linuxobjtest: no area at that start")
}

// NameSpecialArea makes the area of mm at start a special mapping with name,
// as _install_special_mapping does.
func (k *Kernel) NameSpecialArea(mm, start, namer uint64, name string) {
	vma := k.areaAt(mm, start)
	ops := k.Alloc(S39OpsSize)
	k.Mem.U64(ops+S39OpsName, namer)
	sm := k.Alloc(S39SpecialSize)
	k.Mem.U64(sm, k.Str(name))
	k.Mem.U64(vma+S39VMAOps, ops)
	k.Mem.U64(vma+S39VMAPrivate, sm)
}

func (k *Kernel) NameAnonArea(mm, start uint64, name string) {
	vma := k.areaAt(mm, start)
	a := k.Alloc(S39AnonNameString + uint64(len(name)) + 1)
	k.Mem.Write(a+S39AnonNameString, append([]byte(name), 0))
	k.Mem.U64(vma+S39VMAAnonName, a)
}
