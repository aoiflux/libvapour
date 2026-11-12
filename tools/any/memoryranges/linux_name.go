package memoryranges

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools/linuxobj"
)

var ErrAreaNamerUnknown = errors.New("memoryranges: area named by an operation that is not run")

const anonNameMax = 80

// AreaName gives the name the maps file prints for an area (S39 4.7 step 6).
// named is false when the name cannot be known; an empty name with named set
// means the kernel prints none.
func (lw *LinuxWalker) AreaName(task, mm uint64, v LinuxVMA) (string, bool, error) {
	name, named, err := lw.areaName(task, mm, v)
	if err != nil && !IsPathUnresolved(err) && !errors.Is(err, linuxobj.ErrUnsupported) {
		err = fmt.Errorf("%w: %w", ErrAreaNameUnread, err)
	}
	return name, named, err
}

func (lw *LinuxWalker) areaName(task, mm uint64, v LinuxVMA) (string, bool, error) {
	k := lw.k
	mem := k.Memory()
	anon, err := lw.anonName(v)
	if err != nil {
		return "", false, err
	}
	if v.File != 0 {
		if anon != "" && lw.anonNameOwnMember() {
			return "[anon_shmem:" + anon + "]", true, nil
		}
		root, err := k.TaskFSRoot(linuxobj.Task{Addr: task})
		if err != nil {
			return "", false, err
		}
		at, err := k.MappedFileLocation(v.File)
		if err != nil && !errors.Is(err, linuxobj.ErrUnsupported) {
			return "", false, fmt.Errorf("%w: %w", linuxobj.ErrPathUnread, err)
		}
		if err != nil {
			return "", false, err
		}
		shown, err := k.ShowPath(at, root)
		if err != nil {
			return "", false, err
		}
		return shown.Text, true, nil
	}
	if name, decided, err := lw.operationName(v); err != nil || decided {
		return name, decided, err
	}
	if k.Has("vm_area_struct", "vm_mm") {
		owner, err := k.Pointer(mem, v.Addr, "vm_area_struct", "vm_mm")
		if err != nil {
			return "", false, err
		}
		if owner == 0 {
			return "[vdso]", true, nil
		}
	}
	if name, ok, err := lw.processRole(mm, v); err != nil || ok {
		return name, ok, err
	}
	if anon != "" {
		return "[anon:" + anon + "]", true, nil
	}
	return "", true, nil
}

// operationName runs vm_ops->name for the one function known to back it:
// special mappings name themselves through vm_private_data (S39 R3).
func (lw *LinuxWalker) operationName(v LinuxVMA) (string, bool, error) {
	k := lw.k
	mem := k.Memory()
	if !k.Has("vm_area_struct", "vm_ops") || !k.Has("vm_operations_struct", "name") {
		return "", false, nil
	}
	ops, err := k.Pointer(mem, v.Addr, "vm_area_struct", "vm_ops")
	if err != nil || ops == 0 {
		return "", false, err
	}
	fn, err := k.Pointer(mem, ops, "vm_operations_struct", "name")
	if err != nil || fn == 0 {
		return "", false, err
	}
	special, err := k.Symbol("special_mapping_name")
	if err != nil || special.Address != fn {
		return "", false, fmt.Errorf("vm_area_struct at %#x: vm_ops name %#x: %w", k.Masked(v.Addr), k.Masked(fn), ErrAreaNamerUnknown)
	}
	sm, err := k.Pointer(mem, v.Addr, "vm_area_struct", "vm_private_data")
	if err != nil || sm == 0 {
		return "", false, err
	}
	p, err := k.Pointer(mem, sm, "vm_special_mapping", "name")
	if err != nil || p == 0 {
		return "", false, err
	}
	name, err := k.StringAt(p, uint64(k.Context().Bounds().MaxNameBytes))
	if err != nil {
		return "", false, err
	}
	return name, name != "", nil
}

func (lw *LinuxWalker) processRole(mm uint64, v LinuxVMA) (string, bool, error) {
	k := lw.k
	mem := k.Memory()
	if k.Has("mm_struct", "brk") && k.Has("mm_struct", "start_brk") {
		brk, err1 := k.Uint(mem, mm, "mm_struct", "brk")
		startBrk, err2 := k.Uint(mem, mm, "mm_struct", "start_brk")
		if err := errors.Join(err1, err2); err != nil {
			return "", false, err
		}
		if v.Start < brk && v.End > startBrk {
			return "[heap]", true, nil
		}
	}
	if k.Has("mm_struct", "start_stack") {
		stack, err := k.Uint(mem, mm, "mm_struct", "start_stack")
		if err != nil {
			return "", false, err
		}
		if v.Start <= stack && v.End >= stack {
			return "[stack]", true, nil
		}
	}
	return "", false, nil
}

// At v6.1 anon_name shares a union with shared and holds a name only for
// areas without a file (S39 R4).
func (lw *LinuxWalker) anonNameOwnMember() bool {
	k := lw.k
	name, err1 := k.Member("vm_area_struct", "anon_name")
	shared, err2 := k.Member("vm_area_struct", "shared")
	return err1 == nil && (err2 != nil || name.Offset != shared.Offset)
}

func (lw *LinuxWalker) anonName(v LinuxVMA) (string, error) {
	k := lw.k
	if !k.Has("vm_area_struct", "anon_name") || v.File != 0 && !lw.anonNameOwnMember() {
		return "", nil
	}
	p, err := k.Pointer(k.Memory(), v.Addr, "vm_area_struct", "anon_name")
	if err != nil || p == 0 {
		return "", err
	}
	f, err := k.Member("anon_vma_name", "name")
	if err != nil {
		return "", nil
	}
	name, err := k.StringAt(p+f.Offset, anonNameMax-1)
	if err != nil {
		return "", fmt.Errorf("anon_vma_name at %#x: %w", k.Masked(p), err)
	}
	return name, nil
}
