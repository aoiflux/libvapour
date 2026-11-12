package processlist

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
)

var ErrNoPageTableRoot = errors.New("processlist: symbol table has no _KPROCESS.DirectoryTableBase")

type pageTableRoots struct {
	kernel optionalField
	user   optionalField
}

// Pcb is at offset 0 (S25 T1), so a table that names the root as an
// _EPROCESS member describes the same bytes.
func resolvePageTableRoots(ctx tools.Context) pageTableRoots {
	root := func(member string) optionalField {
		if f := lookupNestedOptionalField(ctx, "_EPROCESS", "Pcb", "_KPROCESS", member); f.present {
			return f
		}
		return lookupOptionalField(ctx, "_EPROCESS", member)
	}
	return pageTableRoots{kernel: root("DirectoryTableBase"), user: root("UserDirectoryTableBase")}
}

type UserSpaceDTBResolver struct {
	roots pageTableRoots
}

func NewUserSpaceDTBResolver(ctx tools.Context) UserSpaceDTBResolver {
	return UserSpaceDTBResolver{roots: resolvePageTableRoots(ctx)}
}

// S25 4.5 step 3 and open point O3: a user root whose frame bits are all
// zero stands for no separate user root.
func (r UserSpaceDTBResolver) DTB(ctx tools.Context, eprocess uint64) uint64 {
	if r.roots.user.present {
		if v, err := ctx.Symbols.ReadPointer(ctx.Memory, eprocess+r.roots.user.offset); err == nil && v&^pageTableFlagBits != 0 {
			return v
		}
	}
	if r.roots.kernel.present {
		if v, err := ctx.Symbols.ReadPointer(ctx.Memory, eprocess+r.roots.kernel.offset); err == nil {
			return v
		}
	}
	return 0
}

func (r UserSpaceDTBResolver) Described() bool {
	return r.roots.kernel.present || r.roots.user.present
}

func KernelDirectoryTableBase(ctx tools.Context, eprocess uint64) (uint64, error) {
	root := resolvePageTableRoots(ctx).kernel
	if !root.present {
		return 0, ErrNoPageTableRoot
	}
	v, err := ctx.Symbols.ReadPointer(ctx.Memory, eprocess+root.offset)
	if err != nil {
		return 0, fmt.Errorf("processlist: _EPROCESS at 0x%x: DirectoryTableBase does not read: %w", eprocess, err)
	}
	return v, nil
}
