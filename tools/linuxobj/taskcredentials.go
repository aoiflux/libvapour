package linuxobj

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
)

var ErrNoCredentials = errors.New("linuxobj: task has no credentials")

type CredIDs struct {
	UID, GID, EUID, EGID int64
}

// kuid_t and kgid_t wrap the ID in a struct; a table that types the member as
// a plain integer is read directly.
func (k *Kernel) CredValue(cred uint64, member string) (int64, error) {
	f, err := k.sym.Field("cred", member)
	if err != nil {
		return 0, fmt.Errorf("linuxobj: cred.%s: %w", member, err)
	}
	id := symbols.IntField{}
	if _, err := k.sym.Field(f.Type.Name, "val"); err == nil && !f.Type.IsPointer {
		if id, err = symbols.ResolveIntField(k.sym, f.Type.Name, "val"); err != nil {
			return 0, err
		}
		id.Offset += f.Offset
	} else if id, err = symbols.ResolveIntField(k.sym, "cred", member); err != nil {
		return 0, err
	}
	v, err := id.Read(k.mem, cred)
	if err != nil {
		return 0, fmt.Errorf("linuxobj: cred.%s at %#x: %w", member, cred+id.Offset, err)
	}
	return int64(v), nil
}

func (k *Kernel) credIDs(cred uint64) (CredIDs, error) {
	var ids CredIDs
	for _, m := range []struct {
		name string
		to   *int64
	}{{"uid", &ids.UID}, {"gid", &ids.GID}, {"euid", &ids.EUID}, {"egid", &ids.EGID}} {
		v, err := k.CredValue(cred, m.name)
		if err != nil {
			return CredIDs{}, err
		}
		*m.to = v
	}
	return ids, nil
}

// The objective credentials are what /proc and other tasks see.
func (k *Kernel) objectiveIDs(t Task) (CredIDs, error) {
	cred, err := k.Pointer(k.in(t), t.Addr, "task_struct", "real_cred")
	if err != nil {
		return CredIDs{}, err
	}
	if cred == 0 {
		return CredIDs{}, fmt.Errorf("linuxobj: task at %#x: real_cred is null: %w", t.Addr, ErrNoCredentials)
	}
	return k.credIDs(cred)
}

// Tools compare the subjective cred, the one the task acts with.
func (k *Kernel) TaskCred(t Task) (uint64, bool, error) {
	f, err := k.sym.Field("task_struct", "cred")
	if err != nil {
		return 0, false, fmt.Errorf("linuxobj: task_struct.cred: %w", err)
	}
	size, err := k.SizeOf("cred")
	if err != nil {
		return 0, false, err
	}
	cred, err := k.PointerAt(k.in(t), t.Addr+f.Offset)
	if err != nil || cred == 0 || !k.Readable(cred, size) {
		return 0, false, nil
	}
	return cred, true, nil
}
