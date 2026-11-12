package linuxobj

import "time"

type TaskFields struct {
	Offset          uint64
	PID, TID, PPID  int64
	Name            string
	Comm            string
	Creds           CredIDs
	CredsRead       bool
	CredsErr        error
	ParentErr       error
	CreationTime    time.Time
	CreationTimeErr error
}

// Only the identity fails the summary; the parent, credentials and creation
// time each carry their own failure so one bad pointer does not hide the task.
func (k *Kernel) TaskFields(t Task, decorate bool) (TaskFields, error) {
	f := TaskFields{Offset: t.Addr}
	var err error
	if f.TID, err = k.PID(t); err != nil {
		return TaskFields{}, err
	}
	if f.PID, err = k.TGID(t); err != nil {
		return TaskFields{}, err
	}
	if f.Comm, err = k.Comm(t); err != nil {
		return TaskFields{}, err
	}
	f.Name = f.Comm
	if decorate {
		kernelThread, err := k.IsKernelThread(t)
		if err != nil {
			return TaskFields{}, err
		}
		f.Name = decorateComm(f.Comm, kernelThread, f.TID, f.PID)
	}
	if f.PPID, f.ParentErr = k.ParentPID(t); f.ParentErr != nil {
		f.PPID = 0
	}
	if f.Creds, f.CredsErr = k.objectiveIDs(t); f.CredsErr == nil {
		f.CredsRead = true
	}
	f.CreationTime, f.CreationTimeErr = k.CreateTime(t)
	return f, nil
}
