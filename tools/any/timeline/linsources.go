package timeline

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/linux/boottime"
	"github.com/aoiflux/libvapour/tools/linux/fileopen"
	"github.com/aoiflux/libvapour/tools/linux/pagecache"
	"github.com/aoiflux/libvapour/tools/linux/shellhistory"
)

const linux = "linux"

func linuxTask(r *recorder, p processlist.Process) {
	l := p.Linux
	s := fmt.Sprintf("task %s pid %d", l.Comm, l.PID)
	if l.Thread {
		s = fmt.Sprintf("thread %s tid %d pid %d", l.Comm, l.TID, l.PID)
	}
	if !l.Read {
		s = fmt.Sprintf("task pid %d", p.PID)
	}
	o := object{subject: s, address: p.EPROCESS}
	r.stamp(o, Created, "CreationTime", l.CreationTime, l.Read && l.CreationTimeErr == nil)
}

func historyEntry(r *recorder, c shellhistory.Command) {
	s := fmt.Sprintf("%s pid %d history entry %d: %s", c.Process, c.PID, c.Index, c.Command)
	r.stamp(object{subject: s, address: c.EntryAddress}, Entered, "CommandTime", c.CommandTime, c.CommandTimeOK)
}

func bootRow(r *recorder, b boottime.Row) {
	s := "boot"
	if b.Namespace != 0 {
		s = fmt.Sprintf("boot of time namespace %d", b.Namespace)
	}
	r.stamp(object{subject: s, address: b.NamespaceAddress}, Booted, "BootTime", b.BootTime, true)
}

func inodeTimes(r *recorder, o object, known bool, accessed, modified, changed timeOK) {
	r.stamp(o, Accessed, "Accessed", accessed.t, known && accessed.ok)
	r.stamp(o, Modified, "Modified", modified.t, known && modified.ok)
	r.stamp(o, Changed, "Changed", changed.t, known && changed.ok)
}

func openFile(r *recorder, f fileopen.File) {
	path := f.Path
	if path == "" {
		path = "unnamed file"
	}
	s := fmt.Sprintf("%s open as fd %d by %s pid %d tid %d", path, f.FD, f.Process, f.PID, f.TID)
	inodeTimes(r, object{subject: s}, f.InodeOK,
		timeOK{f.Accessed, f.AccessedOK}, timeOK{f.Modified, f.ModifiedOK}, timeOK{f.Changed, f.ChangedOK})
}

func cachedInode(r *recorder, f pagecache.File) {
	path := f.Path
	if path == "" {
		path = "unnamed"
	}
	s := fmt.Sprintf("cached inode %d %s", f.InodeNumber, path)
	inodeTimes(r, object{subject: s, address: f.InodeAddress}, true,
		timeOK{f.Accessed, f.AccessedOK}, timeOK{f.Modified, f.ModifiedOK}, timeOK{f.Changed, f.ChangedOK})
}
