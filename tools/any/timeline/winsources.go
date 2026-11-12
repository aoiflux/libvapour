package timeline

import (
	"fmt"
	"net/netip"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/any/processscan"
	"github.com/aoiflux/libvapour/tools/windows/executionamcache"
	"github.com/aoiflux/libvapour/tools/windows/executioncompatcachememory"
	"github.com/aoiflux/libvapour/tools/windows/executionuserassist"
	"github.com/aoiflux/libvapour/tools/windows/librarylist"
	"github.com/aoiflux/libvapour/tools/windows/moduleunloaded"
	"github.com/aoiflux/libvapour/tools/windows/network"
	"github.com/aoiflux/libvapour/tools/windows/ntfsrecord"
	"github.com/aoiflux/libvapour/tools/windows/objectlinks"
	"github.com/aoiflux/libvapour/tools/windows/sessionlist"
	"github.com/aoiflux/libvapour/tools/windows/tasklist"
	"github.com/aoiflux/libvapour/tools/windows/threadlist"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
)

const windows = "windows"

func processSubject(name string, pid uint64) string {
	if name == "" {
		return fmt.Sprintf("process pid %d", pid)
	}
	return fmt.Sprintf("process %s pid %d", name, pid)
}

func processTimes(r *recorder, o object, c processlist.Columns) {
	r.stamp(o, Created, "CreateTime", c.CreateTime, !c.CreateTimeUnreadable)
	r.stamp(o, Exited, "ExitTime", c.ExitTime, !c.ExitTimeUnreadable)
}

func listedProcess(r *recorder, p processlist.Process) {
	processTimes(r, object{subject: processSubject(p.Name, p.PID), address: p.EPROCESS}, p.Columns)
}

func scannedProcess(r *recorder, p processscan.Process) {
	o := object{subject: processSubject(p.Name, p.PID), address: p.VirtualOffset, physical: p.Offset}
	processTimes(r, o, p.Columns)
}

func threadTimes(r *recorder, o object, c threadscan.Columns) {
	r.stamp(o, Created, "CreateTime", c.CreateTime, !c.CreateTimeUnreadable)
	r.stamp(o, Exited, "ExitTime", c.ExitTime, !c.ExitTimeUnreadable)
}

func listedThread(r *recorder, t threadlist.Thread) {
	s := fmt.Sprintf("thread tid %d pid %d", t.TID, t.PID)
	if t.ProcessName != "" {
		s += " " + t.ProcessName
	}
	threadTimes(r, object{subject: s, address: t.ETHREAD}, t.Columns)
}

func scannedThread(r *recorder, t threadscan.Thread) {
	o := object{subject: fmt.Sprintf("thread tid %d pid %d", t.TID, t.PID), address: t.VirtualOffset, physical: t.Offset}
	threadTimes(r, o, t.Columns)
}

func library(r *recorder, d librarylist.DLL) {
	name := "unnamed library"
	switch {
	case !d.FullPathUnreadable && d.FullPath != "":
		name = d.FullPath
	case !d.NameUnreadable && d.Name != "":
		name = d.Name
	}
	s := fmt.Sprintf("library %s in %s", name, processSubject(d.ProcName, d.PID))
	r.stamp(object{subject: s, address: d.Base}, Loaded, "LoadTime", d.LoadTime, !d.LoadTimeUnreadable)
}

func ntfsAttribute(r *recorder, row ntfsrecord.Row) {
	name := "unnamed file"
	if row.NameKnown {
		name = row.Name
	}
	s := fmt.Sprintf("%s of %s", row.AttributeType, name)
	if row.SegmentNumberKnown {
		s += fmt.Sprintf(" in record %d", row.SegmentNumber)
	}
	// Hard links repeat one name in one record; the directory tells them apart.
	if row.AttributeType == "$FILE_NAME" {
		s += fmt.Sprintf(" under directory record %d", row.ParentSegmentNumber)
	}
	o := object{subject: s, physical: row.RecordPhysical}
	r.stamp(o, Created, "CreationTime", row.CreationTime, true)
	r.stamp(o, Modified, "LastWriteTime", row.LastWriteTime, true)
	r.stamp(o, Changed, "ChangeTime", row.ChangeTime, true)
	r.stamp(o, Accessed, "LastAccessTime", row.LastAccessTime, true)
}

func endpointText(ip netip.Addr, port uint16) string {
	if !ip.IsValid() {
		return fmt.Sprintf("unread:%d", port)
	}
	return netip.AddrPortFrom(ip, port).String()
}

func endpoint(r *recorder, e network.Endpoint) {
	s := fmt.Sprintf("%s %s %s", e.Kind, e.Family, endpointText(e.LocalIP, e.LocalPort))
	switch e.Kind {
	case network.KindConnection:
		s += fmt.Sprintf(" to %s %s", endpointText(e.RemoteIP, e.RemotePort), e.State)
	case network.KindListener:
		s += " listening"
	}
	if e.OwnerProblem == "" {
		s += " owned by " + processSubject(e.OwnerImage, e.OwningPID)
	}
	o := object{subject: s, address: e.ObjectAddress, physical: e.ObjectPhysical}
	r.stamp(o, Created, "CreateTime", e.CreateTime, true)
}

func task(r *recorder, t tasklist.Task) {
	name := "unnamed"
	switch {
	case t.Path != "":
		name = t.Path
	case t.TreePath != "":
		name = t.TreePath
	case !t.GUIDUnreadable && t.GUID != "":
		name = t.GUID
	}
	o := object{subject: "scheduled task " + name}
	r.stamp(o, Ran, "LastRunTime", t.LastRunTime, true)
	r.stamp(o, Written, "KeyLastWrite", t.KeyLastWrite, true)
}

func session(r *recorder, row sessionlist.Row) {
	s := processSubject(row.Process, row.PID)
	if row.UserName != "" {
		s += " of " + row.UserName
	}
	s += fmt.Sprintf(" in session %d", row.SessionID)
	r.stamp(object{subject: s, address: row.EPROCESS}, Created, "CreateTime", row.CreateTime, true)
}

func compatEntry(r *recorder, e executioncompatcachememory.CacheEntry) {
	key := e.Key
	if e.KeyUnreadable || key == "" {
		key = "with unread key"
	}
	o := object{subject: "compat cache entry " + key, address: e.Address}
	r.stamp(o, Modified, "FileLastWrite", e.FileLastWrite, true)
}

// The key time is shared by every value under the key, so it is one entry
// per key, not per value.
func userAssist() func(*recorder, executionuserassist.CountValue) {
	type keyID struct {
		hive uint64
		key  string
	}
	seen := map[keyID]bool{}
	return func(r *recorder, v executionuserassist.CountValue) {
		name := v.ExpandedName
		if v.NameUnreadable || name == "" {
			name = "unread name"
		}
		o := object{subject: fmt.Sprintf("UserAssist %s at %s, count %d", name, v.Key, v.LaunchCount)}
		r.stamp(o, Launched, "LastLaunch", v.LastLaunch, true)
		id := keyID{v.HiveAddress, v.Key}
		if seen[id] {
			return
		}
		seen[id] = true
		k := object{subject: "UserAssist key " + v.Key, address: v.HiveAddress}
		r.stamp(k, Written, "CountKeyLastWrite", v.CountKeyLastWrite, true)
	}
}

func readUserAssist(ctx tools.Context, r *recorder) error {
	return rowsOf(userAssist())(ctx, r)
}

func amcacheEntry(r *recorder, e executionamcache.InventoryRecord) {
	s := "amcache " + string(e.Category)
	if e.Path != "" {
		s += " " + e.Path
	} else if e.Name != "" {
		s += " " + e.Name
	}
	if e.ProgramID != "" {
		s += " program " + e.ProgramID
	}
	o := object{subject: s, address: e.HiveAddress}
	r.stamp(o, Written, "KeyLastWrite", e.KeyLastWrite, !e.KeyLastWrite.IsZero())
	r.stamp(o, Linked, "LinkTime", e.LinkTime, !e.LinkTime.IsZero())
}

func symlink(r *recorder, l objectlinks.Symlink) {
	name, target := l.Name, l.Target
	if l.NameUnreadable {
		name = "unread name"
	}
	switch {
	case l.Callback:
		target = fmt.Sprintf("callback 0x%x", l.CallbackRoutine)
	case l.TargetUnreadable:
		target = "unread target"
	}
	o := object{subject: fmt.Sprintf("symbolic link %s to %s", name, target), address: l.VirtualOffset, physical: l.Offset}
	r.stamp(o, Created, "CreateTime", l.CreateTime, !l.CreateTimeUnreadable)
}

func unloadedModule(r *recorder, m moduleunloaded.Module) {
	name := m.Name
	if m.NameUnreadable || name == "" {
		name = "with unread name"
	}
	o := object{subject: "kernel module " + name, address: m.StartAddress}
	r.stamp(o, Unloaded, "Time", m.Time, true)
}
