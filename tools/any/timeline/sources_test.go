package timeline

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/any/processscan"
	"github.com/aoiflux/libvapour/tools/linux/boottime"
	"github.com/aoiflux/libvapour/tools/linux/fileopen"
	"github.com/aoiflux/libvapour/tools/linux/pagecache"
	"github.com/aoiflux/libvapour/tools/linux/shellhistory"
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

var (
	t1 = time.Date(2026, 5, 6, 18, 0, 0, 123456700, time.UTC)
	t2 = time.Date(2026, 5, 6, 18, 5, 0, 0, time.UTC)
	t3 = time.Date(1601, 1, 1, 0, 0, 0, 100, time.UTC)
)

func record[T any](tool string, each func(*recorder, T), rows ...T) *recorder {
	r := &recorder{summary: SourceSummary{Tool: tool}}
	for _, row := range rows {
		r.row()
		each(r, row)
	}
	return r
}

type want struct {
	event   Event
	field   string
	at      time.Time
	subject string
}

func check(t *testing.T, r *recorder, rows, absent int, wants ...want) {
	t.Helper()
	if r.summary.Rows != rows || r.summary.Absent != absent || r.summary.Entries != len(wants) || len(r.entries) != len(wants) {
		t.Fatalf("%s: rows %d absent %d entries %d/%d, want %d %d %d", r.summary.Tool, r.summary.Rows, r.summary.Absent,
			r.summary.Entries, len(r.entries), rows, absent, len(wants))
	}
	for i, w := range wants {
		e := r.entries[i]
		if e.Event != w.event || e.Field != w.field || !e.Time.Equal(w.at) || e.Time.Location() != time.UTC ||
			(w.subject != "" && e.Subject != w.subject) || e.Tool != r.summary.Tool {
			t.Errorf("%s entry %d = %+v, want %+v", r.summary.Tool, i, e, w)
		}
	}
}

func TestProcessRowsGiveCreateAndExitEventsUnlessUnread(t *testing.T) {
	local := time.FixedZone("x", 3600)
	r := record("p", listedProcess,
		processlist.Process{PID: 4, Name: "System", EPROCESS: 0xffff1000,
			Columns: processlist.Columns{CreateTime: t1.In(local), ExitTime: t2}},
		processlist.Process{PID: 8, EPROCESS: 0xffff2000,
			Columns: processlist.Columns{CreateTime: t1, CreateTimeUnreadable: true}},
	)
	check(t, r, 2, 2,
		want{Created, "CreateTime", t1, "process System pid 4"},
		want{Exited, "ExitTime", t2, "process System pid 4"})
	if r.entries[0].Address != 0xffff1000 {
		t.Errorf("address %#x", r.entries[0].Address)
	}
	s := record("s", scannedProcess, processscan.Process{PID: 9, Offset: 0x1000, VirtualOffset: 0,
		Columns: processlist.Columns{CreateTime: t1}})
	check(t, s, 1, 1, want{Created, "CreateTime", t1, "process pid 9"})
	if s.entries[0].Physical != 0x1000 || s.entries[0].Address != 0 {
		t.Errorf("scanned process placed at %+v", s.entries[0])
	}
}

func TestThreadRowsFollowTheirUnreadableFlags(t *testing.T) {
	r := record("t", listedThread,
		threadlist.Thread{PID: 4, TID: 8, ProcessName: "System", ETHREAD: 0x10,
			Columns: threadscan.Columns{CreateTime: t1, ExitTime: t2, ExitTimeUnreadable: true}})
	check(t, r, 1, 1, want{Created, "CreateTime", t1, "thread tid 8 pid 4 System"})
	s := record("s", scannedThread, threadscan.Thread{PID: 4, TID: 9, Offset: 0x20, VirtualOffset: 0x30,
		Columns: threadscan.Columns{ExitTime: t2}})
	check(t, s, 1, 1, want{Exited, "ExitTime", t2, "thread tid 9 pid 4"})
}

func TestLibraryNamePrefersTheFullPath(t *testing.T) {
	r := record("l", library,
		librarylist.DLL{PID: 1, ProcName: "a.exe", Name: "n.dll", FullPath: `C:\n.dll`, Base: 0x7ff0, LoadTime: t1},
		librarylist.DLL{PID: 1, ProcName: "a.exe", Name: "n.dll", FullPathUnreadable: true, LoadTime: t2},
		librarylist.DLL{PID: 1, NameUnreadable: true, FullPathUnreadable: true, LoadTime: t2, LoadTimeUnreadable: true},
	)
	check(t, r, 3, 1,
		want{Loaded, "LoadTime", t1, `library C:\n.dll in process a.exe pid 1`},
		want{Loaded, "LoadTime", t2, `library n.dll in process a.exe pid 1`})
}

func TestNTFSAttributeGivesFourEvents(t *testing.T) {
	row := ntfsrecord.Row{AttributeType: "$FILE_NAME", Name: "a.txt", NameKnown: true,
		CreationTime: t1, LastWriteTime: t2, ChangeTime: t3}
	row.RecordPhysical = 0x4000
	row.SegmentNumber, row.SegmentNumberKnown = 38, true
	row.ParentSegmentNumber = 5
	r := record("n", ntfsAttribute, row, ntfsrecord.Row{AttributeType: "$STANDARD_INFORMATION"})
	s := "$FILE_NAME of a.txt in record 38 under directory record 5"
	check(t, r, 2, 5,
		want{Created, "CreationTime", t1, s},
		want{Modified, "LastWriteTime", t2, s},
		want{Changed, "ChangeTime", t3, s})
	if r.summary.BeforeEpoch != 1 || r.entries[0].Physical != 0x4000 {
		t.Errorf("before epoch %d, physical %#x", r.summary.BeforeEpoch, r.entries[0].Physical)
	}
}

func TestEndpointSubjectsNameBothEndsOfAConnectionOnly(t *testing.T) {
	r := record("e", endpoint,
		network.Endpoint{Kind: network.KindConnection, Family: network.FamilyIPv4,
			LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 49000, RemoteIP: netip.MustParseAddr("10.0.0.2"),
			RemotePort: 443, State: network.TCPStateEstablished, OwningPID: 7, OwnerImage: "a.exe", CreateTime: t1},
		network.Endpoint{Kind: network.KindListener, Family: network.FamilyIPv6, LocalIP: netip.IPv6Unspecified(),
			LocalPort: 135, OwnerProblem: "x", CreateTime: t2},
		network.Endpoint{Kind: network.KindDatagram, Family: network.FamilyIPv4, LocalPort: 53, TimeProblem: "x"},
	)
	check(t, r, 3, 1,
		want{Created, "CreateTime", t1, "tcp_connection ipv4 10.0.0.1:49000 to 10.0.0.2:443 ESTABLISHED owned by process a.exe pid 7"},
		want{Created, "CreateTime", t2, "tcp_listener ipv6 [::]:135 listening"})
}

func TestTaskSessionCompatAndLinkRows(t *testing.T) {
	check(t, record("k", task, tasklist.Task{TreePath: `\T`, LastRunTime: t1, KeyLastWrite: t2}, tasklist.Task{GUIDUnreadable: true}), 2, 2,
		want{Ran, "LastRunTime", t1, `scheduled task \T`}, want{Written, "KeyLastWrite", t2, `scheduled task \T`})
	check(t, record("s", session, sessionlist.Row{SessionID: 1, PID: 5, Process: "a.exe", UserName: `D\u`, CreateTime: t1}), 1, 0,
		want{Created, "CreateTime", t1, `process a.exe pid 5 of D\u in session 1`})
	check(t, record("c", compatEntry, executioncompatcachememory.CacheEntry{KeyUnreadable: true, FileLastWrite: t1}), 1, 0,
		want{Modified, "FileLastWrite", t1, "compat cache entry with unread key"})
	check(t, record("o", symlink,
		objectlinks.Symlink{Name: "C:", Target: `\Device\X`, CreateTime: t1},
		objectlinks.Symlink{Name: "Y", Callback: true, CallbackRoutine: 0xf0, CreateTime: t2},
		objectlinks.Symlink{NameUnreadable: true, CreateTime: t2, CreateTimeUnreadable: true}), 3, 1,
		want{Created, "CreateTime", t1, `symbolic link C: to \Device\X`},
		want{Created, "CreateTime", t2, "symbolic link Y to callback 0xf0"})
	check(t, record("m", unloadedModule, moduleunloaded.Module{Name: "x.sys", Time: t1},
		moduleunloaded.Module{Name: "y.sys", SinceBoot: time.Second}), 2, 1,
		want{Unloaded, "Time", t1, "kernel module x.sys"})
}

func TestUserAssistKeyTimeIsOneEntryPerKey(t *testing.T) {
	v := executionuserassist.CountValue{HivePath: `C:\u\NTUSER.DAT`, HiveAddress: 0x99, Key: `S\{G}\Count`,
		CountKeyLastWrite: t2, ExpandedName: "a.exe", LaunchCount: 3, LastLaunch: t1}
	never := v
	never.ExpandedName, never.LaunchCount, never.LastLaunch = "b.exe", 0, time.Time{}
	r := record("u", userAssist(), v, never)
	check(t, r, 2, 1,
		want{Launched, "LastLaunch", t1, `UserAssist a.exe at S\{G}\Count, count 3`},
		want{Written, "CountKeyLastWrite", t2, `UserAssist key S\{G}\Count`})
	if again := record("u", userAssist(), v); again.summary.Entries != 2 {
		t.Errorf("a new run must not remember the keys of an earlier one: %d entries", again.summary.Entries)
	}
}

func TestAmcacheKeyWriteAndLinkTimesAreStamped(t *testing.T) {
	r := record("a", amcacheEntry, executionamcache.InventoryRecord{Category: executionamcache.DriverBinary,
		Path: `c:/windows/a.sys`, KeyLastWrite: t1, LinkTime: t2})
	check(t, r, 1, 0,
		want{Written, "KeyLastWrite", t1, `amcache driver_binary c:/windows/a.sys`},
		want{Linked, "LinkTime", t2, `amcache driver_binary c:/windows/a.sys`})
}

// LinkDate and InstallDate carry no zone (S63 O8), so they place no event.
func TestAmcacheZonelessDatesGiveNoEntry(t *testing.T) {
	r := record("a", amcacheEntry,
		executionamcache.InventoryRecord{Category: executionamcache.Application, Name: "App", ProgramID: "0000ab",
			InstallDate: "11/02/2026 10:00:00", KeyLastWrite: t1},
		executionamcache.InventoryRecord{Category: executionamcache.ApplicationFile, Path: `c:\a.exe`, LinkDate: "11/02/2026 10:00:00"})
	check(t, r, 2, 3, want{Written, "KeyLastWrite", t1, `amcache application App program 0000ab`})
}

func TestLinuxTaskRows(t *testing.T) {
	r := record("t", linuxTask,
		processlist.Process{PID: 1, EPROCESS: 0x10, Linux: processlist.LinuxColumns{Read: true, PID: 1, TID: 1, Comm: "init", CreationTime: t1}},
		processlist.Process{PID: 1, EPROCESS: 0x20, Linux: processlist.LinuxColumns{Read: true, PID: 1, TID: 2, Comm: "w", Thread: true, CreationTime: t2}},
		processlist.Process{PID: 3, Linux: processlist.LinuxColumns{Read: true, CreationTimeErr: errors.New("x"), CreationTime: t2}},
		processlist.Process{PID: 4, Linux: processlist.LinuxColumns{CreationTime: t2}},
	)
	check(t, r, 4, 2,
		want{Created, "CreationTime", t1, "task init pid 1"},
		want{Created, "CreationTime", t2, "thread w tid 2 pid 1"})
}

func TestLinuxHistoryBootAndFileRows(t *testing.T) {
	check(t, record("h", historyEntry,
		shellhistory.Command{PID: 9, Process: "bash", Index: 2, Command: "ls\n-l", CommandTime: t1, CommandTimeOK: true},
		shellhistory.Command{PID: 9, Process: "bash", Index: 3, Command: "x", CommandTime: t1}), 2, 1,
		want{Entered, "CommandTime", t1, "bash pid 9 history entry 2: ls\n-l"})
	check(t, record("b", bootRow, boottime.Row{BootTime: t1}, boottime.Row{Namespace: 4026531834, BootTime: t2}), 2, 0,
		want{Booted, "BootTime", t1, "boot"}, want{Booted, "BootTime", t2, "boot of time namespace 4026531834"})
	check(t, record("f", openFile,
		fileopen.File{PID: 1, TID: 1, Process: "a", FD: 3, Path: "/x", InodeOK: true, Accessed: t1, AccessedOK: true, Modified: t2, ModifiedOK: true},
		fileopen.File{PID: 1, TID: 1, Process: "a", FD: 4, Accessed: t1, AccessedOK: true}), 2, 4,
		want{Accessed, "Accessed", t1, "/x open as fd 3 by a pid 1 tid 1"},
		want{Modified, "Modified", t2, "/x open as fd 3 by a pid 1 tid 1"})
	check(t, record("c", cachedInode, pagecache.File{InodeNumber: 12, InodeAddress: 0x40, Changed: t3, ChangedOK: true}), 1, 2,
		want{Changed, "Changed", t3, "cached inode 12 unnamed"})
}

func TestEveryCatalogueSourceIsKnownAndOnce(t *testing.T) {
	for _, osName := range []string{windows, linux} {
		names := Sources(osName)
		if len(names) == 0 {
			t.Fatalf("no %s sources", osName)
		}
		sorted := slices.Clone(names)
		slices.Sort(sorted)
		if len(slices.Compact(sorted)) != len(names) {
			t.Errorf("%s sources repeat: %q", osName, names)
		}
	}
	if got := len(Sources(windows)) + len(Sources(linux)); got != len(catalogue) {
		t.Errorf("sources %d, catalogue %d", got, len(catalogue))
	}
}
