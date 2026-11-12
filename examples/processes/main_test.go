package main

import (
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools/any/processarguments"
	"github.com/aoiflux/libvapour/tools/any/processtree"
	linuxlibraries "github.com/aoiflux/libvapour/tools/linux/librarylist"
	"github.com/aoiflux/libvapour/tools/windows/threadlist"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
)

func treeRows(t *testing.T, entries []*processtree.Entry, args []processarguments.ProcessCmdline) []string {
	t.Helper()
	var out strings.Builder
	printTree(&out, entries, args)
	return strings.Split(strings.TrimSpace(out.String()), "\n")[1:]
}

func TestACommandLineFollowsItsProcessObjectNotItsPID(t *testing.T) {
	rows := treeRows(t, []*processtree.Entry{
		{PID: 700, Name: "old.exe", EPROCESS: 0xa000},
		{PID: 700, Name: "new.exe", EPROCESS: 0xb000, Depth: 1},
	}, []processarguments.ProcessCmdline{
		{PID: 700, Address: 0xb000, Cmdline: "new.exe --serve"},
		{PID: 700, Address: 0xa000, Cmdline: "old.exe --once"},
	})
	if !strings.Contains(rows[0], "old.exe") || !strings.HasSuffix(rows[0], "old.exe --once") ||
		!strings.Contains(rows[1], ". new.exe") || !strings.HasSuffix(rows[1], "new.exe --serve") {
		t.Errorf("command lines went to the wrong rows:\n%s", strings.Join(rows, "\n"))
	}
}

func TestAMissingCommandLineSaysWhy(t *testing.T) {
	rows := treeRows(t, []*processtree.Entry{
		{PID: 1, Name: "unlisted", EPROCESS: 0x1000},
		{PID: 2, Name: "unread", EPROCESS: 0x2000},
		{PID: 3, Name: "empty", EPROCESS: 0x3000},
	}, []processarguments.ProcessCmdline{
		{PID: 2, Address: 0x2000, CmdlineUnreadable: true},
		{PID: 3, Address: 0x3000},
	})
	for i, want := range []string{cli.NotListed, cli.Unreadable, cli.EmptyCmdline} {
		if !strings.HasSuffix(rows[i], want) {
			t.Errorf("row %q, want it to end in %s", rows[i], want)
		}
	}
}

func TestATreeNameIsEscaped(t *testing.T) {
	rows := treeRows(t, []*processtree.Entry{{PID: 9, Name: " evil\x1b[2J", EPROCESS: 0x9000}}, nil)
	if strings.Contains(rows[0], "\x1b") || !strings.Contains(rows[0], `\x20evil\x1b[2J`) {
		t.Errorf("row %q", rows[0])
	}
}

func TestAThreadsStartFileSaysWhyItIsMissing(t *testing.T) {
	var out strings.Builder
	printThreads(&out, []threadlist.Thread{
		{TID: 10, StateName: "Running", Columns: threadscan.Columns{Win32StartAddress: 0x7ff0,
			Win32StartPath: `\Windows\System32\kernel32.dll`}},
		{TID: 11, StateName: "Waiting", Columns: threadscan.Columns{Win32StartAddress: 0x1234}},
		{TID: 12, StateUnreadable: true, Columns: threadscan.Columns{Win32StartAddressUnreadable: true}},
	})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")[1:]
	for i, want := range []string{`\Windows\System32\kernel32.dll`, "N/A", cli.Unreadable} {
		if !strings.HasSuffix(lines[i], want) {
			t.Errorf("thread %d printed %q, want it to end in %s", 10+i, lines[i], want)
		}
	}
	if !strings.Contains(lines[2], cli.Unreadable+"  ") {
		t.Errorf("an unread state printed %q", lines[2])
	}
}

func TestALibraryRowNamesItsRoute(t *testing.T) {
	var out strings.Builder
	printLibraries(&out, []linuxlibraries.Library{
		{BaseAddress: 0x7f00, Path: "/usr/lib/libc.so.6", Route: linuxlibraries.RouteLinkerList},
		{BaseAddress: 0x7e00, Path: "/usr/lib/libz.so.1", Route: linuxlibraries.RouteMappedImage},
	})
	rows := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(rows) != 3 || !strings.Contains(rows[0], "Route") ||
		!strings.Contains(rows[1], linuxlibraries.RouteLinkerList) || !strings.Contains(rows[2], linuxlibraries.RouteMappedImage) {
		t.Errorf("library table:\n%s", out.String())
	}
}
