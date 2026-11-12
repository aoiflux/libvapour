package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

func TestTheFilterFlagsReachTheSession(t *testing.T) {
	cfg := config(cli.Flags{}, filters{sanity: true, activeOnly: true, crossCheck: "seen.csv"})
	if !cfg.ProcessListSanityFilter || !cfg.ProcessListActiveOnly || cfg.ProcessListCrossCheckCSV != "seen.csv" ||
		!cfg.CollectDiagnostics {
		t.Errorf("config = %+v", cfg)
	}
}

func TestAProcessRowSaysWhatDidNotRead(t *testing.T) {
	var out strings.Builder
	printProcesses(&out, []processlist.Process{
		{PID: 4, Name: "System", EPROCESS: 0xffffa000, Columns: processlist.Columns{
			CreateTime: time.Date(2026, 5, 26, 20, 0, 0, 0, time.UTC)}},
		{PID: 900, Name: "x\x1b.exe", EPROCESS: 0xffffb000, Columns: processlist.Columns{
			PPIDUnreadable: true, CreateTimeUnreadable: true}},
	})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if f := strings.Fields(lines[1]); strings.Join(f, " ") != "4 0 System 0xffffa000 2026-05-26T20:00:00Z" {
		t.Errorf("row %q", lines[1])
	}
	if f := strings.Fields(lines[2]); strings.Join(f, " ") != "900 "+cli.Unreadable+` x\x1b.exe 0xffffb000 `+cli.Unreadable {
		t.Errorf("row %q", lines[2])
	}
}

func TestALinuxRowTakesTheTasksOwnColumns(t *testing.T) {
	var out strings.Builder
	printProcesses(&out, []processlist.Process{{PID: 3, Name: "pool_workqueue_", EPROCESS: 0xffff8d00,
		Linux: processlist.LinuxColumns{Read: true, PPID: 2, PPIDRead: true, CreationTime: time.Date(2026, 8, 22, 13, 0, 0, 0, time.UTC)}}})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if f := strings.Fields(lines[1]); strings.Join(f, " ") != "3 2 pool_workqueue_ 0xffff8d00 2026-08-22T13:00:00Z" {
		t.Errorf("row %q", lines[1])
	}
}
