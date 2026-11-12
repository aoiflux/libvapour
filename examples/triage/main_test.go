package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools/any/memorycode"
	"github.com/aoiflux/libvapour/tools/windows/librarycompare"
	"github.com/aoiflux/libvapour/tools/windows/processcompare"
)

func TestTheProcessViewShowsTheToolsHiddenRows(t *testing.T) {
	rows := []processcompare.Row{
		{PID: 4, Name: "System", ActiveList: true, PoolScan: true, ThreadOwner: true, ExitTimeRead: true,
			Verdict: processcompare.VerdictListed},
		{PID: 900, Name: "sc.exe", PoolScan: true, ExitTimeRead: true, ExitTime: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			Verdict: processcompare.VerdictExited},
		{PID: 666, Name: "evil.exe", PoolScan: true, ThreadOwner: true, ExitTimeRead: true,
			Verdict: processcompare.VerdictHidden, Hidden: true},
	}
	var out strings.Builder
	printProcessViews(&out, rows, false)
	if !strings.Contains(out.String(), "evil.exe") || strings.Contains(out.String(), "sc.exe") ||
		!strings.Contains(out.String(), "1 of 3 processes shown") {
		t.Errorf("default view:\n%s", out.String())
	}
	out.Reset()
	printProcessViews(&out, append(rows, processcompare.Row{PID: 7, Name: "old.exe", PoolScan: true}), true)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if f := strings.Fields(lines[2]); f[8] != "2026-05-01T00:00:00Z" || f[9] != "exited" {
		t.Errorf("exited row %q", lines[2])
	}
	if f := strings.Fields(lines[4]); f[8] != cli.Unreadable {
		t.Errorf("unread exit time printed %q", lines[4])
	}
}

func TestOnlyAnImageOnOneLoaderListIsShown(t *testing.T) {
	mods := []librarycompare.Module{
		{PID: 1, Process: "app.exe", Base: 0x400000, InLoad: true, InMem: true, MappedPath: `\app.exe`},
		{PID: 1, Process: "app.exe", Base: 0x10000000, InInit: true, InMem: true, MappedPath: `\Temp\x.dll`},
		{PID: 1, Process: "app.exe", Base: 0x20000000, MappedPath: `\Windows\System32\en-US\app.exe.mui`},
		{PID: 2, Process: "idle.exe", Base: 0x30000000, LoaderListsEmpty: true},
	}
	var out strings.Builder
	printLoaderLists(&out, mods, false)
	got := out.String()
	if strings.Contains(got, "0x400000") || strings.Contains(got, "0x20000000") || strings.Contains(got, "0x30000000") ||
		!strings.Contains(got, "0x10000000") {
		t.Errorf("wrong images shown:\n%s", got)
	}
	for _, want := range []string{"1 of 4 mapped images shown", "1 mapped images are on neither list", "1 mapped images are in processes"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	out.Reset()
	printLoaderLists(&out, mods, true)
	if !strings.Contains(out.String(), "0x20000000") || !strings.Contains(out.String(), "N/A") ||
		strings.Contains(out.String(), "neither list") {
		t.Errorf("-all:\n%s", out.String())
	}
}

func TestAFindingShowsItsFirstBytes(t *testing.T) {
	header := append([]byte("MZ"), make([]byte, 62)...)
	if got := preview(header); got != "4d5a"+strings.Repeat("00", 14) {
		t.Errorf("preview = %q", got)
	}
	if got := preview([]byte{0xcc}); got != "cc" {
		t.Errorf("preview of one byte = %q", got)
	}
	var out strings.Builder
	printCode(&out, []memorycode.Finding{{PID: 1, Process: "a\x1b.exe", Preview: header}})
	if strings.Contains(out.String(), "\x1b") {
		t.Errorf("a process name wrote an escape byte: %q", out.String())
	}
	out.Reset()
	printLinuxCode(&out, []memorycode.LinuxFinding{{PID: 1, Process: "bash", Path: "/memfd:x", PathAvailable: true}})
	if !strings.Contains(out.String(), "/memfd:x") {
		t.Errorf("linux finding:\n%s", out.String())
	}
}
