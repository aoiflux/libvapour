package main

import (
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/windows/memorydump"
	"github.com/aoiflux/libvapour/tools/windows/processdump"
)

func TestFlagsThatCannotWorkAreRefusedBeforeTheImageOpens(t *testing.T) {
	if checkFlags(true, 0, "") == nil {
		t.Error("no -pid was accepted")
	}
	if checkFlags(false, 1, "out") == nil {
		t.Error("-out was accepted for linux")
	}
	if checkFlags(false, 1, "") != nil || checkFlags(true, 4, "out") != nil {
		t.Error("a usable command line was refused")
	}
}

func TestEachRangeSaysWhatFileItMaps(t *testing.T) {
	ranges := []memoryranges.Mapping{
		{Start: 0x10000, End: 0x1ffff, Protection: "PAGE_READWRITE", Type: memoryranges.KindPrivate, NoFile: true},
		{Start: 0x20000, End: 0x2ffff, Protection: "PAGE_READONLY", Type: memoryranges.KindMapped, PathUnreadable: true},
		{Start: 0x7ff0000, End: 0x7ffffff, Protection: "PAGE_EXECUTE_WRITECOPY", Type: memoryranges.KindImage,
			Path: `\Windows\System32\kernel32.dll`},
	}
	var out strings.Builder
	printRanges(&out, ranges)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")[1:]
	for i, want := range []string{"N/A", cli.Unreadable, `\Windows\System32\kernel32.dll`} {
		if !strings.HasSuffix(lines[i], want) {
			t.Errorf("row %d is %q, want it to end in %s", i, lines[i], want)
		}
	}
}

func TestADumpCountsTheBytesItZeroFilled(t *testing.T) {
	var out strings.Builder
	printDumps(&out, []processdump.Artifact{
		{FileName: "process.4242.dmp", Size: 9000, MemoryBytes: 4096, Gaps: extract.GapMap{{Start: 0x1000, Length: 0x2000}}},
		{Skipped: "no address space"},
	})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if f := strings.Fields(lines[1]); f[0] != "process.4242.dmp" || f[5] != "4096" || f[6] != "8192" {
		t.Errorf("written dump printed %q", lines[1])
	}
	if !strings.HasSuffix(lines[2], "no address space") {
		t.Errorf("skipped dump printed %q", lines[2])
	}

	out.Reset()
	printRangeFiles(&out, []memorydump.Artifact{{Start: 0x10000, End: 0x1ffff, Skipped: "file exists"}})
	if !strings.HasSuffix(strings.TrimSpace(out.String()), "file exists") {
		t.Errorf("skipped range printed %q", out.String())
	}
}
