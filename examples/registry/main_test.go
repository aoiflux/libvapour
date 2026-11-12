package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools/windows/registrykey"
)

const computerName = `ControlSet001\Control\ComputerName\ComputerName`

var written = time.Date(2022, 6, 18, 4, 26, 40, 0, time.UTC)

func TestEachHiveHasItsOwnHeading(t *testing.T) {
	items := []registrykey.Item{
		{HivePath: `\REGISTRY\MACHINE\SYSTEM`, HiveAddress: 0x1000, Path: computerName, Kind: registrykey.KindValue,
			Name: "ComputerName", Type: "REG_SZ", Data: "WIN-LAB", LastWrite: written},
		{HivePath: `\REGISTRY\MACHINE\SYSTEM`, HiveAddress: 0x1000, Path: computerName, Kind: registrykey.KindValue,
			Name: "(Default)", TypeUnreadable: true, DataUnreadable: true, LastWrite: written},
		{HiveAddress: 0x2000, Path: computerName, KeyNotRead: true},
	}
	groups := byHive(items)
	if len(groups) != 2 || len(groups[0]) != 2 || len(groups[1]) != 1 {
		t.Fatalf("byHive gave %d groups", len(groups))
	}
	var out strings.Builder
	for _, g := range groups {
		printHive(&out, g)
	}
	text := out.String()
	first, second, _ := strings.Cut(strings.TrimPrefix(text, "\n== "), "\n== ")
	lines := strings.Split(first, "\n")
	if !strings.HasPrefix(lines[0], `\REGISTRY\MACHINE\SYSTEM, hive at 0x1000`) {
		t.Errorf("first heading %q", lines[0])
	}
	if f := strings.Fields(lines[2]); strings.Join(f, " ") != "2022-06-18T04:26:40Z "+computerName+" ComputerName REG_SZ WIN-LAB" {
		t.Errorf("value row %q", lines[2])
	}
	if f := strings.Fields(lines[3]); f[3] != cli.Unreadable || f[4] != cli.Unreadable {
		t.Errorf("unread value row %q", lines[3])
	}
	if !strings.HasPrefix(second, cli.NoName+", hive at 0x2000") || !strings.Contains(second, "not in this hive") {
		t.Errorf("second hive:\n%s", second)
	}
}

func TestASubkeyIsIndentedByDepth(t *testing.T) {
	var out strings.Builder
	printHive(&out, []registrykey.Item{
		{HivePath: "SYSTEM", Path: `Select`, Kind: registrykey.KindKey, Name: "Select", LastWriteUnreadable: true},
		{HivePath: "SYSTEM", Path: `Select\Deeper`, Kind: registrykey.KindKey, Name: "Deeper", Depth: 1},
	})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if !strings.HasPrefix(lines[2], cli.Unreadable) || !strings.Contains(lines[3], ". Deeper") ||
		!strings.HasPrefix(lines[3], "-") {
		t.Errorf("rows:\n%s", out.String())
	}
}
