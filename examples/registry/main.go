package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	libvapour "github.com/aoiflux/libvapour"
	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools/windows/registrykey"
)

func main() {
	var flags cli.Flags
	flags.Register(flag.CommandLine)
	hive := flag.String("hive", "SYSTEM", "the hives to read, by the end of their path such as SYSTEM or SOFTWARE;\n"+
		"where no hive path ends in it, the hives whose path contains it; empty reads every hive")
	key := flag.String("key", `ControlSet001\Control\ComputerName\ComputerName`, "the key to list, from the hive's root; empty lists the root")
	recurse := flag.Bool("recurse", false, "list every level of subkeys, not only the first")
	image := cli.Parse("registry [flags] <image>")
	if !flags.Windows() {
		cli.UsageError(errors.New("registry: the registry is in windows images only"))
	}
	if err := run(os.Stdout, os.Stderr, image, flags, *hive, *key, *recurse); err != nil {
		log.Fatal(err)
	}
}

func run(stdout, stderr io.Writer, image string, flags cli.Flags, hive, key string, recurse bool) error {
	cfg := flags.Config()
	cfg.ToolOptions = map[string]any{
		registrykey.OptionHive:    hive,
		registrykey.OptionPath:    key,
		registrykey.OptionRecurse: recurse,
	}
	session, err := libvapour.OpenMemory(image, flags.OS, cfg)
	if err != nil {
		return err
	}
	defer session.Close()
	defer func() { cli.PrintDiagnostics(stderr, session.Diagnostics(), flags.Verbose) }()

	items, err := registrykey.Run(session.Context())
	if err != nil {
		return fmt.Errorf("%s: %w", registrykey.Name, err)
	}
	for _, hiveItems := range byHive(items) {
		printHive(stdout, hiveItems)
	}
	return nil
}

// Rows of one hive are adjacent in the tool's output, so a change of hive
// address starts the next group.
func byHive(items []registrykey.Item) [][]registrykey.Item {
	var groups [][]registrykey.Item
	for i, it := range items {
		if i == 0 || it.HiveAddress != items[i-1].HiveAddress {
			groups = append(groups, nil)
		}
		groups[len(groups)-1] = append(groups[len(groups)-1], it)
	}
	return groups
}

func printHive(w io.Writer, items []registrykey.Item) {
	name := cli.NoName
	if items[0].HivePath != "" {
		name = cli.Text(items[0].HivePath)
	}
	cli.Heading(w, fmt.Sprintf("%s, hive at 0x%x", name, items[0].HiveAddress))
	if len(items) == 1 && items[0].KeyNotRead {
		fmt.Fprintf(w, "%s: not in this hive, or a key on its path does not read\n", cli.Text(items[0].Path))
		return
	}
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "Last written\tKey\tName\tType\tData")
	for _, it := range items {
		kind, data := "key", ""
		if it.Kind == registrykey.KindValue {
			kind, data = cli.Cell(it.Type, it.TypeUnreadable), cli.Cell(it.Data, it.DataUnreadable)
		}
		name := strings.Repeat(". ", it.Depth) + cli.Cell(it.Name, it.NameUnreadable)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", cli.Time(it.LastWrite, it.LastWriteUnreadable), cli.Text(it.Path), name,
			kind, data)
	}
	tw.Flush()
}
