package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	libvapour "github.com/aoiflux/libvapour"
	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/windows/memorydump"
	"github.com/aoiflux/libvapour/tools/windows/processdump"
)

func main() {
	var flags cli.Flags
	flags.Register(flag.CommandLine)
	pid := flag.Uint64("pid", 0, "the process to read (required)")
	out := flag.String("out", "", "windows only: write the process's minidump and one file per memory range into this directory\n"+
		"(a missing directory is created readable by you alone; no existing file is overwritten)")
	image := cli.Parse("memory -pid <pid> [flags] <image>")
	if err := checkFlags(flags.Windows(), *pid, *out); err != nil {
		cli.UsageError(err)
	}
	if err := run(os.Stdout, os.Stderr, image, flags, *pid, *out); err != nil {
		log.Fatal(err)
	}
}

func checkFlags(windows bool, pid uint64, out string) error {
	switch {
	case pid == 0:
		return errors.New("memory: -pid is required")
	case out != "" && !windows:
		return errors.New("memory: -out writes windows minidumps; there is no linux writer")
	}
	return nil
}

func run(stdout, stderr io.Writer, image string, flags cli.Flags, pid uint64, out string) error {
	cfg := flags.Config()
	cfg.PID = pid
	if out != "" {
		cfg.ToolOptions = map[string]any{tools.OptionOutputDir: out}
	}
	session, err := libvapour.OpenMemory(image, flags.OS, cfg)
	if err != nil {
		return err
	}
	defer session.Close()
	defer func() { cli.PrintDiagnostics(stderr, session.Diagnostics(), flags.Verbose) }()
	ctx := session.Context()

	ranges, err := memoryranges.Run(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", memoryranges.MemoryListName, err)
	}
	cli.Heading(stdout, fmt.Sprintf("%d memory ranges of PID %d", len(ranges), pid))
	printRanges(stdout, ranges)
	if out == "" {
		return nil
	}

	dumps, err := processdump.Run(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", processdump.Name, err)
	}
	cli.Heading(stdout, "minidump in "+out)
	printDumps(stdout, dumps)

	files, err := memorydump.Run(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", memorydump.Name, err)
	}
	cli.Heading(stdout, "range files in "+out)
	printRangeFiles(stdout, files)
	return nil
}

func mappedFile(m memoryranges.Mapping) string {
	switch {
	case m.Path != "":
		return cli.Text(m.Path)
	case m.PathUnreadable && !m.NoFile:
		return cli.Unreadable
	}
	return "N/A"
}

func printRanges(w io.Writer, ranges []memoryranges.Mapping) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "Start\tEnd\tProtection\tType\tFile")
	for _, m := range ranges {
		fmt.Fprintf(tw, "0x%x\t0x%x\t%s\t%s\t%s\n", m.Start, m.End, cli.Text(m.Protection), cli.Text(m.Type),
			mappedFile(m))
	}
	tw.Flush()
}

func printDumps(w io.Writer, dumps []processdump.Artifact) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "File\tBytes\tModules\tThreads\tRegions\tFrom image\tZero-filled\tNot written because")
	for _, d := range dumps {
		if !d.Written() {
			fmt.Fprintf(tw, "-\t-\t-\t-\t-\t-\t-\t%s\n", cli.Text(d.Skipped))
			continue
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t-\n", cli.Text(d.FileName), d.Size, d.Modules, d.Threads,
			d.Regions, d.MemoryBytes, d.Gaps.PaddedBytes())
	}
	tw.Flush()
}

func printRangeFiles(w io.Writer, files []memorydump.Artifact) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "Start\tEnd\tFile\tBytes\tFrom image\tNot written because")
	for _, f := range files {
		if !f.Written() {
			fmt.Fprintf(tw, "0x%x\t0x%x\t-\t-\t-\t%s\n", f.Start, f.End, cli.Text(f.Skipped))
			continue
		}
		fmt.Fprintf(tw, "0x%x\t0x%x\t%s\t%d\t%d\t-\n", f.Start, f.End, cli.Text(f.FileName), f.Size, f.Captured)
	}
	tw.Flush()
}
