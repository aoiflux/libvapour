package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	libvapour "github.com/aoiflux/libvapour"
	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

type filters struct {
	sanity     bool
	activeOnly bool
	crossCheck string
}

func main() {
	var flags cli.Flags
	var f filters
	flags.Register(flag.CommandLine)
	flag.BoolVar(&f.sanity, "process-list-sanity", false, "leave out rows whose fields fail the list's plausibility checks")
	flag.BoolVar(&f.activeOnly, "process-list-active-only", false,
		"keep only running processes: plausible, not exited, with threads, and not System itself (its children stay)")
	flag.StringVar(&f.crossCheck, "process-list-cross-check-csv", "", "a CSV of processes seen by other means, compared with the list")
	image := cli.Parse("processlist [flags] <image>")
	if err := run(os.Stdout, os.Stderr, image, flags, f); err != nil {
		log.Fatal(err)
	}
}

func config(flags cli.Flags, f filters) libvapour.OpenConfig {
	cfg := flags.Config()
	cfg.ProcessListSanityFilter = f.sanity
	cfg.ProcessListActiveOnly = f.activeOnly
	cfg.ProcessListCrossCheckCSV = f.crossCheck
	return cfg
}

// The tool runs by its registered name, as a program that takes tool names
// from its user would run it; the typed result is then asserted.
func run(stdout, stderr io.Writer, image string, flags cli.Flags, f filters) error {
	report, err := libvapour.AnalyzeMemory(image, flags.OS, config(flags, f), []string{processlist.Name})
	if err != nil {
		return err
	}
	defer cli.PrintDiagnostics(stderr, report.Diagnostics, flags.Verbose)
	if len(report.Tools) != 1 {
		return fmt.Errorf("%s: %d results, want 1", processlist.Name, len(report.Tools))
	}
	result := report.Tools[0]
	if result.Error != nil {
		return fmt.Errorf("%s: %w", processlist.Name, result.Error)
	}
	processes, ok := result.Result.([]processlist.Process)
	if !ok {
		return fmt.Errorf("%s: result is %T, not []processlist.Process", processlist.Name, result.Result)
	}
	printProcesses(stdout, processes)
	return nil
}

func printProcesses(w io.Writer, processes []processlist.Process) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "PID\tPPID\tName\tObject\tCreated")
	for _, p := range processes {
		ppid, created := cli.Decimal(p.PPID, p.PPIDUnreadable), cli.Time(p.CreateTime, p.CreateTimeUnreadable)
		if p.Linux.Read {
			ppid, created = cli.Decimal(p.Linux.PPID, !p.Linux.PPIDRead), cli.Time(p.Linux.CreationTime, p.Linux.CreationTimeErr != nil)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t0x%x\t%s\n", p.PID, ppid, cli.Text(p.Name), p.EPROCESS, created)
	}
	tw.Flush()
}
