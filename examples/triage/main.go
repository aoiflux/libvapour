package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	libvapour "github.com/aoiflux/libvapour"
	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memorycode"
	"github.com/aoiflux/libvapour/tools/windows/librarycompare"
	"github.com/aoiflux/libvapour/tools/windows/processcompare"
)

const previewBytes = 16

func main() {
	var flags cli.Flags
	flags.Register(flag.CommandLine)
	all := flag.Bool("all", false, "windows only: print every row of the process and loader-list comparisons,\n"+
		"not only the rows that disagree")
	image := cli.Parse("triage [flags] <image>")
	if err := run(os.Stdout, os.Stderr, image, flags, *all); err != nil {
		log.Fatal(err)
	}
}

func run(stdout, stderr io.Writer, image string, flags cli.Flags, all bool) error {
	session, err := libvapour.OpenMemory(image, flags.OS, flags.Config())
	if err != nil {
		return err
	}
	defer session.Close()
	defer func() { cli.PrintDiagnostics(stderr, session.Diagnostics(), flags.Verbose) }()
	ctx := session.Context()

	const codeTitle = "executable memory that may hold injected code (" + memorycode.Name + ")"
	if !flags.Windows() {
		found, err := memorycode.RunLinux(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", memorycode.Name, err)
		}
		cli.Heading(stdout, codeTitle)
		printLinuxCode(stdout, found)
		return nil
	}

	// A lead from one check is worth having when another fails, so each
	// failure is printed under its heading and the run goes on.
	var failures []error
	for _, check := range []struct {
		title string
		run   func(tools.Context) error
	}{
		{codeTitle, func(ctx tools.Context) error {
			found, err := memorycode.Run(ctx)
			if err == nil {
				printCode(stdout, found)
			}
			return err
		}},
		{"processes missing from the active process list (" + processcompare.Name + ")", func(ctx tools.Context) error {
			rows, err := processcompare.Run(ctx)
			if err == nil {
				printProcessViews(stdout, rows, all)
			}
			return err
		}},
		{"mapped images missing from a loader list (" + librarycompare.Name + ")", func(ctx tools.Context) error {
			mods, err := librarycompare.Run(ctx)
			if err == nil {
				printLoaderLists(stdout, mods, all)
			}
			return err
		}},
	} {
		cli.Heading(stdout, check.title)
		if err := check.run(ctx); err != nil {
			fmt.Fprintf(stdout, "not checked: %s\n", cli.Text(err.Error()))
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func preview(b []byte) string {
	return hex.EncodeToString(b[:min(len(b), previewBytes)])
}

func printCode(w io.Writer, found []memorycode.Finding) {
	fmt.Fprintf(w, "%d regions\n", len(found))
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "PID\tProcess\tStart\tEnd\tProtection\tRule\tHeader\tFirst bytes")
	for _, f := range found {
		fmt.Fprintf(tw, "%d\t%s\t0x%x\t0x%x\t%s\t%s\t%s\t%s\n", f.PID, cli.Text(f.Process), f.Start, f.End,
			cli.Text(f.Protection), cli.Text(string(f.Rule)), cli.Text(string(f.Header)), preview(f.Preview))
	}
	tw.Flush()
}

func printLinuxCode(w io.Writer, found []memorycode.LinuxFinding) {
	fmt.Fprintf(w, "%d regions\n", len(found))
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "PID\tProcess\tStart\tEnd\tProtection\tRule\tFile\tFirst bytes")
	for _, f := range found {
		file := "N/A"
		if f.PathAvailable {
			file = cli.Text(f.Path)
		}
		fmt.Fprintf(tw, "%d\t%s\t0x%x\t0x%x\t%s\t%s\t%s\t%s\n", f.PID, cli.Text(f.Process), f.Start, f.End,
			cli.Text(f.Protection), cli.Text(string(f.Rule)), file, preview(f.Preview))
	}
	tw.Flush()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// The verdict printed is the tool's own; the program only chooses which rows
// to show.
func printProcessViews(w io.Writer, rows []processcompare.Row, all bool) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "PID\tName\tActive list\tKernel list\tSession\tPool scan\tThread owner\tCSRSS handle\tExit time\tVerdict")
	shown := 0
	for _, r := range rows {
		if !all && !r.Hidden {
			continue
		}
		shown++
		exit := "-"
		if !r.ExitTimeRead {
			exit = cli.Unreadable
		} else if !r.ExitTime.IsZero() {
			exit = cli.Time(r.ExitTime, false)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.PID, cli.Text(r.Name), yesNo(r.ActiveList),
			yesNo(r.KernelList), yesNo(r.SessionRing), yesNo(r.PoolScan), yesNo(r.ThreadOwner), yesNo(r.CsrssHandle),
			exit, cli.Text(string(r.Verdict)))
	}
	tw.Flush()
	fmt.Fprintf(w, "%d of %d processes shown\n", shown, len(rows))
}

// An image on neither list is counted, not shown: resource files mapped as
// images are on neither, and a clean system has dozens.
func printLoaderLists(w io.Writer, mods []librarycompare.Module, all bool) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "PID\tProcess\tBase\tLoad order\tInit order\tMemory order\tMapped file")
	shown, neither, unlisted := 0, 0, 0
	for _, m := range mods {
		switch {
		case m.LoaderListsEmpty:
			unlisted++
		case !m.InLoad && !m.InMem:
			neither++
		}
		if !all && (m.LoaderListsEmpty || m.InLoad == m.InMem) {
			continue
		}
		shown++
		file := cli.Cell(m.MappedPath, m.MappedPathUnreadable)
		if file == "" {
			file = "N/A"
		}
		fmt.Fprintf(tw, "%d\t%s\t0x%x\t%s\t%s\t%s\t%s\n", m.PID, cli.Text(m.Process), m.Base, yesNo(m.InLoad),
			yesNo(m.InInit), yesNo(m.InMem), file)
	}
	tw.Flush()
	fmt.Fprintf(w, "%d of %d mapped images shown\n", shown, len(mods))
	if !all && neither > 0 {
		fmt.Fprintf(w, "%d mapped images are on neither list, as resource files mapped as images are; -all shows them\n", neither)
	}
	if !all && unlisted > 0 {
		fmt.Fprintf(w, "%d mapped images are in processes whose loader lists gave no record, so they were not compared\n", unlisted)
	}
}
