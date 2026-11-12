package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	libvapour "github.com/aoiflux/libvapour"
	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processarguments"
	"github.com/aoiflux/libvapour/tools/any/processtree"
	linuxlibraries "github.com/aoiflux/libvapour/tools/linux/librarylist"
	linuxmodules "github.com/aoiflux/libvapour/tools/linux/modulelist"
	windowslibraries "github.com/aoiflux/libvapour/tools/windows/librarylist"
	windowsmodules "github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/tools/windows/threadlist"
)

func main() {
	var flags cli.Flags
	flags.Register(flag.CommandLine)
	pid := flag.Uint64("pid", 0, "also list what this process has loaded: DLLs and threads on windows, libraries on linux")
	image := cli.Parse("processes [flags] <image>")
	if err := run(os.Stdout, os.Stderr, image, flags, *pid); err != nil {
		log.Fatal(err)
	}
}

func run(stdout, stderr io.Writer, image string, flags cli.Flags, pid uint64) error {
	session, err := libvapour.OpenMemory(image, flags.OS, flags.Config())
	if err != nil {
		return err
	}
	defer session.Close()
	defer func() { cli.PrintDiagnostics(stderr, session.Diagnostics(), flags.Verbose) }()
	ctx := session.Context()

	roots, err := processtree.Run(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", processtree.Name, err)
	}
	args, err := processarguments.Run(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", processarguments.Name, err)
	}
	cli.Heading(stdout, "process tree")
	printTree(stdout, processtree.Flatten(roots), args)

	cli.Heading(stdout, "kernel modules")
	if err := printKernelModules(stdout, ctx, flags.Windows()); err != nil {
		return err
	}
	if pid == 0 {
		return nil
	}

	one := cli.WithOptions(ctx, map[string]any{"pid": pid})
	if !flags.Windows() {
		libs, err := linuxlibraries.Run(one)
		if err != nil {
			return fmt.Errorf("%s: %w", linuxlibraries.Name, err)
		}
		cli.Heading(stdout, fmt.Sprintf("libraries mapped by PID %d", pid))
		printLibraries(stdout, libs)
		return nil
	}
	dlls, err := windowslibraries.Run(one)
	if err != nil {
		return fmt.Errorf("%s: %w", windowslibraries.Name, err)
	}
	cli.Heading(stdout, fmt.Sprintf("DLLs of PID %d", pid))
	printDLLs(stdout, dlls)
	threads, err := threadlist.Run(one)
	if err != nil {
		return fmt.Errorf("%s: %w", threadlist.Name, err)
	}
	cli.Heading(stdout, fmt.Sprintf("threads of PID %d", pid))
	printThreads(stdout, threads)
	return nil
}

// The join is on the kernel object's address, not the PID: an exited
// process and the one that reused its PID can both be in the image.
func printTree(w io.Writer, entries []*processtree.Entry, args []processarguments.ProcessCmdline) {
	byObject := make(map[uint64]processarguments.ProcessCmdline, len(args))
	for _, a := range args {
		byObject[a.Address] = a
	}
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "PID\tPPID\tName\tCommand line")
	for _, e := range entries {
		cmdline := cli.NotListed
		if a, ok := byObject[e.EPROCESS]; ok {
			cmdline = cli.Cell(a.Cmdline, a.CmdlineUnreadable)
			if cmdline == "" {
				cmdline = cli.EmptyCmdline
			}
		}
		name := strings.Repeat(". ", e.Depth) + cli.Text(e.Name)
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", e.PID, cli.Decimal(e.PPID, e.PPIDUnreadable), name, cmdline)
	}
	tw.Flush()
}

func printKernelModules(w io.Writer, ctx tools.Context, windows bool) error {
	tw := cli.NewTable(w)
	defer tw.Flush()
	fmt.Fprintln(tw, "Base\tSize\tName")
	if !windows {
		rows, err := linuxmodules.Run(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", linuxmodules.Name, err)
		}
		for _, m := range rows {
			fmt.Fprintf(tw, "0x%x\t0x%x\t%s\n", m.Base, m.CoreSize, cli.Text(m.Name))
		}
		return nil
	}
	mods, err := windowsmodules.Run(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", windowsmodules.Name, err)
	}
	for _, m := range mods {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", cli.Hex(m.Base, m.BaseUnreadable), cli.Hex(m.Size, m.SizeUnreadable),
			cli.Cell(m.Name, m.NameUnreadable))
	}
	return nil
}

func printDLLs(w io.Writer, dlls []windowslibraries.DLL) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "Base\tSize\tLoaded\tPath")
	for _, d := range dlls {
		fmt.Fprintf(tw, "0x%x\t%s\t%s\t%s\n", d.Base, cli.Hex(d.Size, d.SizeUnreadable),
			cli.Time(d.LoadTime, d.LoadTimeUnreadable), cli.Cell(d.FullPath, d.FullPathUnreadable))
	}
	tw.Flush()
}

func startFile(t threadlist.Thread) string {
	switch {
	case t.Win32StartAddressUnreadable:
		return cli.Unreadable
	case t.Win32StartPath == "":
		return "N/A"
	}
	return cli.Text(t.Win32StartPath)
}

func printThreads(w io.Writer, threads []threadlist.Thread) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "TID\tState\tCreated\tStart\tStart file")
	for _, t := range threads {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", t.TID, cli.Cell(t.StateName, t.StateUnreadable),
			cli.Time(t.CreateTime, t.CreateTimeUnreadable), cli.Hex(t.Win32StartAddress, t.Win32StartAddressUnreadable),
			startFile(t))
	}
	tw.Flush()
}

func printLibraries(w io.Writer, libs []linuxlibraries.Library) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "Base\tRoute\tPath")
	for _, l := range libs {
		fmt.Fprintf(tw, "0x%x\t%s\t%s\n", l.BaseAddress, l.Route, cli.Text(l.Path))
	}
	tw.Flush()
}
