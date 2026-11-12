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
	"github.com/aoiflux/libvapour/tools/any/timeline"
)

func main() {
	var flags cli.Flags
	flags.Register(flag.CommandLine)
	sources := flag.String("tools", "", "comma-separated words: run only the sources whose tool name contains one,\n"+
		"such as any.process.list,windows.thread.list; every source runs when empty")
	out := flag.String("out", "", "also write a body file into this directory\n"+
		"(a missing directory is created readable by you alone; no existing file is overwritten)")
	image := cli.Parse("timeline [flags] <image>")
	if err := run(os.Stdout, os.Stderr, image, flags, words(*sources), *out); err != nil {
		log.Fatal(err)
	}
}

func words(list string) []string {
	var out []string
	for _, w := range strings.Split(list, ",") {
		if w = strings.TrimSpace(w); w != "" {
			out = append(out, w)
		}
	}
	return out
}

func options(sources []string, out string) map[string]any {
	opts := map[string]any{}
	if len(sources) > 0 {
		opts[timeline.OptionToolFilter] = sources
	}
	if out != "" {
		opts[timeline.OptionCreateBodyfile] = true
		opts[tools.OptionOutputDir] = out
	}
	return opts
}

func run(stdout, stderr io.Writer, image string, flags cli.Flags, sources []string, out string) error {
	cfg := flags.Config()
	cfg.ToolOptions = options(sources, out)
	session, err := libvapour.OpenMemory(image, flags.OS, cfg)
	if err != nil {
		return err
	}
	defer session.Close()
	defer func() { cli.PrintDiagnostics(stderr, session.Diagnostics(), flags.Verbose) }()

	entries, err := timeline.Run(session.Context())
	if err != nil {
		return fmt.Errorf("%s: %w", timeline.Name, err)
	}
	cli.Heading(stdout, fmt.Sprintf("%d timed entries", len(entries)))
	printEntries(stdout, entries)
	if out != "" {
		fmt.Fprintf(stdout, "\nbody file written to %s as %s, or with a number added when that name was taken\n",
			cli.Text(out), timeline.BodyfileName)
	}
	return nil
}

func printEntries(w io.Writer, entries []timeline.Entry) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "Time\tEvent\tTool\tField\tSubject")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", cli.Time(e.Time, false), cli.Text(string(e.Event)), cli.Text(e.Tool),
			cli.Text(e.Field), cli.Text(e.Subject))
	}
	tw.Flush()
}
