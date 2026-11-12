package cli

import (
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"text/tabwriter"

	libvapour "github.com/aoiflux/libvapour"
	"github.com/aoiflux/libvapour/tools"
)

type Flags struct {
	OS      string
	Symbols string
	CR3     uint64
	Offline bool
	Strict  bool
	Verbose bool
}

func (f *Flags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.OS, "os", "windows", "the image's operating system: windows or linux")
	fs.StringVar(&f.Symbols, "symbols", "", "an uncompressed .vsym symbol table for the running kernel, used instead of\n"+
		"the one found by default (symbol server or cache on windows, the image itself on linux)")
	fs.Uint64Var(&f.CR3, "cr3", 0, "the kernel's page-table root; the session finds it, and a different value fails the open (hex such as 0x1aa000 is accepted)")
	fs.BoolVar(&f.Offline, "offline", false, "windows only: never download symbols; use the cache or -symbols")
	fs.BoolVar(&f.Strict, "strict", false, "fail where a tool that honours strict mode would only report a diagnostic")
	fs.BoolVar(&f.Verbose, "verbose", false, "print every diagnostic after the tables")
}

// Diagnostics are the only sign that a table is partial, so they are always
// collected; -verbose decides whether they print.
func (f Flags) Config() libvapour.OpenConfig {
	return libvapour.OpenConfig{
		SymbolsPath:        f.Symbols,
		KernelCR3:          f.CR3,
		OfflineOnly:        f.Offline,
		Strict:             f.Strict,
		CollectDiagnostics: true,
	}
}

func (f Flags) Windows() bool { return strings.EqualFold(strings.TrimSpace(f.OS), "windows") }

func Image(fs *flag.FlagSet) (string, error) {
	if fs.NArg() != 1 {
		return "", fmt.Errorf("want one image path after the flags, got %d arguments", fs.NArg())
	}
	return fs.Arg(0), nil
}

// A bad command line ends the program with the usage text and exit status 2,
// so a script can tell it from a failed analysis.
func Parse(synopsis string) string {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s\n\nflags come before the image:\n\n", synopsis)
		flag.PrintDefaults()
	}
	flag.Parse()
	image, err := Image(flag.CommandLine)
	if err != nil {
		UsageError(err)
	}
	return image
}

func UsageError(err error) {
	fmt.Fprintln(flag.CommandLine.Output(), err)
	flag.Usage()
	os.Exit(2)
}

// A copy, because the session's option map is shared by every tool run in it.
func WithOptions(ctx tools.Context, options map[string]any) tools.Context {
	merged := maps.Clone(ctx.Options)
	if merged == nil {
		merged = make(map[string]any, len(options))
	}
	maps.Copy(merged, options)
	ctx.Options = merged
	return ctx
}

func NewTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
}

func Heading(w io.Writer, title string) {
	fmt.Fprintf(w, "\n== %s\n", title)
}

// A quiet run still gives the count, so a partial table never passes for a
// whole one. A diagnostic can quote image bytes, hence Text.
func PrintDiagnostics(w io.Writer, diagnostics []string, verbose bool) {
	if !verbose {
		if n := len(diagnostics); n > 0 {
			fmt.Fprintf(w, "warning: %d diagnostic(s) not shown, so a table may be partial; -verbose lists them\n", n)
		}
		return
	}
	for _, d := range diagnostics {
		fmt.Fprintf(w, "warning: %s\n", Text(d))
	}
}
