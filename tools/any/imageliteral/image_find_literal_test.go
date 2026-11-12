package imageliteral

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

type flat []byte

func (f flat) ReadAt(off, n uint64) ([]byte, error) {
	if off > uint64(len(f)) || n > uint64(len(f))-off {
		return nil, memory.ErrOutOfBounds
	}
	return f[off : off+n], nil
}

func (f flat) Size() uint64 { return uint64(len(f)) }

func context(physical memory.MemoryReader, opts map[string]any) (tools.Context, *[]string) {
	diags := &[]string{}
	if opts == nil {
		opts = map[string]any{}
	}
	opts["diagnostics"] = diags
	if physical != nil {
		opts[tools.OptionPhysicalMemory] = physical
	}
	return tools.Context{Memory: flat{}, Symbols: symbols.NewTable("t", 8), Profile: profiles.LinuxX64Profile{},
		Options: opts}, diags
}

func image(size int, at map[int]string) flat {
	b := make(flat, size)
	for off, s := range at {
		copy(b[off:], s)
	}
	return b
}

type hit struct {
	lit string
	at  uint64
}

func hits(rows []Finding) []hit {
	out := make([]hit, len(rows))
	for i, r := range rows {
		out[i] = hit{r.Literal, r.Offset}
	}
	return out
}

func TestLiteralsAreFoundInOffsetOrder(t *testing.T) {
	img := image(0x3000, map[int]string{0x100: "evil.exe", 0x200: "EVIL.EXE", 0x2000: "aaaa"})
	ctx, _ := context(img, map[string]any{OptionLiterals: []string{"evil.exe", "aa", "evil.exe"}})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []hit{{"evil.exe", 0x100}, {"aa", 0x2000}, {"aa", 0x2001}, {"aa", 0x2002}}
	if got := hits(rows); !slices.Equal(got, want) {
		t.Fatalf("hits %v, want %v", got, want)
	}
	if rows[0].Length != 8 || !strings.HasPrefix(rows[0].Preview, "evil.exe....") || len(rows[0].Preview) != 128 {
		t.Errorf("first row %+v", rows[0])
	}
}

func TestCaseFoldingIsASCIIOnly(t *testing.T) {
	img := image(0x1000, map[int]string{0x10: "EVIL.exe", 0x40: "evil.EXE", 0x80: "\xc9vil.exe"})
	ctx, _ := context(img, map[string]any{OptionLiterals: []string{"Evil.Exe", "\xe9vil.exe"}, OptionCaseInsensitive: true})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []hit{{"Evil.Exe", 0x10}, {"Evil.Exe", 0x40}}
	if got := hits(rows); !slices.Equal(got, want) {
		t.Fatalf("hits %v, want %v", got, want)
	}
	if !strings.HasPrefix(rows[0].Preview, "EVIL.exe") {
		t.Errorf("the preview is not the image's bytes: %q", rows[0].Preview)
	}
}

func TestAMatchAcrossAWindowBoundaryIsFoundOnce(t *testing.T) {
	img := image(3<<20, map[int]string{1<<20 - 3: "boundary", 2 << 20: "boundary"})
	ctx, _ := context(img, map[string]any{OptionLiterals: []string{"boundary"}})
	ctx.Limits = limits.Limits{MaxBufferBytes: 1 << 20}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hits(rows), []hit{{"boundary", 1<<20 - 3}, {"boundary", 2 << 20}}; !slices.Equal(got, want) {
		t.Fatalf("hits %v, want %v", got, want)
	}
}

func TestTheScanLimitCutsAMatchThatEndsPastIt(t *testing.T) {
	img := image(0x1000, map[int]string{0x10: "first", 0xfe: "second"})
	ctx, _ := context(img, map[string]any{OptionLiterals: []string{"first", "second"}, OptionMaxScanBytes: uint64(0x100)})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hits(rows), []hit{{"first", 0x10}}; !slices.Equal(got, want) {
		t.Fatalf("hits %v, want %v", got, want)
	}
}

func TestSegmentsAreSearchedAtTheirPhysicalAddresses(t *testing.T) {
	backing := image(0x2000, map[int]string{0x10: "one", 0x1ffd: "two"})
	r, err := memory.NewSegmentedReader(backing, []memory.Segment{
		{PhysicalBase: 0x100000, FileOffset: 0, Length: 0x1000},
		{PhysicalBase: 0x300000, FileOffset: 0x1000, Length: 0x1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := context(r, map[string]any{OptionLiterals: []string{"one", "two"}})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hits(rows), []hit{{"one", 0x100010}, {"two", 0x300ffd}}; !slices.Equal(got, want) {
		t.Fatalf("hits %v, want %v", got, want)
	}
	if rows[1].Preview != "two" {
		t.Errorf("preview at the end of a segment %q", rows[1].Preview)
	}
}

func TestAWindowFullOfMatchesIsCut(t *testing.T) {
	ctx, diags := context(image(0x100, map[int]string{0: strings.Repeat("x", 0x100)}),
		map[string]any{OptionLiterals: []string{"x"}})
	ctx.Limits = limits.Limits{MaxMatchesPerChunk: 10}
	rows, err := Run(ctx)
	if err != nil || len(rows) != 10 || len(*diags) != 1 || !strings.Contains((*diags)[0], "MaxMatchesPerChunk (10)") {
		t.Fatalf("rows %d err %v diags %q", len(rows), err, *diags)
	}
}

type broken struct{ flat }

func (broken) ReadAt(uint64, uint64) ([]byte, error) { return nil, memory.ErrOutOfBounds }

func TestUnreadableMemoryIsSaidOrFailsWhenStrict(t *testing.T) {
	ctx, diags := context(broken{image(0x1000, nil)}, map[string]any{OptionLiterals: []string{"x"}})
	if _, err := Run(ctx); err != nil || len(*diags) != 1 {
		t.Fatalf("err %v diags %q", err, *diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Fatal("strict mode passed over unreadable memory")
	}
}

func TestOptionsAreChecked(t *testing.T) {
	img := image(0x100, nil)
	for _, opts := range []map[string]any{
		{OptionLiterals: 5},
		{OptionLiterals: []string{strings.Repeat("a", 4097)}},
		{OptionLiterals: []string{"a"}, OptionMaxScanBytes: -1},
		{OptionLiterals: []string{"a"}, OptionCaseInsensitive: "x"},
	} {
		ctx, _ := context(img, opts)
		if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
			t.Errorf("%v: %v", opts, err)
		}
	}
	ctx, diags := context(img, nil)
	if rows, err := Run(ctx); err != nil || len(rows) != 0 || len(*diags) != 1 {
		t.Errorf("no literals: rows %v err %v diags %q", rows, err, *diags)
	}
	ctx, _ = context(nil, map[string]any{OptionLiterals: []string{"a"}})
	if _, err := Run(ctx); !errors.Is(err, ErrNoPhysical) {
		t.Errorf("no physical layer: %v", err)
	}
}

func TestTheToolIsRegisteredAsAPlaceholder(t *testing.T) {
	tool, err := tools.Get(Name)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tool.Spec.Description, "Placeholder: ") {
		t.Errorf("description %q", tool.Spec.Description)
	}
}
