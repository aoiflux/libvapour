package tools

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

func TestValidateChecksInOrder(t *testing.T) {
	full, _ := win10.context(nil)
	if err := full.Validate(); err != nil {
		t.Fatalf("complete context: %v", err)
	}
	cases := []struct {
		name   string
		break_ func(*Context)
		want   error
	}{
		{"memory", func(c *Context) { c.Memory, c.Symbols = nil, nil }, ErrMissingMemoryReader},
		{"symbols", func(c *Context) { c.Symbols, c.Profile = nil, nil }, ErrMissingSymbolTable},
		{"profile", func(c *Context) { c.Profile = nil }, ErrMissingProfile},
		{"options", func(c *Context) { c.Options = map[string]any{optionStrict: "maybe"} }, ErrOptionType},
	}
	for _, tc := range cases {
		c, _ := win10.context(nil)
		tc.break_(&c)
		if err := c.Validate(); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	c, _ := win10.context(nil)
	c.Limits = limits.Limits{MaxListEntries: -1}
	var le *limits.Error
	if err := c.Validate(); !errors.As(err, &le) {
		t.Errorf("limits: %v", err)
	}
	if c.Bounds() != limits.Default() {
		t.Error("limits that do not resolve must give the defaults")
	}
}

type tagged struct{ id int }

func (tagged) ReadAt(uint64, uint64) ([]byte, error) { return nil, errUnmapped }
func (tagged) Size() uint64                          { return 0 }

func TestProcessSpaceNeverFallsBackToTheKernel(t *testing.T) {
	kernelMem := tagged{1}
	if r, err := (Context{Memory: kernelMem}).ProcessSpace(0x1aa000); err != nil || r != memory.MemoryReader(kernelMem) {
		t.Errorf("no factory: %v %v, want the kernel reader", r, err)
	}
	proc := tagged{2}
	ok := Context{Memory: kernelMem, ProcessMemory: func(uint64) (memory.MemoryReader, error) { return proc, nil }}
	if r, err := ok.ProcessSpace(0x1aa000); err != nil || r != memory.MemoryReader(proc) {
		t.Errorf("factory: %v %v", r, err)
	}
	refusal := errors.New("root outside physical memory")
	for name, factory := range map[string]func(uint64) (memory.MemoryReader, error){
		"error":     func(uint64) (memory.MemoryReader, error) { return nil, refusal },
		"no reader": func(uint64) (memory.MemoryReader, error) { return nil, nil },
	} {
		r, err := Context{Memory: kernelMem, ProcessMemory: factory}.ProcessSpace(0x1aa000)
		if r != nil || !errors.Is(err, ErrProcessSpaceUnavailable) || !strings.Contains(err.Error(), "root 0x1aa000") {
			t.Errorf("%s: %v %v", name, r, err)
		}
		if name == "error" && !errors.Is(err, refusal) {
			t.Errorf("the factory's error is lost: %v", err)
		}
	}
}

func TestDiagnosticsGoToTheSinkOnly(t *testing.T) {
	Context{}.AddDiagnostic("dropped %d", 1)
	Context{Options: map[string]any{optionDiagnostics: "not a sink"}}.AddDiagnostic("dropped")
	var sink []string
	c := Context{Options: map[string]any{optionDiagnostics: &sink}}
	c.AddDiagnostic("a: %s", "b")
	c.WithoutPIDFilter().AddDiagnostic("c")
	if len(sink) != 2 || sink[0] != "a: b" || sink[1] != "c" {
		t.Errorf("sink %q", sink)
	}
}

func TestStrictModeIsTheSaferReading(t *testing.T) {
	for v, want := range map[any]bool{true: true, false: false, "on": true, "off": false, "maybe": true, 3: true} {
		if got := (Context{Options: map[string]any{optionStrict: v}}).StrictMode(); got != want {
			t.Errorf("strict %v: %v, want %v", v, got, want)
		}
	}
	if (Context{}).StrictMode() {
		t.Error("absent strict is strict")
	}
}

func TestWithoutPIDFilterCopiesTheOptions(t *testing.T) {
	options := map[string]any{optionPID: "4,8", "other": 1}
	c := Context{Options: options}
	relaxed := c.WithoutPIDFilter()
	if !relaxed.PIDs().All() || relaxed.Options["other"] != 1 {
		t.Errorf("relaxed options %v", relaxed.Options)
	}
	if c.PIDs().Key() != "4,8" || len(options) != 2 {
		t.Errorf("the original options changed: %v", options)
	}
	none := Context{Options: map[string]any{"other": 1}}
	if none.WithoutPIDFilter().Options["other"] != 1 {
		t.Error("a context with no filter must be unchanged")
	}
}

func TestKernelFramesNamesWhatIsMissing(t *testing.T) {
	cases := []struct {
		options map[string]any
		want    string
	}{
		{map[string]any{}, "no physical memory"},
		{map[string]any{OptionPhysicalMemory: pages{}}, "no kernel page-table root"},
		{map[string]any{OptionPhysicalMemory: pages{}, OptionKernelDTB: uint64(0x1aa000), OptionPagingMode: "none"}, `paging mode "none"`},
	}
	for _, tc := range cases {
		_, err := Context{Options: tc.options}.KernelFrames()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.options, err, tc.want)
		}
	}
}
