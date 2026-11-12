package tools

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aoiflux/libvapour/memory"
)

const (
	optionPID         = "pid"
	optionStrict      = "strict"
	optionDiagnostics = "diagnostics"

	// No default: a tool that writes files and has no directory fails
	// instead of choosing a place on the examiner's disk.
	OptionOutputDir         = "output_dir"
	OptionMaxDumpSize       = "max_dump_size"
	OptionPhysicalMemory    = "physical_memory"
	OptionKernelBase        = "kernel_base"
	OptionKernelDTB         = "kernel_dtb"
	OptionPagingMode        = "paging_mode"
	OptionNetworkScanLayout = "windows.network.scan.layout"
)

// Unknown keys are not errors: every tool reads the same map.
var ErrOptionType = errors.New("tools: option value of the wrong form")

func wrongForm(key string, v any, want string) error {
	return fmt.Errorf("%w: %q is %s; want %s", ErrOptionType, key, describeValue(v), want)
}

func describeValue(v any) string {
	switch x := v.(type) {
	case nil:
		return "nil"
	case string:
		return strconv.Quote(x)
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, uintptr, float32, float64:
		return fmt.Sprintf("%T %v", x, x)
	}
	return fmt.Sprintf("a value of type %T", v)
}

const (
	boolForms = "a bool, or text reading true, 1, yes, on, false, 0, no or off"
	uintForms = "an integer of 0 or more, or text in decimal or 0x hexadecimal"
)

func (c Context) BoolOption(key string) (bool, error) {
	v, ok := c.Options[key]
	if !ok {
		return false, nil
	}
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true", "1", "yes", "on":
			return true, nil
		case "false", "0", "no", "off":
			return false, nil
		}
	}
	return false, wrongForm(key, v, boolForms)
}

func (c Context) UintOption(key string) (uint64, bool, error) {
	v, ok := c.Options[key]
	if !ok {
		return 0, false, nil
	}
	n, ok := toUint(v)
	if !ok {
		return 0, true, wrongForm(key, v, uintForms)
	}
	return n, true, nil
}

func toUint(v any) (uint64, bool) {
	var signed int64
	switch x := v.(type) {
	case uint:
		return uint64(x), true
	case uint8:
		return uint64(x), true
	case uint16:
		return uint64(x), true
	case uint32:
		return uint64(x), true
	case uint64:
		return x, true
	case uintptr:
		return uint64(x), true
	case int:
		signed = int64(x)
	case int8:
		signed = int64(x)
	case int16:
		signed = int64(x)
	case int32:
		signed = int64(x)
	case int64:
		signed = x
	case string:
		return parseUintText(x)
	default:
		return 0, false
	}
	return uint64(signed), signed >= 0
}

// Base 0 would read a leading 0 as octal, so 010 would not be ten.
func parseUintText(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	base := 10
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s, base = s[2:], 16
	}
	if s == "" || s[0] == '+' || s[0] == '-' {
		return 0, false
	}
	n, err := strconv.ParseUint(s, base, 64)
	return n, err == nil
}

func (c Context) StringOption(key string) (string, error) {
	v, ok := c.Options[key]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", wrongForm(key, v, "text")
	}
	return s, nil
}

func (c Context) StringListOption(key string) ([]string, error) {
	v, ok := c.Options[key]
	if !ok {
		return nil, nil
	}
	var raw []string
	switch x := v.(type) {
	case []string:
		raw = x
	case string:
		raw = strings.Split(x, ",")
	default:
		return nil, wrongForm(key, v, "a []string, or text of items separated by commas")
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out, nil
}

const uintListForms = "a []uint64, a []int of numbers 0 or more, or text of such numbers separated by commas"

func (c Context) UintListOption(key string) ([]uint64, error) {
	v, ok := c.Options[key]
	if !ok {
		return nil, nil
	}
	switch x := v.(type) {
	case []uint64:
		return append([]uint64(nil), x...), nil
	case []int:
		out := make([]uint64, len(x))
		for i, n := range x {
			if n < 0 {
				return nil, wrongForm(key, v, uintListForms)
			}
			out[i] = uint64(n)
		}
		return out, nil
	case string:
		var out []uint64
		for _, item := range strings.Split(x, ",") {
			if strings.TrimSpace(item) == "" {
				continue
			}
			n, ok := parseUintText(item)
			if !ok {
				return nil, wrongForm(key, v, uintListForms)
			}
			out = append(out, n)
		}
		return out, nil
	}
	return nil, wrongForm(key, v, uintListForms)
}

func (c Context) ValidateOptions() error {
	var errs []error
	keep := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	_, err := c.pidSet()
	keep(err)
	_, err = c.BoolOption(optionStrict)
	keep(err)
	for _, key := range []string{OptionMaxDumpSize, OptionKernelBase, OptionKernelDTB} {
		_, _, err := c.UintOption(key)
		keep(err)
	}
	for _, key := range []string{OptionOutputDir, OptionPagingMode, OptionNetworkScanLayout} {
		_, err := c.StringOption(key)
		keep(err)
	}
	if v, ok := c.Options[OptionPhysicalMemory]; ok {
		if _, ok := v.(memory.MemoryReader); !ok {
			keep(wrongForm(OptionPhysicalMemory, v, "a memory.MemoryReader"))
		}
	}
	if v, ok := c.Options[optionDiagnostics]; ok {
		if _, ok := v.(*[]string); !ok {
			keep(wrongForm(optionDiagnostics, v, "a *[]string"))
		}
	}
	return errors.Join(errs...)
}

func (c Context) OutputDir() (string, bool) {
	s, err := c.StringOption(OptionOutputDir)
	return s, err == nil && s != ""
}

func (c Context) MaxDumpSize() uint64 {
	n, _, err := c.UintOption(OptionMaxDumpSize)
	if err != nil {
		return 0
	}
	return n
}

func (c Context) DumpLimit() uint64 {
	ceiling := uint64(c.Bounds().MaxArtifactBytes)
	if n := c.MaxDumpSize(); n > 0 && n < ceiling {
		return n
	}
	return ceiling
}

func (c Context) PhysicalMemory() memory.MemoryReader {
	r, _ := c.Options[OptionPhysicalMemory].(memory.MemoryReader)
	return r
}

func (c Context) KernelBase() (uint64, bool) { return c.presentUint(OptionKernelBase) }

func (c Context) KernelDTB() (uint64, bool) { return c.presentUint(OptionKernelDTB) }

func (c Context) presentUint(key string) (uint64, bool) {
	n, ok, err := c.UintOption(key)
	return n, ok && err == nil
}

func (c Context) PagingMode() string { return c.textOrEmpty(OptionPagingMode) }

func (c Context) NetworkScanLayout() string { return c.textOrEmpty(OptionNetworkScanLayout) }

func (c Context) textOrEmpty(key string) string {
	s, _ := c.StringOption(key)
	return s
}
