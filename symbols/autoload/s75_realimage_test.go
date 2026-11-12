//go:build realimage

package autoload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

// Each variable lists "expected=path" pairs separated by ';'.
func imageCases(t *testing.T, variable string) map[string]string {
	t.Helper()
	spec := strings.TrimSpace(os.Getenv(variable))
	if spec == "" {
		t.Skipf("set %s to \"expected=path;...\" to run against captures", variable)
	}
	out := map[string]string{}
	for _, field := range strings.Split(spec, ";") {
		if field = strings.TrimSpace(field); field == "" {
			continue
		}
		expect, path, ok := strings.Cut(field, "=")
		if !ok {
			t.Fatalf("%s entry %q is not \"expected=path\"", variable, field)
		}
		out[strings.TrimSpace(path)] = strings.TrimSpace(expect)
	}
	return out
}

func openCapture(t *testing.T, path string) memory.MemoryReader {
	t.Helper()
	file, err := memory.NewFileMemoryReader(path)
	if err != nil {
		t.Skipf("no capture %s: %v", path, err)
	}
	t.Cleanup(func() { _ = file.Close() })
	reader, _, err := memory.DetectFormat(file, memory.DefaultDetectors()...)
	if err != nil {
		t.Fatalf("detect format of %s: %v", path, err)
	}
	return reader
}

type headerless struct{ r memory.MemoryReader }

func (h headerless) ReadAt(offset, size uint64) ([]byte, error) { return h.r.ReadAt(offset, size) }
func (h headerless) Size() uint64                               { return h.r.Size() }

func TestTheRunningKernelIsIdentifiedOnCaptures(t *testing.T) {
	for path, want := range imageCases(t, "LIBVAPOUR_TEST_WINDOWS_IMAGES") {
		t.Run(filepath.Base(path), func(t *testing.T) {
			r := openCapture(t, path)
			id, err := IdentifyKernel(r, limits.Default())
			if err != nil || !strings.EqualFold(id.Fingerprint.String(), want) {
				t.Fatalf("IdentifyKernel = %+v (%v), want %s", id, err, want)
			}
			if id.Method == MethodScan {
				t.Errorf("identified only by the scan")
			}
			run, err := IdentifyRunningKernel(headerless{r}, limits.Default())
			if err != nil || run == nil || run.Fingerprint != id.Fingerprint || run.Base != id.Base {
				t.Errorf("without the crash dump header: %+v (%v)", run, err)
			}
		})
	}
}

func TestTheKernelBannerIsFoundOnCaptures(t *testing.T) {
	for path, want := range imageCases(t, "LIBVAPOUR_TEST_LINUX_IMAGES") {
		t.Run(filepath.Base(path), func(t *testing.T) {
			b, err := LinuxKernelBanner(openCapture(t, path), limits.Default())
			if err != nil || b.Release != want || !b.InKernelRodata {
				t.Errorf("LinuxKernelBanner = %+v (%v), want release %s", b, err, want)
			}
		})
	}
}
