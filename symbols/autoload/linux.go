package autoload

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

// linux_banner is "Linux version <release> (...) ... <version>\n" in a char
// array, so its bytes end "\n\0". linux_proc_banner, the /proc/version
// template, is defined in the same file and starts "%s version %s (". The
// template sits at a 32-byte boundary on both measured kernels, so at most 31
// bytes of padding part it from the banner.
const (
	bannerPrefix     = "Linux version "
	procBannerPrefix = "%s version %s ("
	procBannerGap    = 31
	bannerScanStep   = 4 << 20
)

var (
	ErrNoLinuxBanner        = errors.New("autoload: no linux kernel banner")
	ErrLinuxBannerAmbiguous = errors.New("autoload: linux kernel banner is ambiguous")
)

// InKernelRodata is true when linux_proc_banner follows the banner, as it does
// where init/version.c's banner lies in the kernel's read-only data. From 6.1
// that copy is the weak definition compiled before the build's timestamp, so
// its Release is the running kernel's but its Raw is not the banner a symbol
// table is keyed on; ReadLinuxBanner reads that one at linux_banner.
type LinuxBanner struct {
	Raw            string
	Release        string
	Offset         uint64
	InKernelRodata bool
}

func (b LinuxBanner) String() string { return b.Raw }

func ScanLinuxBanners(r memory.MemoryReader, l limits.Limits) ([]LinuxBanner, error) {
	return scanLinuxBanners(r, bannerScanStep, int(l.Effective().MaxNameBytes))
}

// A window reaches past the next one's start by a whole banner, the gap and
// the template's prefix, so a banner that starts in a window is seen there
// whole, together with what follows it. Each banner is kept only by the window
// it starts in.
func scanLinuxBanners(r memory.MemoryReader, step, maxLen int) ([]LinuxBanner, error) {
	overlap := uint64(maxLen) + procBannerGap + uint64(len(procBannerPrefix))
	var out []LinuxBanner
	coverage := memory.ScanWindows(r, uint64(step), overlap, func(base uint64, window []byte) bool {
		owned := min(step, len(window))
		for from := 0; from < owned; {
			i := bytes.Index(window[from:], []byte(bannerPrefix))
			if i < 0 || from+i >= owned {
				break
			}
			start := from + i
			from = start + 1
			body, n, ok := bannerAt(window[start:], maxLen)
			if !ok {
				continue
			}
			release, ok := bannerRelease(body)
			if !ok {
				continue
			}
			after := window[start+n:]
			after = after[:min(len(after), procBannerGap+len(procBannerPrefix))]
			out = append(out, LinuxBanner{
				Raw:            body,
				Release:        release,
				Offset:         base + uint64(start),
				InKernelRodata: bytes.Contains(after, []byte(procBannerPrefix)),
			})
		}
		return false
	})
	if err := coverage.Incomplete(); err != nil && len(out) == 0 {
		return nil, fmt.Errorf("%w in the readable part of the %d-byte image: %w", ErrNoLinuxBanner, r.Size(), err)
	}
	return out, nil
}

// The text runs to "\n\0" within maxLen bytes and is printable ASCII before
// it: a log line or journal record holds the same words without the NUL, and
// a copy with binary spliced into it is not the kernel's string.
func bannerAt(b []byte, maxLen int) (body string, n int, ok bool) {
	for i := range min(len(b), maxLen) {
		switch c := b[i]; {
		case c == '\n':
			if i+1 < len(b) && b[i+1] == 0 {
				return string(b[:i]), i + 2, true
			}
			return "", 0, false
		case c < 0x20 || c > 0x7e:
			return "", 0, false
		}
	}
	return "", 0, false
}

// The release is the word after the prefix: a kernel release starts with the
// VERSION number and has a dot before the PATCHLEVEL.
func bannerRelease(body string) (string, bool) {
	rest, ok := strings.CutPrefix(body, bannerPrefix)
	if !ok {
		return "", false
	}
	release, _, _ := strings.Cut(rest, " ")
	if release == "" || release[0] < '0' || release[0] > '9' || !strings.Contains(release, ".") {
		return "", false
	}
	return release, true
}

func LinuxKernelBanner(r memory.MemoryReader, l limits.Limits) (LinuxBanner, error) {
	banners, err := ScanLinuxBanners(r, l)
	if err != nil {
		return LinuxBanner{}, err
	}
	var inRodata []LinuxBanner
	for _, b := range banners {
		if b.InKernelRodata {
			inRodata = append(inRodata, b)
		}
	}
	switch {
	case len(inRodata) == 1:
		return inRodata[0], nil
	case len(inRodata) > 1:
		return LinuxBanner{}, fmt.Errorf("%w: linux_proc_banner follows %d banners: %s", ErrLinuxBannerAmbiguous, len(inRodata), listBanners(inRodata))
	case len(banners) == 0:
		return LinuxBanner{}, fmt.Errorf("%w: none ends in \"\\n\\0\" in the %d-byte image", ErrNoLinuxBanner, r.Size())
	}
	return LinuxBanner{}, fmt.Errorf("%w: linux_proc_banner follows none of %d banners, which may be copies in logs or files: %s",
		ErrNoLinuxBanner, len(banners), listBanners(banners))
}

const listedBanners = 8

func listBanners(banners []LinuxBanner) string {
	var parts []string
	for i, b := range banners {
		if i == listedBanners {
			parts = append(parts, fmt.Sprintf("%d more", len(banners)-i))
			break
		}
		parts = append(parts, fmt.Sprintf("%s at 0x%x", b.Release, b.Offset))
	}
	return strings.Join(parts, ", ")
}

// The bytes returned run through the NUL, as a char array initialised from a
// string literal holds it and as a table's linux_banner constant stores it.
func ReadLinuxBanner(kernel memory.MemoryReader, address uint64, l limits.Limits) ([]byte, string, error) {
	const page = 4096
	maxLen := int(l.Effective().MaxNameBytes)
	want := uint64(maxLen) + 1
	if address > math.MaxUint64-want {
		return nil, "", fmt.Errorf("autoload: linux_banner at 0x%x: %d bytes would pass the end of the address space", address, want)
	}
	var buf []byte
	for uint64(len(buf)) < want && bytes.IndexByte(buf, 0) < 0 {
		at := address + uint64(len(buf))
		b, err := kernel.ReadAt(at, min(page-at%page, want-uint64(len(buf))))
		if err != nil {
			return nil, "", fmt.Errorf("autoload: linux_banner at 0x%x: read 0x%x: %w", address, at, err)
		}
		if len(b) == 0 {
			return nil, "", fmt.Errorf("autoload: linux_banner at 0x%x: empty read at 0x%x", address, at)
		}
		buf = append(buf, b...)
	}
	body, n, ok := bannerAt(buf, maxLen)
	if !ok {
		return nil, "", fmt.Errorf("%w: linux_banner at 0x%x is not printable text ending \"\\n\\0\" within MaxNameBytes (%d): %q",
			ErrNoLinuxBanner, address, maxLen, buf[:min(len(buf), 80)])
	}
	release, ok := bannerRelease(body)
	if !ok {
		return nil, "", fmt.Errorf("%w: linux_banner at 0x%x names no release: %q", ErrNoLinuxBanner, address, body)
	}
	return buf[:n], release, nil
}
