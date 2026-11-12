package imagebanners

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
)

const Name = "any.image.find_banners"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find Linux version banners and Windows kernel PDB records in physical memory, and mark the running kernel's copy",
		},
		RunAny,
	)
}

var ErrNoPhysical = errors.New("imagebanners: session has no physical layer")

type Kind string

const (
	KindLinux      Kind = "linux"
	KindWindowsPDB Kind = "windows-pdb"
)

type Banner struct {
	Offset        uint64
	Kind          Kind
	Banner        string
	Release       string
	Version       string
	Terminated    bool
	RunningCopy   bool
	SameAsRunning bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Banner, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysical)
	}
	bounds := ctx.Bounds()
	run, err := runningCopy(ctx, uint64(bounds.MaxNameBytes))
	if err != nil {
		ctx.AddDiagnostic("%s: running kernel's banner not read: %v", Name, err)
	}

	maxText := int(bounds.MaxNameBytes)
	step := uint64(bounds.MaxBufferBytes)
	overlap := uint64(max(maxText, codeViewHead+maxPathBytes))
	perWindow := bounds.MaxMatchesPerChunk
	var out []Banner
	capped := 0
	coverage := memory.ScanWindows(physical, step, overlap, func(base uint64, window []byte) bool {
		if !scanWindow(base, window, step, maxText, perWindow, &out) {
			capped++
		}
		return false
	})
	if capped > 0 {
		ctx.AddDiagnostic("%s: %d windows held more than MaxMatchesPerChunk (%d) hits; the rest of each was not searched",
			Name, capped, perWindow)
	}
	if err := coverage.Incomplete(); err != nil {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		ctx.AddDiagnostic("%s: %v", Name, err)
	}

	slices.SortFunc(out, func(a, b Banner) int {
		switch {
		case a.Offset < b.Offset:
			return -1
		case a.Offset > b.Offset:
			return 1
		}
		return 0
	})
	for i := range out {
		out[i].RunningCopy = run.ok && out[i].Kind == run.kind && out[i].Offset == run.physical
		out[i].SameAsRunning = run.ok && out[i].Kind == run.kind && out[i].Banner == run.text
	}
	return out, nil
}

// A hit belongs to the window it starts in below the step; the overlap past
// the step only completes it. false when the window held more than cap hits.
func scanWindow(base uint64, window []byte, step uint64, maxText, cap int, out *[]Banner) bool {
	owned := int(min(uint64(len(window)), step))
	found := 0
	keep := func(at int, b Banner) bool {
		if found >= cap {
			return false
		}
		found++
		b.Offset = base + uint64(at)
		*out = append(*out, b)
		return true
	}
	for at := 0; at < owned; {
		i := bytes.Index(window[at:], linuxPrefix)
		if i < 0 || at+i >= owned {
			break
		}
		at += i
		if b, ok := parseLinuxBanner(window[at:], maxText); ok && !keep(at, b) {
			return false
		}
		at++
	}
	for at := 0; at < owned; {
		i := bytes.Index(window[at:], codeViewSignature)
		if i < 0 || at+i >= owned {
			break
		}
		at += i
		if b, ok := parseCodeView(window[at:]); ok && !keep(at, b) {
			return false
		}
		at++
	}
	return true
}

var linuxPrefix = []byte("Linux version ")

// UTS_RELEASE is at most 64 bytes (S47 B2).
const maxRelease = 64

func printable(c byte) bool { return c >= 0x20 && c <= 0x7e }

// S47 B1 and 4.2 step 4.
func parseLinuxBanner(b []byte, maxText int) (Banner, bool) {
	if !bytes.HasPrefix(b, linuxPrefix) {
		return Banner{}, false
	}
	rest := b[len(linuxPrefix):]
	n := 0
	for n < len(rest) && n <= maxRelease && rest[n] > 0x20 && rest[n] <= 0x7e {
		n++
	}
	if n == 0 || n > maxRelease || !bytes.HasPrefix(rest[n:], []byte(" (")) {
		return Banner{}, false
	}
	end, terminated := 0, false
	for end < len(b) && end < maxText {
		if b[end] == '\n' {
			terminated = true
			break
		}
		if !printable(b[end]) {
			break
		}
		end++
	}
	text := string(b[:end])
	banner := Banner{Kind: KindLinux, Banner: text, Release: string(rest[:n]), Terminated: terminated}
	if i := strings.LastIndex(text, ") #"); i >= 0 {
		banner.Version = text[i+2:]
	}
	return banner, true
}

var codeViewSignature = []byte("RSDS")

// "RSDS", the GUID and the age (S47 B6); a path of fewer than MAX_PATH bytes
// before its NUL (B8).
const (
	codeViewHead = 4 + 16 + 4
	maxPathBytes = 260
)

// S47 B7.
var kernelPDBNames = []string{"ntoskrnl.pdb", "ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb"}

func parseCodeView(b []byte) (Banner, bool) {
	fp, ok := codeViewFingerprint(b)
	if !ok {
		return Banner{}, false
	}
	return Banner{Kind: KindWindowsPDB, Banner: fp.String()}, true
}

func codeViewFingerprint(b []byte) (autoload.Fingerprint, bool) {
	if len(b) <= codeViewHead || !bytes.HasPrefix(b, codeViewSignature) {
		return autoload.Fingerprint{}, false
	}
	path := b[codeViewHead:min(len(b), codeViewHead+maxPathBytes)]
	end := bytes.IndexByte(path, 0)
	if end <= 0 {
		return autoload.Fingerprint{}, false
	}
	path = path[:end]
	name := string(path[bytes.LastIndexAny(path, `\/`)+1:])
	if !slices.ContainsFunc(kernelPDBNames, func(k string) bool { return strings.EqualFold(k, name) }) {
		return autoload.Fingerprint{}, false
	}
	return autoload.Fingerprint{PDBName: name, GUID: autoload.FormatGUID(b[4:20]),
		Age: binary.LittleEndian.Uint32(b[20:codeViewHead])}, true
}

type running struct {
	kind     Kind
	text     string
	physical uint64
	ok       bool
}

type translator interface {
	Translate(virtualAddress uint64) (uint64, error)
}

func runningCopy(ctx tools.Context, maxText uint64) (running, error) {
	tr, ok := ctx.Memory.(translator)
	if !ok {
		return running{}, errors.New("the kernel layer does not translate to physical addresses")
	}
	var r running
	var va uint64
	var err error
	switch strings.ToLower(ctx.Profile.OS()) {
	case "linux":
		r.kind = KindLinux
		va, r.text, err = runningLinuxBanner(ctx, maxText)
	case "windows":
		r.kind = KindWindowsPDB
		va, r.text, err = runningKernelRecord(ctx)
	default:
		return running{}, fmt.Errorf("profile os %q has no kernel banner", ctx.Profile.OS())
	}
	if err != nil {
		return running{}, err
	}
	if r.physical, err = tr.Translate(va); err != nil {
		return running{}, fmt.Errorf("0x%x does not translate: %w", va, err)
	}
	r.ok = true
	return r, nil
}

func runningLinuxBanner(ctx tools.Context, maxText uint64) (uint64, string, error) {
	sym, err := ctx.Symbols.LookupSymbol("linux_banner")
	if err != nil {
		return 0, "", err
	}
	var text []byte
	for at := sym.Address; uint64(len(text)) < maxText; {
		n := min(pageSize-at%pageSize, maxText-uint64(len(text)))
		b, err := ctx.Memory.ReadAt(at, n)
		if err != nil {
			return 0, "", fmt.Errorf("linux_banner at 0x%x: %w", sym.Address, err)
		}
		if i := bytes.IndexByte(b, 0); i >= 0 {
			text = append(text, b[:i]...)
			break
		}
		text = append(text, b...)
		at += n
	}
	return sym.Address, strings.TrimSuffix(string(text), "\n"), nil
}

const pageSize = uint64(0x1000)

// The record lies at the kernel's base plus AddressOfRawData (S47 B6).
func runningKernelRecord(ctx tools.Context) (uint64, string, error) {
	base, ok := ctx.KernelBase()
	if !ok {
		return 0, "", errors.New("no kernel base")
	}
	read := func(rva uint32, n int) ([]byte, error) { return ctx.Memory.ReadAt(base+uint64(rva), uint64(n)) }
	head, err := ctx.Memory.ReadAt(base, pageSize)
	if err != nil {
		return 0, "", fmt.Errorf("kernel header at 0x%x: %w", base, err)
	}
	h, err := pe.ParseHeaders(head)
	if err != nil {
		return 0, "", fmt.Errorf("kernel header at 0x%x: %w", base, err)
	}
	dir, err := h.DataDirectory(head, pe.DirectoryEntryDebug)
	if err != nil {
		return 0, "", fmt.Errorf("kernel at 0x%x: %w", base, err)
	}
	cv, err := pe.ReadCodeView(read, dir)
	if err != nil {
		return 0, "", fmt.Errorf("kernel at 0x%x: %w", base, err)
	}
	fp := autoload.Fingerprint{PDBName: cv.PDBName(), GUID: autoload.FormatGUID(cv.GUID[:]), Age: cv.Age}
	return base + uint64(cv.RVA), fp.String(), nil
}
