package syscallstub

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/windows/pesymbols"
)

const Name = "windows.syscall.compare_stubs"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Compare the system-call stubs of ntdll and win32u across processes",
		},
		RunAny,
	)
}

// The widest stub measured is 0x20 bytes with its padding (S29 M2).
const stubWindow = 0x20

// KUSER_SHARED_DATA is mapped at this user address in every measured process
// (S29 M4); the kernel address is S03's.
const userSharedData = uint64(0x7FFE0000)

type Form string

const (
	FormSyscall Form = "syscall"
	FormX86Call Form = "x86_call"
	FormJump    Form = "jump"
	FormOther   Form = "other"
	FormUnread  Form = "unread"
)

func IsStubName(name string) bool {
	return strings.HasPrefix(name, "Nt") || strings.HasPrefix(name, "Zw")
}

func stubModule(path string) bool {
	base := strings.ToLower(path[strings.LastIndexAny(path, `\/`)+1:])
	return base == "ntdll.dll" || base == "win32u.dll"
}

type Row struct {
	Module    string
	Function  string
	Aliases   []string
	RVA       uint32
	Address   uint64
	Form      Form
	Number    uint32
	Processes int
	Unread    int
	Variants  int
	Agreeing  int
	Differing []string
	Tie       bool
}

func (r Row) DifferingText() string { return strings.Join(r.Differing, ", ") }

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	mappings, err := memoryranges.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process memory ranges: %w", Name, err)
	}
	return compare(ctx, stubImages(mappings), liveImages{ctx})
}

type image struct {
	pid      uint64
	process  string
	dtb      uint64
	path     string
	base     uint64
	size     uint64
	sequence int
}

func (im image) label() string { return fmt.Sprintf("%s (%d)", im.process, im.pid) }

func stubImages(mappings []memoryranges.Mapping) []image {
	var out []image
	for _, m := range mappings {
		if m.Type != memoryranges.KindImage || m.Path == "" || !stubModule(m.Path) || m.End < m.Start {
			continue
		}
		out = append(out, image{pid: m.PID, process: m.Process, dtb: m.DirectoryTableBase, path: m.Path,
			base: m.Start, size: m.End - m.Start + 1, sequence: len(out)})
	}
	return out
}

type imageSource interface {
	exports(im image) ([]pe.Export, error)
	read(im image, address, n uint64) ([]byte, error)
	systemCallOffset() (uint64, bool)
}

type liveImages struct{ ctx tools.Context }

func (l liveImages) exports(im image) ([]pe.Export, error) {
	return pesymbols.Exports(l.ctx, pesymbols.Module{PID: im.pid, ProcessName: im.process,
		DirectoryTableBase: im.dtb, Name: im.path, Base: im.base, Size: im.size})
}

func (l liveImages) read(im image, address, n uint64) ([]byte, error) {
	space, err := l.ctx.ProcessSpace(im.dtb)
	if err != nil {
		return nil, err
	}
	b, err := space.ReadAt(address, n)
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) < n {
		return nil, fmt.Errorf("read 0x%x bytes, got 0x%x", n, len(b))
	}
	return b, nil
}

func (l liveImages) systemCallOffset() (uint64, bool) {
	f, err := l.ctx.Symbols.Field("_KUSER_SHARED_DATA", "SystemCall")
	if err != nil {
		return 0, false
	}
	return f.Offset, true
}

type stubKey struct {
	module string
	rva    uint32
}

type stubNames struct {
	names []string
}

type sighting struct {
	im    image
	bytes []byte
}

func compare(ctx tools.Context, images []image, src imageSource) ([]Row, error) {
	tests := testTemplates(src)
	// One file has one export table, but a page of its names can be absent in
	// one process and resident in another, so the tables of every instance are
	// merged by name.
	exportsByModule := map[string][]pe.Export{}
	known := map[string]map[string]bool{}
	failures := map[string]error{}
	var order []image
	for _, im := range images {
		key := strings.ToLower(im.path)
		if known[key] == nil {
			known[key] = map[string]bool{}
			order = append(order, im)
		}
		exports, err := src.exports(im)
		if err != nil {
			failures[key] = err
			continue
		}
		for _, e := range exports {
			if e.Name == "" || known[key][e.Name] {
				continue
			}
			known[key][e.Name] = true
			exportsByModule[key] = append(exportsByModule[key], e)
		}
	}
	for _, im := range order {
		key := strings.ToLower(im.path)
		if _, ok := exportsByModule[key]; !ok && failures[key] != nil {
			ctx.AddDiagnostic("%s: %s at 0x%x: export table not read in any process: %v", Name, im.path, im.base,
				failures[key])
		}
	}

	names := map[stubKey]*stubNames{}
	for module, exports := range exportsByModule {
		for _, e := range exports {
			if e.Forwarder != "" || e.ForwarderUnreadable || !IsStubName(e.Name) {
				continue
			}
			k := stubKey{module, e.RVA}
			if names[k] == nil {
				names[k] = &stubNames{}
			}
			names[k].names = append(names[k].names, e.Name)
		}
	}

	window := stubWindows(names)
	seen := map[stubKey][]sighting{}
	unread := map[stubKey]int{}
	display := map[string]string{}
	for _, im := range images {
		module := strings.ToLower(im.path)
		if _, ok := display[module]; !ok {
			display[module] = im.path
		}
		for k := range names {
			if k.module != module {
				continue
			}
			if uint64(k.rva)+window[k] > im.size {
				unread[k]++
				continue
			}
			b, err := src.read(im, im.base+uint64(k.rva), window[k])
			if err != nil {
				unread[k]++
				continue
			}
			seen[k] = append(seen[k], sighting{im, b})
		}
	}

	rows := make([]Row, 0, len(names))
	for k, n := range names {
		rows = append(rows, summarise(k, n.names, seen[k], unread[k], display[k.module], tests))
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := strings.ToLower(rows[i].Module), strings.ToLower(rows[j].Module)
		if a != b {
			return a < b
		}
		return rows[i].Function < rows[j].Function
	})
	return rows, nil
}

// A stub ends where the next exported stub starts: 0x10 bytes apart in the
// 32-bit images, 0x20 in the 64-bit ones (S29 M2). Reading past that would
// compare the next stub's bytes too.
func stubWindows(names map[stubKey]*stubNames) map[stubKey]uint64 {
	byModule := map[string][]uint32{}
	for k := range names {
		byModule[k.module] = append(byModule[k.module], k.rva)
	}
	out := make(map[stubKey]uint64, len(names))
	for module, rvas := range byModule {
		sort.Slice(rvas, func(i, j int) bool { return rvas[i] < rvas[j] })
		for i, rva := range rvas {
			w := uint64(stubWindow)
			if i+1 < len(rvas) {
				w = min(w, uint64(rvas[i+1]-rva))
			}
			out[stubKey{module, rva}] = w
		}
	}
	return out
}

func preferredName(names []string) (string, []string) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	first := 0
	for i, n := range sorted {
		if strings.HasPrefix(n, "Nt") {
			first = i
			break
		}
	}
	main := sorted[first]
	aliases := append(append([]string(nil), sorted[:first]...), sorted[first+1:]...)
	return main, aliases
}

func summarise(k stubKey, names []string, seen []sighting, unread int, module string, tests [][]byte) Row {
	fn, aliases := preferredName(names)
	r := Row{Module: module, Function: fn, Aliases: aliases, RVA: k.rva, Processes: len(seen), Unread: unread,
		Form: FormUnread}
	if len(seen) == 0 {
		return r
	}
	type group struct {
		bytes   []byte
		members []image
	}
	var groups []*group
	for _, s := range seen {
		var g *group
		for _, cand := range groups {
			if bytes.Equal(cand.bytes, s.bytes) {
				g = cand
				break
			}
		}
		if g == nil {
			g = &group{bytes: s.bytes}
			groups = append(groups, g)
		}
		g.members = append(g.members, s.im)
	}
	// Largest first; among equals the group whose first member came first in
	// the process listing, so the order does not depend on map iteration.
	sort.SliceStable(groups, func(i, j int) bool {
		if len(groups[i].members) != len(groups[j].members) {
			return len(groups[i].members) > len(groups[j].members)
		}
		return groups[i].members[0].sequence < groups[j].members[0].sequence
	})
	r.Variants = len(groups)
	r.Agreeing = len(groups[0].members)
	r.Address = groups[0].members[0].base + uint64(k.rva)
	r.Form, r.Number = classify(groups[0].bytes, tests)
	if len(groups) > 1 && len(groups[1].members) == r.Agreeing {
		r.Tie = true
		return r
	}
	for _, g := range groups[1:] {
		for _, m := range g.members {
			r.Differing = append(r.Differing, m.label())
		}
	}
	return r
}

// The two x64 tails measured after `mov r10, rcx; mov eax, imm32` (S29 M3):
// the SystemCall test that picks SYSCALL or INT 2E, and a bare SYSCALL.
func testTemplates(src imageSource) [][]byte {
	out := [][]byte{{0x0F, 0x05, 0xC3}}
	if off, ok := src.systemCallOffset(); ok {
		t := []byte{0xF6, 0x04, 0x25, 0, 0, 0, 0, 0x01, 0x75, 0x03, 0x0F, 0x05, 0xC3, 0xCD, 0x2E, 0xC3}
		binary.LittleEndian.PutUint32(t[3:], uint32(userSharedData+off))
		out = append(out, t)
	}
	return out
}

func classify(b []byte, tails [][]byte) (Form, uint32) {
	if len(b) >= 8 && b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
		number := binary.LittleEndian.Uint32(b[4:])
		for _, tail := range tails {
			if bytes.HasPrefix(b[8:], tail) {
				return FormSyscall, number
			}
		}
	}
	if len(b) >= 12 && b[0] == 0xB8 && b[5] == 0xBA && b[10] == 0xFF && b[11] == 0xD2 {
		return FormX86Call, binary.LittleEndian.Uint32(b[1:])
	}
	if len(b) >= 2 && (b[0] == 0xE9 || b[0] == 0xEB || (b[0] == 0xFF && b[1] == 0x25)) {
		return FormJump, 0
	}
	return FormOther, 0
}
