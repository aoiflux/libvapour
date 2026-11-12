package libvapour

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

func TestOneSpacePerRootFrame(t *testing.T) {
	c := newWinCapture()
	phys := &memoryBuffer{c.buf}
	built := 0
	cache := newSpaceCache(phys, func(root uint64) memory.MemoryReader {
		built++
		return windowsSpaceBuilder(phys, layers.ModeX64, 16, nil)(root)
	})
	a, err := cache.get(c.root)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := cache.get(c.root | 0xabc)
	other, _ := cache.get(c.root + fxPage)
	if a != b || a == other || built != 2 {
		t.Errorf("same frame shared %v, other frame distinct %v, built %d", a == b, a != other, built)
	}
	for _, root := range []uint64{0, 0xfff, uint64(len(c.buf)), uint64(len(c.buf)) + fxPage} {
		if _, err := cache.get(root); err == nil {
			t.Errorf("root 0x%x accepted", root)
		}
	}
}

type memoryBuffer struct{ b []byte }

func (m *memoryBuffer) ReadAt(off, size uint64) ([]byte, error) {
	if off > uint64(len(m.b)) || size > uint64(len(m.b))-off {
		return nil, memory.ErrOutOfBounds
	}
	return append([]byte(nil), m.b[off:off+size]...), nil
}

func (m *memoryBuffer) Size() uint64 { return uint64(len(m.b)) }

func TestPagefileNumbersFollowTheirPlaceInTheList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pagefile.sys")
	if err := os.WriteFile(path, make([]byte, fxPage), 0o600); err != nil {
		t.Fatal(err)
	}
	files, closers, err := openPagefiles([]string{"", path})
	if err != nil || len(files) != 1 || files[1] == nil || len(closers) != 1 {
		t.Fatalf("files %v, %v", files, err)
	}
	if err := closeAll(closers); err != nil {
		t.Error(err)
	}
	if files, _, err := openPagefiles([]string{""}); files != nil || err != nil {
		t.Errorf("no paths: %v, %v", files, err)
	}
	if _, _, err := openPagefiles([]string{path, path + ".absent"}); err == nil || !strings.Contains(err.Error(), "pagefile 1") {
		t.Errorf("absent file: %v", err)
	}
}

func lookupTable(t *testing.T, d symbols.Declaration) *symbols.Table {
	t.Helper()
	table, err := symbols.Build("s76", d)
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func names(syms []symbols.Symbol) []string {
	out := make([]string, len(syms))
	for i, s := range syms {
		out[i] = fmt.Sprintf("%s@%#x", s.Name, s.Address)
	}
	slices.Sort(out)
	return out
}

func TestAMovedTableAnswersBothWaysAlike(t *testing.T) {
	inner := lookupTable(t, symbols.Declaration{PointerWidth: 8, Addresses: []symbols.Address{
		{Name: "rva", Address: 0x2000}, {Name: "fixed", Address: 0xfffff80000002000},
	}})
	const shift = 0xfffff80000000000
	m := movedTable{inner: inner, shift: shift, moves: isRVA}
	if s, _ := m.LookupSymbol("rva"); s.Address != shift+0x2000 {
		t.Errorf("rva at %#x", s.Address)
	}
	if s, _ := m.LookupSymbol("fixed"); s.Address != 0xfffff80000002000 {
		t.Errorf("fixed at %#x", s.Address)
	}
	got := names(m.SymbolsAt(shift + 0x2000))
	if !slices.Equal(got, []string{"fixed@0xfffff80000002000", "rva@0xfffff80000002000"}) {
		t.Errorf("SymbolsAt = %q", got)
	}
	if got := m.SymbolsAt(0x2000); len(got) != 0 {
		t.Errorf("an RVA still names a moved symbol: %v", got)
	}
	if got := names(m.TableSymbols()); !slices.Contains(got, "rva@0x2000") {
		t.Errorf("listing left its own space: %q", got)
	}
	if !slices.Contains(m.SymbolNames(), "rva") {
		t.Error("names not forwarded")
	}
	if _, err := m.LookupSymbol("absent"); err == nil {
		t.Error("absent symbol found")
	}
}

func TestALayeredTableAddsTypesNotSymbols(t *testing.T) {
	u32 := symbols.TypeRef{Name: "unsigned int"}
	kernel := lookupTable(t, symbols.Declaration{PointerWidth: 8,
		Records:   []symbols.Record{{Name: "shared", Width: 8, Members: []symbols.Member{{Name: "a", Offset: 4, Type: u32}}}},
		Addresses: []symbols.Address{{Name: "k", Address: 0x10}}})
	extra := lookupTable(t, symbols.Declaration{PointerWidth: 8,
		Records: []symbols.Record{
			{Name: "shared", Width: 16, Members: []symbols.Member{{Name: "a", Offset: 12, Type: u32}}},
			{Name: "own", Width: 8, Members: []symbols.Member{{Name: "b", Offset: 2, Type: u32}}}},
		Addresses: []symbols.Address{{Name: "x", Address: 0x20}}})
	l := layeredTable{kernel: kernel, extra: extra}
	if f, _ := l.Field("shared", "a"); f.Offset != 4 {
		t.Errorf("kernel type overridden: %d", f.Offset)
	}
	if off, _ := l.OffsetOf("own", "b"); off != 2 {
		t.Errorf("extra type offset %d", off)
	}
	if size, err := l.FieldSize("own", "b"); err != nil || size != 4 {
		t.Errorf("extra member size %d, %v", size, err)
	}
	if size, _ := l.SizeOf("shared"); size != 8 {
		t.Errorf("shared size %d", size)
	}
	if _, err := l.LookupSymbol("x"); err == nil {
		t.Error("symbol answered from the extra table")
	}
	if _, err := l.OffsetOf("absent", "a"); err == nil {
		t.Error("absent type answered")
	}
	if s, _ := l.LookupSymbol("k"); s.Address != 0x10 {
		t.Errorf("kernel symbol %#x", s.Address)
	}
}

// One page per address: the image header at a base, nothing elsewhere.
type pages map[uint64][]byte

func (p pages) ReadAt(off, size uint64) ([]byte, error) {
	page, ok := p[off&^(fxPage-1)]
	if !ok || off%fxPage+size > fxPage {
		return nil, layers.ErrPageInvalid
	}
	return append([]byte(nil), page[off%fxPage:off%fxPage+size]...), nil
}

func (p pages) Size() uint64 { return 1 << 48 }

func at(address uint64) baseCandidate {
	return baseCandidate{from: fmt.Sprintf("candidate %#x", address), find: func() (uint64, error) { return address, nil }}
}

func failing(why string) baseCandidate {
	return baseCandidate{from: why, find: func() (uint64, error) { return 0, errors.New(why) }}
}

func TestTheFirstBaseNamingTheLoadedBuildIsTaken(t *testing.T) {
	const a, b, c = 0xfffff80000100000, 0xfffff80000200000, 0xfffff80000300000
	other := fxGUID
	other[15] ^= 1
	space := pages{
		a: peWithCodeView(`x\hal.pdb`, other, 1),
		b: peWithCodeView(`x\ntkrnlmp.pdb`, fxGUID, 1),
		c: peWithCodeView(`x\ntkrnlmp.pdb`, other, 1),
	}
	id := &autoload.KernelIdentity{Fingerprint: fxFingerprint(fxGUID), Method: autoload.MethodScan}

	got, err := findKernelBase(space, id, []baseCandidate{failing("first"), at(a), at(b), at(c)})
	if err != nil || got.address != b || !got.confirmed || len(got.tried) != 2 || !strings.Contains(got.tried[1], "not a kernel") {
		t.Errorf("found %+v, %v", got, err)
	}
	if _, err := findKernelBase(space, id, []baseCandidate{at(c), at(b)}); !errors.Is(err, errOtherKernelBuild) {
		t.Errorf("another kernel build first: %v", err)
	}
}

func TestAnUnreadableRecordIsTrustedOnlyForAnUnambiguousBuild(t *testing.T) {
	const a = 0xfffff80000100000
	header := peWithCodeView(`x\ntkrnlmp.pdb`, fxGUID, 1)
	binary.LittleEndian.PutUint32(header[0x200+20:], 0x5000)
	space := pages{a: header}
	id := &autoload.KernelIdentity{Fingerprint: fxFingerprint(fxGUID), Method: autoload.MethodScan}

	got, err := findKernelBase(space, id, []baseCandidate{at(a)})
	if err != nil || got.address != a || got.confirmed || got.unread == nil {
		t.Errorf("unconfirmed base %+v, %v", got, err)
	}
	id.Provisional = true
	if _, err := findKernelBase(space, id, []baseCandidate{at(a)}); !errors.Is(err, errBaseUnconfirmed) {
		t.Errorf("provisional build: %v", err)
	}
	if _, err := findKernelBase(space, id, nil); !errors.Is(err, errBaseUnconfirmed) {
		t.Errorf("provisional build, no candidate: %v", err)
	}
	id.Provisional = false
	if got, err := findKernelBase(space, id, []baseCandidate{failing("only")}); err != nil || got.address != 0 || len(got.tried) != 1 {
		t.Errorf("nothing found: %+v, %v", got, err)
	}
}

func TestAnExplicitTableIsHeldToTheRunningKernel(t *testing.T) {
	build := fxBuild(fxGUID)
	named := lookupTable(t, symbols.Declaration{PointerWidth: 8, WindowsPDB: &build,
		Addresses: []symbols.Address{{Name: "PsActiveProcessHead", Address: fxHeadRVA}}})
	unnamed := lookupTable(t, symbols.Declaration{PointerWidth: 8,
		Addresses: []symbols.Address{{Name: "PsActiveProcessHead", Address: fxHeadRVA}}})
	other := fxGUID
	other[3] ^= 1
	running := &autoload.KernelIdentity{Fingerprint: fxFingerprint(fxGUID), Method: autoload.MethodLowStub}
	elsewhere := &autoload.KernelIdentity{Fingerprint: fxFingerprint(other), Method: autoload.MethodLowStub}

	if id, why, err := explicitTableKernel(named, running, nil); id != running || why != "" || err != nil {
		t.Errorf("same build: %v %q %v", id, why, err)
	}
	if _, _, err := explicitTableKernel(named, elsewhere, nil); !errors.Is(err, errOtherKernelBuild) {
		t.Errorf("other build: %v", err)
	}
	if id, why, _ := explicitTableKernel(unnamed, running, nil); id != running || !strings.Contains(why, "not checked") {
		t.Errorf("unnamed table: %v %q", id, why)
	}
	id, why, _ := explicitTableKernel(named, nil, errors.New("no start page"))
	if id == nil || id.Method != methodTableOwnBuild || !sameBuild(id.Fingerprint, fxFingerprint(fxGUID)) || !strings.Contains(why, "no start page") {
		t.Errorf("no running kernel: %v %q", id, why)
	}
	if id, why, _ := explicitTableKernel(unnamed, nil, nil); id != nil || !strings.Contains(why, "stay at their RVAs") {
		t.Errorf("nothing to check: %v %q", id, why)
	}
	if !needsKernelBase(named) || needsKernelBase(lookupTable(t, symbols.Declaration{PointerWidth: 8,
		Addresses: []symbols.Address{{Name: "PsActiveProcessHead", Address: fxKernelBase + fxHeadRVA}}})) {
		t.Error("needsKernelBase")
	}
}

func TestBuildsCompareByGUIDAgeAndNameWhenBothHaveOne(t *testing.T) {
	fp := fxFingerprint(fxGUID)
	lower := fp
	lower.GUID, lower.PDBName = strings.ToLower(fp.GUID), "NTKRNLMP.PDB"
	noName := fp
	noName.PDBName = ""
	older := fp
	older.Age = 2
	renamed := fp
	renamed.PDBName = "ntoskrnl.pdb"
	for _, c := range []struct {
		b    autoload.Fingerprint
		want bool
	}{{lower, true}, {noName, true}, {older, false}, {renamed, false}} {
		if sameBuild(fp, c.b) != c.want {
			t.Errorf("sameBuild(%v, %v) = %v", fp, c.b, !c.want)
		}
	}
	for path, want := range map[string]string{`d:\a\ntkrnlmp.pdb`: "ntkrnlmp.pdb", "a/b/hal.pdb": "hal.pdb", "x.pdb": "x.pdb"} {
		if got := pdbBaseName(path); got != want {
			t.Errorf("pdbBaseName(%q) = %q", path, got)
		}
	}
}

func layoutName(t *testing.T, b winkernel.Build) string {
	t.Helper()
	table, err := tcpipLayout(b)
	if err != nil {
		return "error: " + err.Error()
	}
	return table.Name()
}

func TestTheKernelBuildComesBeforeTheSharedCopy(t *testing.T) {
	unread := errors.New("unread")
	for _, c := range []struct {
		name string
		b    winkernel.Build
		want string
	}{
		{"kernel", winkernel.Build{Kernel: 26100, Major: 10, Shared: 14393}, "tcpip-26100"},
		{"kernel range", winkernel.Build{Kernel: 19044, VersionErr: unread, SharedErr: unread}, "tcpip-19041-19045"},
		{"shared", winkernel.Build{KernelErr: unread, Major: 10, Shared: 14393}, "tcpip-14393"},
		{"unmeasured kernel", winkernel.Build{Kernel: 22000, Major: 10, Shared: 26100}, "tcpip-26100"},
		{"not nt 10.0", winkernel.Build{KernelErr: unread, Major: 6, Minor: 3, Shared: 26100}, "nt version 6.3"},
		{"nothing", winkernel.Build{KernelErr: unread, VersionErr: unread}, "kernel build: unread; shared build: unread"},
		{"unmeasured both", winkernel.Build{Kernel: 9600, Major: 10, Shared: 9600}, "shared build 9600"},
	} {
		if got := layoutName(t, c.b); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAModulePDBIsLoadedOncePerSession(t *testing.T) {
	cache := t.TempDir()
	fp := autoload.Fingerprint{PDBName: "tcpip.pdb", GUID: autoload.FormatGUID(fxGUID[:]), Age: 1}
	build := symbols.PDBBuild{Database: fp.PDBName, GUID: fp.GUID, Age: 1}
	seedCache(t, cache, fp, symbols.Declaration{PointerWidth: 8, WindowsPDB: &build,
		Addresses: []symbols.Address{{Name: "TcpPortPool", Address: 0x100}}})
	opts, err := autoload.LoadOptions{CacheDir: cache, OfflineOnly: true}.Resolved()
	if err != nil {
		t.Fatal(err)
	}
	pdbs := newModulePDBs(opts)
	first, err := pdbs.load(fp)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := autoload.CachePath(cache, &fp)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if again, err := pdbs.load(fp); err != nil || again != first {
		t.Errorf("second load %v, %v", again, err)
	}

	absent := fp
	absent.Age = 9
	if _, err := pdbs.load(absent); !errors.Is(err, autoload.ErrSymbolsUnavailableOffline) {
		t.Fatalf("absent offline: %v", err)
	}
	seedCache(t, cache, absent, symbols.Declaration{PointerWidth: 8, Addresses: []symbols.Address{{Name: "a", Address: 1}}})
	if _, err := pdbs.load(absent); !errors.Is(err, autoload.ErrSymbolsUnavailableOffline) {
		t.Errorf("a failure was asked again: %v", err)
	}
}

// ELF gABI header and program header (S71 E2) for an ET_CORE file holding
// one PT_NOTE with a CORE NT_AUXV note, which only process cores carry
// (S71 E6).
func processCore() []byte {
	note := binary.LittleEndian.AppendUint32(nil, 5)
	note = binary.LittleEndian.AppendUint32(note, 8)
	note = binary.LittleEndian.AppendUint32(note, 6)
	note = append(note, "CORE\x00\x00\x00\x00"...)
	note = append(note, make([]byte, 8)...)
	const ehdr, phdr = 64, 56
	f := make([]byte, ehdr+phdr, ehdr+phdr+len(note))
	copy(f, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(f[16:], 4)
	binary.LittleEndian.PutUint16(f[18:], 62)
	binary.LittleEndian.PutUint32(f[20:], 1)
	binary.LittleEndian.PutUint64(f[32:], ehdr)
	binary.LittleEndian.PutUint16(f[52:], ehdr)
	binary.LittleEndian.PutUint16(f[54:], phdr)
	binary.LittleEndian.PutUint16(f[56:], 1)
	binary.LittleEndian.PutUint32(f[ehdr:], 4)
	binary.LittleEndian.PutUint64(f[ehdr+8:], ehdr+phdr)
	binary.LittleEndian.PutUint64(f[ehdr+32:], uint64(len(note)))
	binary.LittleEndian.PutUint64(f[ehdr+40:], uint64(len(note)))
	binary.LittleEndian.PutUint64(f[ehdr+48:], 4)
	return append(f, note...)
}

func TestAnOpenFailsOnWhatItCannotTake(t *testing.T) {
	dir := t.TempDir()
	core := filepath.Join(dir, "sleep.core")
	if err := os.WriteFile(core, processCore(), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(dir, "zero.raw")
	if err := os.WriteFile(raw, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path, os string
		cfg      OpenConfig
		want     string
	}{
		"operating system": {raw, "macos", OpenConfig{}, `"macos" is not windows or linux`},
		"limits":           {raw, "windows", OpenConfig{Limits: Limits{MaxListEntries: -1}}, "open config"},
		"symbol server":    {raw, "linux", OpenConfig{SymbolLoad: autoload.LoadOptions{ServerURL: "ftp://x"}}, "open config"},
		"missing file":     {filepath.Join(dir, "absent.raw"), "windows", OpenConfig{}, "open capture"},
		"symbol file":      {raw, "windows", OpenConfig{SymbolsPath: filepath.Join(dir, "absent.vsym")}, "read symbol table"},
		"no kernel":        {raw, "windows", OpenConfig{OfflineOnly: true}, "identify the windows kernel"},
	} {
		if _, err := OpenMemory(c.path, c.os, c.cfg); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, osName := range []string{"windows", "linux"} {
		if _, err := OpenMemory(core, osName, OpenConfig{}); !errors.Is(err, memory.ErrProcessCore) {
			t.Errorf("%s process core: %v", osName, err)
		}
	}
}

// Whatever the shift and the names' addresses, a name found by
// LookupSymbol is among those SymbolsAt gives for its address.
func FuzzMovedTableAgreesWithItself(f *testing.F) {
	f.Add(uint64(0xfffff80000000000), uint64(0x2000), uint64(0xfffff80000002000))
	f.Add(uint64(0), uint64(0), uint64(math32))
	f.Add(uint64(1<<63), uint64(math32), uint64(math32+1))
	f.Fuzz(func(t *testing.T, shift, a, b uint64) {
		inner, err := symbols.Build("fuzz", symbols.Declaration{PointerWidth: 8, Addresses: []symbols.Address{
			{Name: "a", Address: a}, {Name: "b", Address: b}}})
		if err != nil {
			return
		}
		m := movedTable{inner: inner, shift: shift, moves: isRVA}
		for _, name := range []string{"a", "b"} {
			s, err := m.LookupSymbol(name)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(m.SymbolsAt(s.Address), func(x symbols.Symbol) bool { return x.Name == name && x.Address == s.Address }) {
				t.Fatalf("%s at %#x not named there (shift %#x)", name, s.Address, shift)
			}
		}
	})
}

const math32 = 1<<32 - 1
