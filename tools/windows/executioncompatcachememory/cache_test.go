package executioncompatcachememory

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

// 2024-01-02T03:04:05Z as a FILETIME.
const ft = uint64(133486382450000000)

var three = []s41Entry{
	{key: `C:\Windows\System32\notepad.exe`, time: ft, data: []byte{0, 2, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0}},
	{key: "0000000b\t000a000065f40001\tMicrosoft.Example\tneutral", data: []byte{0, 2, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0}},
	{key: `C:\Tools\a.exe`, time: ft + 10_000_000},
}

func diagsWith(diags []string, part string) int {
	n := 0
	for _, d := range diags {
		if strings.Contains(d, part) {
			n++
		}
	}
	return n
}

func TestAWholeCacheIsListedMostRecentFirst(t *testing.T) {
	f := newS41Cache(three)
	rows, err := collect(f.ctx(false), handleAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || len(f.diags) != 0 {
		t.Fatalf("got %d rows, diagnostics %q", len(rows), f.diags)
	}
	for i, r := range rows {
		if r.Position != i || r.PositionFromTail != 2-i || !r.InList || !r.InTable || r.Address != f.element(i) {
			t.Errorf("row %d: %+v", i, r)
		}
		if r.Key != three[i].key || r.KeyUnreadable || r.DataUnreadable || r.DataSize != uint32(len(three[i].data)) ||
			string(r.Data) != string(three[i].data) {
			t.Errorf("row %d: %+v", i, r)
		}
	}
	if want := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC); !rows[0].FileLastWrite.Equal(want) {
		t.Errorf("file time %v, want %v", rows[0].FileLastWrite, want)
	}
	if !rows[1].FileLastWrite.IsZero() {
		t.Errorf("a package key with no file time has %v", rows[1].FileLastWrite)
	}
	if rows[2].Data != nil {
		t.Errorf("empty data is %v", rows[2].Data)
	}
}

func TestABrokenListIsWalkedFromBothEndsAndTheTreeFindsTheRest(t *testing.T) {
	entries := []s41Entry{{key: "a"}, {key: "b"}, {key: "c"}, {key: "d"}, {key: "e"}}
	f := newS41Cache(entries)
	f.linkList(f.element(0), f.element(1), f.element(2), f.element(3))
	f.mem.u64(f.element(1), 0)
	f.mem.u64(f.element(2)+8, 0)
	rows, err := collect(f.ctx(false), handleAddr)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		at             uint64
		pos, fromTail  int
		inList, inTree bool
	}{
		{f.element(0), 0, -1, true, true},
		{f.element(1), 1, -1, true, true},
		{f.element(2), -1, 1, true, true},
		{f.element(3), -1, 0, true, true},
		{f.element(4), -1, -1, false, true},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows: %+v", len(rows), rows)
	}
	for i, w := range want {
		r := rows[i]
		if r.Address != w.at || r.Position != w.pos || r.PositionFromTail != w.fromTail || r.InList != w.inList || r.InTable != w.inTree {
			t.Errorf("row %d: %+v, want %+v", i, r, w)
		}
	}
	if diagsWith(f.diags, "1 entries only in the tree, 0 only in the list, 5 tree nodes reached of 5 counted") != 1 {
		t.Errorf("diagnostics %q", f.diags)
	}
	if _, err := collect(f.ctx(true), handleAddr); err == nil {
		t.Error("strict mode accepted a broken list")
	}
}

func TestAListEntryOutsideTheTreeIsKeptAndCounted(t *testing.T) {
	f := newS41Cache(three)
	stray := pool + 0x90000
	f.mem.u64(stray+elementDataOffset, pool+0x91000)
	f.mem.u32(pool+0x91000+dataSizeOffset, 0)
	f.linkList(f.element(0), stray, f.element(1), f.element(2))
	rows, err := collect(f.ctx(false), handleAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || rows[1].Address != stray || rows[1].InTable || !rows[1].InList || rows[1].Position != 1 {
		t.Fatalf("rows %+v", rows)
	}
	if diagsWith(f.diags, "0 entries only in the tree, 1 only in the list") != 1 {
		t.Errorf("diagnostics %q", f.diags)
	}
}

func TestTreeNodesThatAreMisparentedOrUnreadableAreReported(t *testing.T) {
	f := newS41Cache(three)
	root := binary.LittleEndian.Uint64(must(f.mem.ReadAt(storeAddr+0x10, 8)))
	left := binary.LittleEndian.Uint64(must(f.mem.ReadAt(root+8, 8)))
	f.mem.u64(left, 0)
	f.mem.u64(root+0x10, pool+0xF00000)
	rows, err := collect(f.ctx(false), handleAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows", len(rows))
	}
	if diagsWith(f.diags, "Parent is 0x0, not the node above") != 1 || diagsWith(f.diags, "links do not read") != 1 {
		t.Errorf("diagnostics %q", f.diags)
	}
	if diagsWith(f.diags, "1 only in the list, 2 tree nodes reached of 3 counted") != 1 {
		t.Errorf("diagnostics %q", f.diags)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestBadKeysAndDataAreFlaggedAndStrictModeFails(t *testing.T) {
	f := newS41Cache([]s41Entry{{key: "odd", time: ft}, {key: "gone"}, {key: "data", data: make([]byte, 64)}, {key: "big", data: make([]byte, 8)}})
	f.mem.u16(f.element(0)+elementKeyOffset, 3)
	f.mem.drop(f.keyAt(1))
	f.mem.drop(f.blobAt(2))
	f.limits = limits.Limits{MaxNameBytes: 16, MaxTextBytes: 32, MaxBufferBytes: 32}
	f.mem.u32(f.dataAt(3)+dataSizeOffset, 33)
	rows, err := collect(f.ctx(false), handleAddr)
	if err != nil {
		t.Fatal(err)
	}
	if !rows[0].KeyUnreadable || rows[0].DataUnreadable || rows[0].FileLastWrite.IsZero() {
		t.Errorf("odd key: %+v", rows[0])
	}
	if !rows[1].KeyUnreadable || rows[1].Key != "" {
		t.Errorf("unread key: %+v", rows[1])
	}
	if rows[2].KeyUnreadable || !rows[2].DataUnreadable || rows[2].DataSize != 64 {
		t.Errorf("unread data: %+v", rows[2])
	}
	if !rows[3].DataUnreadable || rows[3].DataSize != 33 {
		t.Errorf("data over the limit: %+v", rows[3])
	}
	if diagsWith(f.diags, "key not read") != 2 || diagsWith(f.diags, "data not read") != 2 {
		t.Errorf("diagnostics %q", f.diags)
	}
	rows, err = collect(f.ctx(true), handleAddr)
	if !errors.Is(err, ErrKeyLayout) || len(rows) != 4 {
		t.Errorf("strict: %d rows, %v", len(rows), err)
	}
}

func TestAKeyLongerThanMaxNameBytesIsNotRead(t *testing.T) {
	f := newS41Cache([]s41Entry{{key: strings.Repeat("x", 40)}})
	f.limits = limits.Limits{MaxNameBytes: 64}
	rows, err := collect(f.ctx(false), handleAddr)
	if err != nil || len(rows) != 1 || !rows[0].KeyUnreadable {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if diagsWith(f.diags, ErrKeyTooLong.Error()) != 1 {
		t.Errorf("diagnostics %q", f.diags)
	}
}

func TestTheTreeWalkStopsAtMaxTableEntries(t *testing.T) {
	f := newS41Cache(three)
	f.linkList()
	f.limits = limits.Limits{MaxTableEntries: 2}
	rows, err := collect(f.ctx(false), handleAddr)
	if err != nil || len(rows) != 2 {
		t.Fatalf("got %d rows, %v", len(rows), err)
	}
	if diagsWith(f.diags, "more than 2 nodes") != 1 {
		t.Errorf("diagnostics %q", f.diags)
	}
	rows, err = collect(f.ctx(true), handleAddr)
	if !errors.Is(err, ErrLimit) || len(rows) != 2 {
		t.Errorf("strict: %d rows, %v", len(rows), err)
	}
}

func TestAnEmptyCacheHasNoRows(t *testing.T) {
	f := newS41Cache(nil)
	rows, err := collect(f.ctx(false), handleAddr)
	if err != nil || len(rows) != 0 || len(f.diags) != 0 {
		t.Fatalf("rows %+v, %v, %q", rows, err, f.diags)
	}
}

func TestACacheThatDoesNotReadFailsTheRun(t *testing.T) {
	f := newS41Cache(three)
	f.mem.u64(cacheAddr+cacheStoreOffset, 0)
	if _, err := collect(f.ctx(false), handleAddr); !errors.Is(err, ErrCacheUnread) {
		t.Errorf("null store: %v", err)
	}
	if _, err := collect(f.ctx(false), pool+0xF00000); !errors.Is(err, ErrCacheUnread) {
		t.Errorf("unread handle: %v", err)
	}
	f = newS41Cache(three)
	f.table = symbols.NewTable("bare", 8)
	if _, err := collect(f.ctx(false), handleAddr); !errors.Is(err, ErrTypeMissing) {
		t.Errorf("no tree types: %v", err)
	}
}

func TestA32BitKernelIsRefused(t *testing.T) {
	f := newS41Cache(three)
	f.table = s41Table(4)
	if _, err := Run(f.ctx(false)); !errors.Is(err, ErrNot64Bit) {
		t.Errorf("got %v", err)
	}
}

const driverBase = uint64(0xFFFFF80010000000)

// A PE header with one debug directory entry naming ahcache.pdb (PE/COFF
// optional header and debug directory; CodeView RSDS record).
func writeDriverImage(m sparse) {
	m.u16(driverBase, 0x5A4D)
	m.u32(driverBase+0x3C, 0x80)
	m.u32(driverBase+0x80, 0x00004550)
	m.u16(driverBase+0x84, 0x8664)
	m.u16(driverBase+0x84+16, 0xF0)
	opt := driverBase + 0x98
	m.u16(opt, 0x020B)
	m.u32(opt+32, 0x1000)
	m.u32(opt+36, 0x200)
	m.u32(opt+56, 0x30000)
	m.u32(opt+60, 0x400)
	m.u32(opt+108, 16)
	m.u32(opt+112+6*8, 0x1000)
	m.u32(opt+112+6*8+4, 28)
	path := "ahcache.pdb\x00"
	m.u32(driverBase+0x1000+12, 2)
	m.u32(driverBase+0x1000+16, uint32(24+len(path)))
	m.u32(driverBase+0x1000+20, 0x1100)
	m.write(driverBase+0x1100, []byte("RSDS"))
	m.write(driverBase+0x1104, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	m.u32(driverBase+0x1114, 1)
	m.write(driverBase+0x1118, []byte(path))
}

func TestTheHandleIsFoundThroughTheDriversSymbols(t *testing.T) {
	f := newS41Cache(three)
	writeDriverImage(f.mem)
	mods := []modulelist.Module{{Base: driverBase, Size: 0x30000, Name: "AHCACHE.SYS"}}
	ctx := f.ctx(false)

	if _, err := locateHandle(ctx, nil); !errors.Is(err, ErrNoDriver) {
		t.Errorf("no driver: %v", err)
	}
	if _, err := locateHandle(ctx, mods); !errors.Is(err, ErrNoSymbols) {
		t.Errorf("no loader: %v", err)
	}
	var asked autoload.Fingerprint
	ctx.LoadPDB = func(fp autoload.Fingerprint) (symbols.SymbolTable, error) {
		asked = fp
		t := symbols.NewTable("ahcache", 8)
		t.AddSymbol(symbols.Symbol{Name: handleSymbol, Address: handleAddr - driverBase})
		return t, nil
	}
	got, err := locateHandle(ctx, mods)
	if err != nil || got != handleAddr {
		t.Fatalf("handle 0x%x, %v", got, err)
	}
	if asked.PDBName != "ahcache.pdb" || asked.Age != 1 || asked.GUID != autoload.FormatGUID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}) {
		t.Errorf("fingerprint %+v", asked)
	}
	ctx.LoadPDB = func(autoload.Fingerprint) (symbols.SymbolTable, error) { return symbols.NewTable("ahcache", 8), nil }
	if _, err := locateHandle(ctx, mods); !errors.Is(err, ErrNoSymbols) {
		t.Errorf("no handle symbol: %v", err)
	}
	ctx.LoadPDB = func(autoload.Fingerprint) (symbols.SymbolTable, error) { return nil, errors.New("offline") }
	if _, err := locateHandle(ctx, mods); !errors.Is(err, ErrNoSymbols) {
		t.Errorf("load failure: %v", err)
	}
}

func TestRunRefusesAnotherProfile(t *testing.T) {
	f := newS41Cache(three)
	ctx := f.ctx(false)
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Error("a Linux profile was accepted")
	}
}
