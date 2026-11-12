package modulescan

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

func pooledEntry(k *testsupport.S64Kernel, name string, base, size uint64) uint64 {
	va := k.Alloc(testsupport.PoolHeaderSize + testsupport.S64LoaderEntrySize)
	header := make([]byte, testsupport.PoolHeaderSize)
	testsupport.WritePoolHeader(header, 0, "MmLd", testsupport.BlocksFor(testsupport.PoolHeaderSize+testsupport.S64LoaderEntrySize),
		testsupport.NonPagedPoolType)
	k.Write(va, header)
	body := va + testsupport.PoolHeaderSize
	k.U64(body+testsupport.S64LoaderDllBase, base)
	k.U32(body+testsupport.S64LoaderSize, uint32(size))
	if name != "" {
		k.String(body+testsupport.S64LoaderBaseName, name)
		k.String(body+testsupport.S64LoaderFullName, `\SystemRoot\system32\drivers\`+name)
	}
	return body
}

func TestLoaderEntriesAreFoundAndJudgedByTheirImageRange(t *testing.T) {
	k := testsupport.NewS64Kernel()
	good := pooledEntry(k, "alpha.sys", 0xfffff80001000000, 0x5000)
	pooledEntry(k, "user.sys", 0x00007ff600000000, 0x5000)
	pooledEntry(k, "odd.sys", 0xfffff80001000800, 0x5000)
	pooledEntry(k, "empty.sys", 0xfffff80002000000, 0)
	pooledEntry(k, "ragged.sys", 0xfffff80003000000, 0x1234)
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want alpha only", rows)
	}
	r := rows[0]
	if r.VirtualOffset != good || r.Offset != k.Physical(good) || r.Base != 0xfffff80001000000 || r.Size != 0x5000 ||
		r.Name != "alpha.sys" || r.Path != `\SystemRoot\system32\drivers\alpha.sys` || r.NameUnreadable || r.PathUnreadable {
		t.Errorf("row = %+v", r)
	}
}

func TestTheBaseAndNameOptionsFilter(t *testing.T) {
	k := testsupport.NewS64Kernel()
	pooledEntry(k, "alpha.sys", 0xfffff80001000000, 0x5000)
	pooledEntry(k, "beta.sys", 0xfffff80002000000, 0x5000)
	unnamed := pooledEntry(k, "", 0xfffff80003000000, 0x5000)
	k.U16(unnamed+testsupport.S64LoaderBaseName, 4)
	k.U64(unnamed+testsupport.S64LoaderBaseName+8, k.Skip())
	ctx := k.Context()
	ctx.Options[OptionName] = "beta"
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Name != "beta.sys" || !rows[1].NameUnreadable {
		t.Errorf("rows = %+v, want beta and the entry whose name did not read", rows)
	}
	ctx.Options[OptionName] = ""
	ctx.Options[OptionBase] = uint64(0x0000f80001000000)
	if rows, err = Run(ctx); err != nil || len(rows) != 1 || rows[0].Name != "alpha.sys" {
		t.Errorf("masked base: rows %+v, err %v", rows, err)
	}
	ctx.Options[OptionBase] = "x"
	if _, err := Run(ctx); err == nil {
		t.Error("a base of the wrong type was accepted")
	}
}

func TestPlausibleName(t *testing.T) {
	if !PlausibleName("ntoskrnl.exe") || PlausibleName("") || PlausibleName("a\x00") || PlausibleName("�") {
		t.Error("PlausibleName")
	}
}

func FuzzDecode(f *testing.F) {
	k := testsupport.NewS64Kernel()
	body := pooledEntry(k, "seed.sys", 0xfffff80001000000, 0x5000)
	seed, _ := k.Context().Memory.ReadAt(body, testsupport.S64LoaderEntrySize)
	f.Add(seed)
	ctx := k.Context()
	l, err := resolve(ctx.Symbols, "_KLDR_DATA_TABLE_ENTRY")
	if err != nil {
		f.Fatal(err)
	}
	l.systemStart = testsupport.S64SystemStart
	scratch := testsupport.NewPagedMemory(0x2000)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if uint64(len(raw)) > 0x1000 {
			return
		}
		scratch.WriteAt(0, make([]byte, 0x1000))
		scratch.WriteAt(0, raw)
		m, ok := l.decode(scratch, ctx.Memory, 0)
		if !ok {
			return
		}
		if m.Base < l.systemStart || m.Base&0xFFF != 0 || m.Size == 0 || m.Size&0xFFF != 0 {
			t.Errorf("accepted %+v", m)
		}
		if m.NameUnreadable && m.Name != "" {
			t.Errorf("flagged name with text %q", m.Name)
		}
	})
}
