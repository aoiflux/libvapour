package syscalllist

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

const kernel = uint64(0xfffff80000400000)

func serviceKernel(entries []uint32, descriptorBase uint64) (*testsupport.S64Kernel, uint64) {
	k := testsupport.NewS64Kernel()
	k.AddModule("ntoskrnl.exe", kernel, 0x100000)
	table := kernel + 0x1000
	k.Table.AddSymbol(symbolAt("KiServiceTable", table))
	limit := k.Global("KiServiceLimit", 4)
	k.U32(limit, uint32(len(entries)))
	for i, e := range entries {
		k.U32(table+uint64(i)*4, e)
	}
	if descriptorBase != 0 {
		sdt := k.Global("KeServiceDescriptorTable", 0x20)
		k.U64(sdt, descriptorBase)
		k.U32(sdt+16, uint32(len(entries)))
	}
	return k, table
}

func TestEntriesAreOffsetsFromTheTableWithArgumentBytes(t *testing.T) {
	k, table := serviceKernel([]uint32{0x1000<<4 | 2, 0, negative(-0x800)}, 0)
	k.Table.AddSymbol(symbolAt("NtFirst", table+0x1000))
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	if r := rows[0]; r.Index != 0 || r.Address != table+0x1000 || r.ArgumentBytes != 8 || r.Module != "ntoskrnl" ||
		r.Symbol != "NtFirst" || r.Unowned {
		t.Errorf("first = %+v", r)
	}
	if rows[1].Address != table || rows[2].Address != table-0x800 {
		t.Errorf("addresses 0x%x 0x%x", rows[1].Address, rows[2].Address)
	}
}

func TestTheDescriptorIsPreferredAndADifferentTableIsReported(t *testing.T) {
	k, table := serviceKernel([]uint32{0x10 << 4}, 0)
	other := k.Alloc(0x10)
	k.U32(other, 0x20<<4)
	sdt := k.Global("KeServiceDescriptorTable", 0x20)
	k.U64(sdt, other)
	k.U32(sdt+16, 1)
	ctx := k.Context()
	var diags []string
	ctx.Options["diagnostics"] = &diags
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].Address != other+0x20 || !rows[0].Unowned {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	found := false
	for _, d := range diags {
		if d == "windows.syscall.list: KeServiceDescriptorTable at 0x"+hex(sdt)+": names table 0x"+hex(other)+
			" with limit 1, not KiServiceTable 0x"+hex(table)+" with limit 1" {
			found = true
		}
	}
	if !found {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestNoTableIsAnError(t *testing.T) {
	k := testsupport.NewS64Kernel()
	if _, err := Run(k.Context()); err == nil {
		t.Error("no error without a service table")
	}
}

func FuzzServiceTable(f *testing.F) {
	f.Add([]byte{0x20, 0, 0, 0, 0xf0, 0xff, 0xff, 0xff})
	k, table := serviceKernel(make([]uint32, 4), 0)
	ctx := k.Context()
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 16 {
			raw = raw[:16]
		}
		k.Write(table, append(raw, make([]byte, 16-len(raw))...))
		rows, err := Run(ctx)
		if err != nil || len(rows) != 4 {
			t.Fatalf("rows %d err %v", len(rows), err)
		}
		for _, r := range rows {
			if r.ArgumentBytes > 60 || r.ArgumentBytes%4 != 0 {
				t.Errorf("row %+v", r)
			}
		}
	})
}
