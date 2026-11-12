package moduleunloaded

import (
	"testing"
	"time"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

const (
	boot = uint64(134000000000000000)
	up   = uint64(36_000_000_000)
)

type record struct {
	name       string
	start, end uint64
	when       uint64
}

func unloadedKernel(records []record, last uint32) *testsupport.S64Kernel {
	k := testsupport.NewS64Kernel()
	for _, m := range []struct{ off, v uint64 }{{testsupport.S64SystemTime, boot + up}, {testsupport.S64InterruptTime, up}} {
		at := testsupport.S64SharedData + m.off
		k.U32(at, uint32(m.v))
		k.U32(at+4, uint32(m.v>>32))
		k.U32(at+8, uint32(m.v>>32))
	}
	array := k.Alloc(capacity * recordBytes)
	for i, r := range records {
		at := array + uint64(i)*recordBytes
		k.String(at+nameOffset, r.name)
		k.U64(at+startOffset, r.start)
		k.U64(at+endOffset, r.end)
		k.U64(at+timeOffset, r.when)
	}
	k.U64(k.Global("MmUnloadedDrivers", 8), array)
	k.U32(k.Global("MmLastUnloadedDriver", 4), last)
	return k
}

func TestRecordsAreListedOldestFirstOnTheirClock(t *testing.T) {
	k := unloadedKernel([]record{
		{"early.sys", 0xfffff80001000000, 0xfffff80001005000, 10_000_000},
		{"wall.sys", 0xfffff80002000000, 0xfffff80002003000, boot + 600_000_000},
		{"future.sys", 0xfffff80003000000, 0xfffff80003001000, boot + up + 1},
	}, 3)
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	bootTime := time.Unix(0, int64(boot-116444736000000000)*100).UTC()
	if r := rows[0]; r.Name != "early.sys" || r.Clock != ClockInterrupt || r.SinceBoot != time.Second ||
		!r.Time.Equal(bootTime.Add(time.Second)) || r.StartAddress != 0xfffff80001000000 {
		t.Errorf("first = %+v", r)
	}
	if r := rows[1]; r.Clock != ClockSystem || r.SinceBoot != time.Minute || !r.Time.Equal(bootTime.Add(time.Minute)) {
		t.Errorf("second = %+v", r)
	}
	if r := rows[2]; r.Clock != ClockUnknown || !r.Time.IsZero() {
		t.Errorf("third = %+v", r)
	}
}

func TestAWrappedArrayStartsAtTheNextSlot(t *testing.T) {
	records := make([]record, capacity)
	for i := range records {
		records[i] = record{name: string(rune('a'+i%26)) + ".sys", when: uint64(i + 1)}
	}
	rows, err := Run(unloadedKernel(records, 2).Context())
	if err != nil || len(rows) != capacity || rows[0].CurrentTime != 3 || rows[capacity-1].CurrentTime != 2 {
		t.Errorf("rows %d err %v", len(rows), err)
	}
}

func TestAnIndexAboveTheCapacityIsCapped(t *testing.T) {
	k := unloadedKernel([]record{{name: "a.sys"}}, capacity+5)
	ctx := k.Context()
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Error("strict mode accepted the index")
	}
	delete(ctx.Options, "strict")
	if rows, err := Run(ctx); err != nil || len(rows) != capacity {
		t.Errorf("rows %d err %v", len(rows), err)
	}
}

func TestANullArrayHasNoRows(t *testing.T) {
	k := unloadedKernel(nil, 0)
	arr, _ := k.Table.LookupSymbol("MmUnloadedDrivers")
	k.U64(arr.Address, 0)
	if rows, err := Run(k.Context()); err != nil || len(rows) != 0 {
		t.Errorf("rows %v err %v", rows, err)
	}
}

func FuzzRecords(f *testing.F) {
	f.Add(make([]byte, recordBytes), uint32(1))
	k := unloadedKernel(nil, 0)
	arr, _ := k.Table.LookupSymbol("MmUnloadedDrivers")
	last, _ := k.Table.LookupSymbol("MmLastUnloadedDriver")
	array, _ := k.Context().Memory.ReadAt(arr.Address, 8)
	base := uint64(0)
	for i := 7; i >= 0; i-- {
		base = base<<8 | uint64(array[i])
	}
	ctx := k.Context()
	f.Fuzz(func(t *testing.T, raw []byte, n uint32) {
		if len(raw) > 4*recordBytes {
			raw = raw[:4*recordBytes]
		}
		k.Write(base, raw)
		k.U32(last.Address, n)
		rows, err := Run(ctx)
		if err == nil && len(rows) > capacity {
			t.Errorf("%d rows", len(rows))
		}
		for _, r := range rows {
			if r.NameUnreadable && r.Name != "" {
				t.Errorf("row %+v", r)
			}
		}
	})
}
