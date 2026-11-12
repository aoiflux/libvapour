package timerlist

import (
	"math/bits"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

const (
	never  = uint64(0xe1711ac006d72e15)
	always = uint64(0x01b5cb5212c47b80)
)

func encode(dpc, timer uint64) uint64 {
	x := bits.ReverseBytes64(dpc^always) ^ timer
	return bits.RotateLeft64(x, -int(never&0xFF)) ^ never
}

type fixture struct {
	k     *testsupport.S64Kernel
	prcb  uint64
	heads []uint64
}

func newFixture(t *testing.T) *fixture {
	k := testsupport.NewS64Kernel()
	k.AddModule("ntoskrnl.exe", 0xfffff80000400000, 0x100000)
	k.AddModule("alpha.sys", 0xfffff80001000000, 0x5000)
	block := k.Global("KiProcessorBlock", 8)
	count := k.Global("KeNumberProcessors", 4)
	k.Write(count, []byte{1})
	pcr := k.Alloc(0xd080)
	prcb := pcr + testsupport.S64PcrPrcb
	k.U64(pcr+testsupport.S64PcrSelf, pcr)
	k.U64(pcr+testsupport.S64PcrCurrentPrcb, prcb)
	k.U64(block, prcb)
	f := &fixture{k: k, prcb: prcb}
	for b := uint64(0); b < testsupport.S64TimerBuckets; b++ {
		head := prcb + testsupport.S64PrcbTimerTable + testsupport.S64TimerEntries + b*testsupport.S64TableEntrySize +
			testsupport.S64TableEntryList
		k.U64(head, head)
		k.U64(head+8, head)
		f.heads = append(f.heads, head)
	}
	k.U64(k.Global("KiWaitNever", 8), never)
	k.U64(k.Global("KiWaitAlways", 8), always)
	return f
}

func (f *fixture) timer(bucket int, kind byte, routine uint64, withDpc bool) uint64 {
	k := f.k
	timer := k.Alloc(testsupport.S64TimerSize)
	k.Write(timer, []byte{kind})
	k.U64(timer+testsupport.S64TimerDueTime, 0x123456789)
	k.U32(timer+testsupport.S64TimerPeriod, 1000)
	k.U32(timer+testsupport.S64HeaderSignal, 1)
	dpc := uint64(0)
	if withDpc {
		dpc = k.Alloc(testsupport.S64DpcSize)
		k.Write(dpc, []byte{19})
		k.U64(dpc+testsupport.S64DpcRoutine, routine)
	}
	k.U64(timer+testsupport.S64TimerDpc, encode(dpc, timer))
	head := f.heads[bucket]
	link := timer + testsupport.S64TimerLinks
	last, _ := k.Context().Memory.ReadAt(head+8, 8)
	prev := uint64(0)
	for i := 7; i >= 0; i-- {
		prev = prev<<8 | uint64(last[i])
	}
	k.U64(link, head)
	k.U64(link+8, prev)
	k.U64(prev, link)
	k.U64(head+8, link)
	return timer
}

func TestTimersWithADpcAreListedWithTheirRoutine(t *testing.T) {
	f := newFixture(t)
	a := f.timer(3, 8, 0xfffff80001000100, true)
	f.timer(3, 9, 0, false)
	b := f.timer(300, 9, 0xfffff80009000000, true)
	f.timer(4, 5, 0xfffff80001000100, true)
	rows, err := Run(f.k.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	if r := rows[0]; r.Offset != a || r.Routine != 0xfffff80001000100 || r.Module != "alpha" || r.Unowned ||
		r.DueTime != 0x123456789 || r.Period != 1000 || !r.Signaled || r.Processor != 0 {
		t.Errorf("first = %+v", r)
	}
	if r := rows[1]; r.Offset != b || !r.Unowned || r.Module != "" {
		t.Errorf("second = %+v", r)
	}
}

func TestAStoredPointerIsTakenAsIsWithoutTheKeys(t *testing.T) {
	f := newFixture(t)
	timer := f.timer(0, 8, 0xfffff80001000100, true)
	k := f.k
	dpc := k.Alloc(testsupport.S64DpcSize)
	k.Write(dpc, []byte{26})
	k.U64(dpc+testsupport.S64DpcRoutine, 0xfffff80000400200)
	k.U64(timer+testsupport.S64TimerDpc, dpc)
	keyed, err := Run(k.Context())
	if err != nil || len(keyed) != 0 {
		t.Errorf("a plain pointer decoded with the keys: %+v %v", keyed, err)
	}
	if got := (dpcKeys{never: never, always: always}).decode(encode(dpc, timer), timer); got != dpc {
		t.Errorf("decode(encode) = 0x%x, want 0x%x", got, dpc)
	}
}

func TestAMisalignedLinkIsNotATimer(t *testing.T) {
	f := newFixture(t)
	timer := f.timer(7, 8, 0xfffff80001000100, true)
	k := f.k
	k.U64(f.heads[7], timer+testsupport.S64TimerLinks+3)
	k.U64(f.heads[7]+8, timer+testsupport.S64TimerLinks+3)
	rows, err := Run(k.Context())
	if err != nil || len(rows) != 0 {
		t.Errorf("rows %+v err %v", rows, err)
	}
}

func FuzzDpcKey(f *testing.F) {
	f.Add(uint64(1), uint64(2), uint64(3), uint64(4))
	f.Fuzz(func(t *testing.T, n, a, dpc, timer uint64) {
		k := dpcKeys{never: n, always: a}
		x := bits.ReverseBytes64(dpc^a) ^ timer
		stored := bits.RotateLeft64(x, -int(n&0xFF)) ^ n
		if got := k.decode(stored, timer); got != dpc {
			t.Errorf("decode(encode(0x%x)) = 0x%x", dpc, got)
		}
	})
}
