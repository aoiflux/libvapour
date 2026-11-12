package threadaddress

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

const ethread = uint64(0xffffd00000200000)

func TestTheSystemThreadBitIsReadAtItsOwnBit(t *testing.T) {
	mem := testsupport.S51Memory{}
	mem.Put32(ethread+testsupport.S51MiscFlags, ^uint32(1<<testsupport.S51SystemBit))
	flag := ResolveSystemThread(testsupport.S51Table())
	if set, err := IsSystemThread(flag, mem, ethread, 4); err != nil || set {
		t.Errorf("bit clear, every other bit set: %v, %v", set, err)
	}
	testsupport.S51SetBit(mem, ethread+testsupport.S51MiscFlags, testsupport.S51SystemBit)
	if set, err := IsSystemThread(flag, mem, ethread, 1300); err != nil || !set {
		t.Errorf("bit set: %v, %v", set, err)
	}
	if _, err := IsSystemThread(flag, mem, ethread+0x10000, 4); err == nil {
		t.Error("an unread flag gives no error")
	}
}

func TestWithoutTheBitTheSystemProcessOwnsTheSystemThreads(t *testing.T) {
	flag := ResolveSystemThread(testsupport.S51Table("_KTHREAD.SystemThread"))
	if flag.Known() {
		t.Fatal("flag known without its member")
	}
	for pid, want := range map[uint64]bool{4: true, 1300: false} {
		if got, err := IsSystemThread(flag, nil, 0, pid); err != nil || got != want {
			t.Errorf("pid %d: %v, %v", pid, got, err)
		}
	}
}
