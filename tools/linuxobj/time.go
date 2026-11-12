package linuxobj

import (
	"errors"
	"fmt"
	"math"
	"time"
)

var (
	ErrNoTimekeeper  = errors.New("linuxobj: no core timekeeper in the symbol table")
	ErrTimekeeperAt  = errors.New("linuxobj: timekeeper placement unknown")
	ErrTimeRange     = errors.New("linuxobj: time out of range")
	ErrNoStartTime   = errors.New("linuxobj: task_struct has no boot-relative start time")
	ErrNoTimeNSProxy = errors.New("linuxobj: nsproxy has no time namespace")
)

// S46 C1: the core timekeeper's symbol up to v6.14, and the array whose
// element 0 is the core timekeeper at v6.17.
var timekeeperSymbols = []string{"tk_core", "timekeeper_data"}

const (
	nsecPerSec = int64(time.Second)
	// S46 C7: KTIME_SEC_MAX, the largest whole second a ktime_t holds.
	ktimeSecMax = math.MaxInt64 / nsecPerSec
)

type BootClock struct {
	Timekeeper   uint64
	Sequence     uint64
	SequenceRead bool
	RealOffset   time.Duration
	BootOffset   time.Duration
	Boot         time.Time
	Updated      time.Time
	WallChecked  bool
	WallAgrees   bool
	SleepChecked bool
	SleepAgrees  bool
}

// S46 C4: an odd sequence means a writer was between its two increments.
func (c BootClock) Updating() bool { return c.SequenceRead && c.Sequence&1 != 0 }

func (c BootClock) Consistent() bool {
	return (!c.WallChecked || c.WallAgrees) && (!c.SleepChecked || c.SleepAgrees)
}

func (k *Kernel) BootClock() (BootClock, error) {
	if k.clock == nil && k.clockErr == nil {
		c, err := k.readBootClock()
		if err != nil {
			k.clockErr = err
		} else {
			k.clock = &c
		}
	}
	if k.clockErr != nil {
		return BootClock{}, k.clockErr
	}
	return *k.clock, nil
}

func (k *Kernel) BootTime() (time.Time, error) {
	c, err := k.BootClock()
	if err != nil {
		return time.Time{}, err
	}
	return c.Boot, nil
}

func (k *Kernel) readBootClock() (BootClock, error) {
	container, at, err := k.timekeeper()
	if err != nil {
		return BootClock{}, err
	}
	c := BootClock{Timekeeper: at}
	real, err := k.Int(k.mem, at, "timekeeper", "offs_real")
	if err != nil {
		return BootClock{}, err
	}
	boot, err := k.Int(k.mem, at, "timekeeper", "offs_boot")
	if err != nil {
		return BootClock{}, err
	}
	c.RealOffset, c.BootOffset = time.Duration(real), time.Duration(boot)
	wall, ok := subtract(real, boot)
	if !ok {
		return BootClock{}, fmt.Errorf("%w: timekeeper at %#x: offs_real %d less offs_boot %d", ErrTimeRange, at, real, boot)
	}
	c.Boot = time.Unix(0, wall).UTC()
	if seq, err := k.Uint(k.mem, container, "seqcount_t", "sequence"); err == nil {
		c.Sequence, c.SequenceRead = seq, true
	}
	if k.Has("timekeeper", "xtime_sec") {
		if s, err := k.Uint(k.mem, at, "timekeeper", "xtime_sec"); err == nil && s <= math.MaxInt64 {
			c.Updated = time.Unix(int64(s), 0).UTC()
		}
	}
	if f, err := k.Member("timekeeper", "wall_to_monotonic"); err == nil {
		if ns, err := k.timespecAt(at + f.Offset); err == nil {
			c.WallChecked, c.WallAgrees = true, ns == -real
		}
	}
	if f, err := k.Member("timekeeper", "monotonic_to_boot"); err == nil {
		if ns, err := k.timespecAt(at + f.Offset); err == nil {
			c.SleepChecked, c.SleepAgrees = true, ns == boot
		}
	}
	return c, nil
}

// S46 C2, C3, C4: the timekeeper's place in its container comes from the
// container's type when the table names one, and from the layout of an
// unnamed container otherwise.
func (k *Kernel) timekeeper() (container, at uint64, err error) {
	var base uint64
	var declared string
	found := false
	for _, name := range timekeeperSymbols {
		if s, err := k.sym.LookupSymbol(name); err == nil {
			base, declared, found = s.Address, s.Type, true
			break
		}
	}
	if !found {
		return 0, 0, ErrNoTimekeeper
	}
	for _, typ := range []string{declared, "tk_data"} {
		if typ == "" {
			continue
		}
		if f, err := k.sym.Field(typ, "timekeeper"); err == nil {
			return base, base + f.Offset, nil
		}
	}
	for _, seq := range []string{"seqcount_raw_spinlock_t", "seqcount_t"} {
		n, err := k.SizeOf(seq)
		if err != nil || n == 0 {
			continue
		}
		align := k.PointerSize()
		return base, base + (n+align-1)/align*align, nil
	}
	return 0, 0, fmt.Errorf("%w: container at %#x has no named type and no sequence counter type", ErrTimekeeperAt, base)
}

func subtract(a, b int64) (int64, bool) {
	d := a - b
	if (b > 0 && d > a) || (b < 0 && d < a) {
		return 0, false
	}
	return d, true
}

func add(a, b int64) (int64, bool) {
	s := a + b
	if (b > 0 && s < a) || (b < 0 && s > a) {
		return 0, false
	}
	return s, true
}

// S46 C7: a timespec64 holds whole seconds and 0 to 999999999 nanoseconds;
// a value whose seconds exceed KTIME_SEC_MAX has no nanosecond form.
func (k *Kernel) timespecAt(addr uint64) (int64, error) {
	sec, err := k.Int(k.mem, addr, "timespec64", "tv_sec")
	if err != nil {
		return 0, err
	}
	nsec, err := k.Int(k.mem, addr, "timespec64", "tv_nsec")
	if err != nil {
		return 0, err
	}
	return timespecNanoseconds(sec, nsec)
}

func timespecNanoseconds(sec, nsec int64) (int64, error) {
	if nsec < 0 || nsec >= nsecPerSec || sec > ktimeSecMax || sec < -ktimeSecMax {
		return 0, fmt.Errorf("%w: timespec %d s %d ns", ErrTimeRange, sec, nsec)
	}
	ns, ok := add(sec*nsecPerSec, nsec)
	if !ok {
		return 0, fmt.Errorf("%w: timespec %d s %d ns", ErrTimeRange, sec, nsec)
	}
	return ns, nil
}

// S46 C8: start_boottime from v6.1 and real_start_time at v4.19 both count
// CLOCK_BOOTTIME nanoseconds of the host, whatever the task's namespace.
func (k *Kernel) CreateTime(t Task) (time.Time, error) {
	boot, err := k.BootClock()
	if err != nil {
		return time.Time{}, err
	}
	member := ""
	for _, m := range []string{"start_boottime", "real_start_time"} {
		if k.Has("task_struct", m) {
			member = m
			break
		}
	}
	if member == "" {
		return time.Time{}, ErrNoStartTime
	}
	since, err := k.Uint(k.in(t), t.Addr, "task_struct", member)
	if err != nil {
		return time.Time{}, err
	}
	wall, ok := add(boot.Boot.UnixNano(), int64(since))
	if since > math.MaxInt64 || !ok {
		return time.Time{}, fmt.Errorf("%w: task at %#x: %s %d", ErrTimeRange, t.Addr, member, since)
	}
	return time.Unix(0, wall).UTC(), nil
}

type TimeNamespace struct {
	Address    uint64
	Inode      uint64
	BootOffset time.Duration
}

// S46 C6: inside a namespace the boot time is the host's less the
// namespace's boottime offset.
func (ns TimeNamespace) BootTime(host time.Time) (time.Time, error) {
	wall, ok := subtract(host.UnixNano(), int64(ns.BootOffset))
	if !ok {
		return time.Time{}, fmt.Errorf("%w: time namespace %d: offset %d", ErrTimeRange, ns.Inode, ns.BootOffset)
	}
	return time.Unix(0, wall).UTC(), nil
}

func (k *Kernel) HasTimeNamespaces() bool { return k.Has("nsproxy", "time_ns") }

// An exiting task has a null nsproxy and holds no namespace; that is held
// false with no error.
func (k *Kernel) TaskTimeNamespace(t Task) (ns TimeNamespace, held bool, err error) {
	if !k.HasTimeNamespaces() {
		return TimeNamespace{}, false, ErrNoTimeNSProxy
	}
	proxy, err := k.Pointer(k.in(t), t.Addr, "task_struct", "nsproxy")
	if err != nil {
		return TimeNamespace{}, false, err
	}
	if proxy == 0 {
		return TimeNamespace{}, false, nil
	}
	at, err := k.Pointer(k.mem, proxy, "nsproxy", "time_ns")
	if err != nil {
		return TimeNamespace{}, false, err
	}
	if at == 0 {
		return TimeNamespace{}, false, fmt.Errorf("linuxobj: nsproxy at %#x: time_ns is null", proxy)
	}
	ns, err = k.ReadTimeNamespace(at)
	return ns, err == nil, err
}

func (k *Kernel) ReadTimeNamespace(at uint64) (TimeNamespace, error) {
	ns := TimeNamespace{Address: at}
	common, err := k.Member("time_namespace", "ns")
	if err != nil {
		return ns, fmt.Errorf("linuxobj: time_namespace.ns: %w", err)
	}
	if ns.Inode, err = k.Uint(k.mem, at+common.Offset, "ns_common", "inum"); err != nil {
		return ns, err
	}
	if ns.Inode == 0 {
		return ns, fmt.Errorf("linuxobj: time_namespace at %#x: inode number is 0", at)
	}
	offsets, err := k.Member("time_namespace", "offsets")
	if err != nil {
		return ns, fmt.Errorf("linuxobj: time_namespace.offsets: %w", err)
	}
	boot, err := k.Member("timens_offsets", "boottime")
	if err != nil {
		return ns, fmt.Errorf("linuxobj: timens_offsets.boottime: %w", err)
	}
	off, err := k.timespecAt(at + offsets.Offset + boot.Offset)
	if err != nil {
		return ns, fmt.Errorf("linuxobj: time_namespace at %#x: boottime offset: %w", at, err)
	}
	ns.BootOffset = time.Duration(off)
	return ns, nil
}
