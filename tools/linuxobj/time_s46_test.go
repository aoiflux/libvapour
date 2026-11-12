package linuxobj_test

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func fixtureKernel(t *testing.T, k *lt.Kernel) *linuxobj.Kernel {
	t.Helper()
	ctx, _ := k.Context(nil)
	return linuxobj.New(ctx)
}

func TestBootTimeIsOffsRealLessOffsBoot(t *testing.T) {
	k := lt.NewKernel(1787405196, 396665099)
	c, err := fixtureKernel(t, k).BootClock()
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(1787405196, 396665099).UTC()
	if !c.Boot.Equal(want) || c.Boot.Location() != time.UTC {
		t.Errorf("boot %s, want %s in UTC", c.Boot, want)
	}
	if c.BootOffset != 5*time.Second || c.WallChecked || c.SleepChecked || !c.Consistent() || c.Updating() {
		t.Errorf("clock %+v: want offs_boot 5 s and no checks available", c)
	}
}

func TestBootClockChecksAgainstTheTimespecCopies(t *testing.T) {
	for _, c := range []struct {
		name               string
		seq                uint32
		wall, sleep        bool
		consistent, update bool
	}{
		{"agreeing", 10, true, true, true, false},
		{"wall_to_monotonic off by 1 ns", 10, false, true, false, false},
		{"monotonic_to_boot off by 1 s", 10, true, false, false, false},
		{"odd sequence", 11, true, true, true, true},
	} {
		k := lt.NewKernel(1700000000, 999999999)
		k.AddClockChecks(c.seq, c.wall, c.sleep)
		got, err := fixtureKernel(t, k).BootClock()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !got.WallChecked || !got.SleepChecked || got.Consistent() != c.consistent || got.Updating() != c.update {
			t.Errorf("%s: %+v", c.name, got)
		}
		if got.Sequence != uint64(c.seq) || !got.SequenceRead {
			t.Errorf("%s: sequence %d", c.name, got.Sequence)
		}
		if want := time.Unix(1700000000+5+600, 0).UTC(); !got.Updated.Equal(want) {
			t.Errorf("%s: xtime_sec %s, want %s", c.name, got.Updated, want)
		}
	}
}

type clockTable struct {
	mem *lt.Memory
	tab *symbols.Table
	at  uint64
}

func newClockTable(symbol, declared string, typed bool, seqType string) clockTable {
	c := clockTable{mem: lt.NewMemory(), tab: symbols.NewTable("s46clock", 8), at: lt.Base}
	f := func(name string, off uint64, typ string) symbols.Field {
		return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: typ}}
	}
	c.tab.AddStruct(symbols.StructType{Name: "timekeeper", Size: 0x118, Fields: []symbols.Field{
		f("offs_real", 0x58, "long long int"), f("offs_boot", 0x60, "long long int"),
	}})
	if typed {
		c.tab.AddStruct(symbols.StructType{Name: "tk_data", Size: 0x240, Fields: []symbols.Field{
			f("seq", 0, "seqcount_raw_spinlock_t"), f("timekeeper", 8, "timekeeper"),
		}})
	}
	if seqType != "" {
		c.tab.AddStruct(symbols.StructType{Name: seqType, Size: 4})
	}
	c.tab.AddSymbol(symbols.Symbol{Name: symbol, Address: c.at, Type: declared})
	c.mem.Map(c.at, 0x1000)
	return c
}

func (c clockTable) kernel() *linuxobj.Kernel {
	return linuxobj.New(tools.Context{Memory: c.mem, Symbols: c.tab, Profile: profiles.LinuxX64Profile{}})
}

func TestTheTimekeeperIsFoundInEachContainerShape(t *testing.T) {
	for _, c := range []struct {
		name     string
		table    clockTable
		wantAt   uint64
		wantFail error
	}{
		{"v6.17 timekeeper_data of tk_data", newClockTable("timekeeper_data", "", true, ""), 8, nil},
		{"v6.14 tk_core of tk_data", newClockTable("tk_core", "", true, ""), 8, nil},
		{"v6.1 unnamed container after seqcount_raw_spinlock_t", newClockTable("tk_core", "", false, "seqcount_raw_spinlock_t"), 8, nil},
		{"v4.19 unnamed container after seqcount_t", newClockTable("tk_core", "", false, "seqcount_t"), 8, nil},
		{"no placement", newClockTable("tk_core", "", false, ""), 0, linuxobj.ErrTimekeeperAt},
		{"no symbol", newClockTable("other", "", true, ""), 0, linuxobj.ErrNoTimekeeper},
	} {
		at := c.table.at + c.wantAt
		c.table.mem.U64(at+0x58, uint64(1787406664114798359))
		c.table.mem.U64(at+0x60, uint64(2*time.Second))
		got, err := c.table.kernel().BootClock()
		if c.wantFail != nil {
			if !errors.Is(err, c.wantFail) {
				t.Errorf("%s: %v, want %v", c.name, err, c.wantFail)
			}
			continue
		}
		if err != nil || got.Timekeeper != at || !got.Boot.Equal(time.Unix(0, 1787406662114798359)) {
			t.Errorf("%s: %+v, %v", c.name, got, err)
		}
	}
}

func TestBootTimeOutOfRangeIsRefused(t *testing.T) {
	c := newClockTable("tk_core", "", true, "")
	c.mem.U64(c.at+8+0x58, uint64(1)<<63)
	c.mem.U64(c.at+8+0x60, 1)
	if _, err := c.kernel().BootTime(); !errors.Is(err, linuxobj.ErrTimeRange) {
		t.Errorf("offs_real at the minimum less 1: %v", err)
	}
}

func TestCreateTimeIsBootPlusTheTaskStart(t *testing.T) {
	k := lt.NewKernel(1700000000, 500000000)
	task := k.AddTask(lt.Task{PID: 10, TGID: 10, Comm: "sh", StartNS: 1_600_000_123})
	late := k.AddTask(lt.Task{PID: 11, TGID: 11, Comm: "x", StartNS: math.MaxUint64})
	kk := fixtureKernel(t, k)
	got, err := kk.CreateTime(linuxobj.Task{Addr: task})
	if want := time.Unix(1700000002, 100000123).UTC(); err != nil || !got.Equal(want) {
		t.Errorf("create %s, %v; want %s", got, err, want)
	}
	if _, err := kk.CreateTime(linuxobj.Task{Addr: late}); !errors.Is(err, linuxobj.ErrTimeRange) {
		t.Errorf("start past the int64 range: %v", err)
	}
}

func TestCreateTimeReadsRealStartTimeBeforeV55(t *testing.T) {
	k := lt.NewKernel(1600000000, 0)
	task := k.AddTask(lt.Task{PID: 2, TGID: 2, Comm: "a", StartNS: 7e9})
	st, _ := k.Table.Struct("task_struct")
	for i := range st.Fields {
		if st.Fields[i].Name == "start_boottime" {
			st.Fields[i].Name = "real_start_time"
		}
	}
	k.Table.AddStruct(st)
	got, err := fixtureKernel(t, k).CreateTime(linuxobj.Task{Addr: task})
	if err != nil || !got.Equal(time.Unix(1600000007, 0)) {
		t.Errorf("create %s, %v", got, err)
	}
	for i := range st.Fields {
		if st.Fields[i].Name == "real_start_time" {
			st.Fields[i].Name = "other"
		}
	}
	k.Table.AddStruct(st)
	if _, err := fixtureKernel(t, k).CreateTime(linuxobj.Task{Addr: task}); !errors.Is(err, linuxobj.ErrNoStartTime) {
		t.Errorf("no start member: %v", err)
	}
}

func TestTimeNamespacesShiftTheBootTime(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	lt.AddTimeNamespaceTypes(k)
	host := k.AddTimeNamespace(0xEFFFFFFA, 0, 0)
	shifted := k.AddTimeNamespace(0xF0000123, 86400, 250000000)
	a := k.AddTask(lt.Task{PID: 1, TGID: 1, Comm: "init"})
	b := k.AddTask(lt.Task{PID: 2, TGID: 2, Comm: "inner"})
	c := k.AddTask(lt.Task{PID: 3, TGID: 3, Comm: "exiting"})
	k.SetTaskTimeNS(a, host)
	k.SetTaskTimeNS(b, shifted)
	k.Mem.U64(c+lt.TaskNsproxy, 0)
	kk := fixtureKernel(t, k)
	boot, _ := kk.BootTime()
	if !kk.HasTimeNamespaces() {
		t.Fatal("no time namespaces")
	}
	ns, held, err := kk.TaskTimeNamespace(linuxobj.Task{Addr: a})
	if err != nil || !held || ns.Inode != 0xEFFFFFFA || ns.BootOffset != 0 || ns.Address != host {
		t.Errorf("host namespace %+v %t %v", ns, held, err)
	}
	ns, _, _ = kk.TaskTimeNamespace(linuxobj.Task{Addr: b})
	at, err := ns.BootTime(boot)
	if want := time.Unix(1700000000-86400, -250000000).UTC(); err != nil || !at.Equal(want) {
		t.Errorf("shifted boot %s, %v; want %s", at, err, want)
	}
	if _, held, err := kk.TaskTimeNamespace(linuxobj.Task{Addr: c}); held || err != nil {
		t.Errorf("null nsproxy: held %t, %v", held, err)
	}
	k.Mem.U64(shifted+lt.S46TimeNSOffsets+lt.S46OffsetsBoottime+8, 1e9)
	if _, err := kk.ReadTimeNamespace(shifted); !errors.Is(err, linuxobj.ErrTimeRange) {
		t.Errorf("tv_nsec of a whole second: %v", err)
	}
	k.Mem.U32(host+lt.S46TimeNSCommon+0x10, 0)
	if _, err := kk.ReadTimeNamespace(host); err == nil {
		t.Error("an inode number of 0 reads")
	}
	k.SetTaskTimeNS(a, 0)
	if _, _, err := kk.TaskTimeNamespace(linuxobj.Task{Addr: a}); err == nil {
		t.Error("a null time_ns reads")
	}
}

func TestNoTimeNamespacesWithoutTheMember(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	task := k.AddTask(lt.Task{PID: 1, TGID: 1, Comm: "init"})
	kk := fixtureKernel(t, k)
	if kk.HasTimeNamespaces() {
		t.Fatal("time namespaces without nsproxy.time_ns")
	}
	if _, _, err := kk.TaskTimeNamespace(linuxobj.Task{Addr: task}); !errors.Is(err, linuxobj.ErrNoTimeNSProxy) {
		t.Errorf("%v", err)
	}
}
