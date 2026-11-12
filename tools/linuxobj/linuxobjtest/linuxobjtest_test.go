package linuxobjtest

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

// checkLayout holds S80 rule L1: a member lies inside its record (when
// sized is set), a pointer or scalar sits on its natural alignment, and two
// members overlap only when one holds the other, as union or alias members
// do.
func checkLayout(t *testing.T, table *symbols.Table, sized bool, names ...string) {
	t.Helper()
	type span struct {
		name     string
		from, to uint64
	}
	for _, name := range names {
		st, err := table.Struct(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		var spans []span
		for _, f := range st.Fields {
			w, err := table.FieldSize(name, f.Name)
			if err != nil {
				t.Errorf("%s.%s: %v", name, f.Name, err)
				continue
			}
			if sized && f.Offset+w > st.Size {
				t.Errorf("%s.%s ends at %#x, past the record size %#x", name, f.Name, f.Offset+w, st.Size)
			}
			_, recordErr := table.Struct(f.Type.Name)
			scalar := f.Type.IsPointer || !f.Type.IsArray && recordErr != nil
			if scalar && (w == 2 || w == 4 || w == 8) && f.Offset%w != 0 {
				t.Errorf("%s.%s at %#x is not %d-byte aligned", name, f.Name, f.Offset, w)
			}
			spans = append(spans, span{f.Name, f.Offset, f.Offset + w})
		}
		slices.SortFunc(spans, func(a, b span) int {
			if c := cmp.Compare(a.from, b.from); c != 0 {
				return c
			}
			return cmp.Compare(b.to, a.to)
		})
		for i := 1; i < len(spans); i++ {
			a, b := spans[i-1], spans[i]
			if b.from < a.to && b.to > a.to {
				t.Errorf("%s: %s [%#x,%#x) and %s [%#x,%#x) overlap", name, a.name, a.from, a.to, b.name, b.from, b.to)
			}
		}
	}
}

var declared = []string{
	"list_head", "hlist_node", "task_struct", "signal_struct", "cred", "timekeeper", "tk_core_t", "pid", "upid",
	"xa_node", "xarray", "idr", "address_space", "mm_struct", "vm_area_struct", "file", "path", "fs_struct",
	"files_struct", "fdtable", "dentry", "qstr", "inode", "super_block", "vfsmount", "mount", "mnt_namespace",
	"nsproxy", "ns_common", "page", "rb_node", "timespec64", "net", "netns_nf", "net_device", "Qdisc",
	"Qdisc_ops", "in_device", "in_ifaddr", "inet6_dev", "inet6_ifaddr", "socket", "socket_alloc", "sock_common",
	"sock", "inet_sock", "unix_sock", "unix_address", "sockaddr_un", "netlink_sock", "packet_sock", "xdp_sock",
	"sk_filter", "bpf_prog", "bpf_prog_aux", "nf_hook_entry", "nf_hook_ops", "module", "module_kobject",
	"kobject", "kset", "mod_kallsyms", "mod_tree_root", "kernel_symbol", "ftrace_mod_map", "ftrace_mod_func",
	"ftrace_ops", "bpf_ksym",
}

func fullKernel() *Kernel {
	k := NewKernel(1700000000, 0)
	AddFS(k)
	AddNetTypes(k)
	AddKallsymsLists(k, AddModuleTypes(k), false)
	return k
}

func TestEveryDeclaredRecordKeepsLayoutRuleL1(t *testing.T) {
	k := fullKernel()
	checkLayout(t, k.Table, true, declared...)
	AddAreaOperations(k)
	AddExeFile(k)
	AddTimeNamespaceTypes(k)
	checkLayout(t, k.Table, true, "vm_area_struct", "mm_struct", "nsproxy")
	k.AddClockChecks(2, true, true)
	checkLayout(t, k.Table, false, "timekeeper")
}

func TestFileTypesAreOneLayoutInEitherOrder(t *testing.T) {
	a, b := NewKernel(0, 0), NewKernel(0, 0)
	AddFS(a)
	AddNetTypes(a)
	AddNetTypes(b)
	AddFS(b)
	shape := func(k *Kernel, name string) []string {
		st, _ := k.Table.Struct(name)
		var out []string
		for _, f := range st.Fields {
			out = append(out, fmt.Sprintf("%s@%#x", f.Name, f.Offset))
		}
		return out
	}
	for _, name := range []string{"file", "inode", "dentry", "task_struct", "nsproxy", "ns_common"} {
		if x, y := shape(a, name), shape(b, name); !slices.Equal(x, y) {
			t.Errorf("%s: %v one way, %v the other", name, x, y)
		}
	}
}

// decodeKallsyms reads the tables back as kallsyms_expand_symbol and
// kallsyms_sym_address do (kernel/kallsyms.c v6.1).
func decodeKallsyms(t *testing.T, k *Kernel) ([]string, []uint64) {
	t.Helper()
	at := func(name string) uint64 {
		s, err := k.Table.LookupSymbol(name)
		if err != nil {
			t.Fatal(err)
		}
		return s.Address
	}
	read := func(a, n uint64) []byte {
		b, err := k.Mem.ReadAt(a, n)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	n := binary.LittleEndian.Uint32(read(at("kallsyms_num_syms"), 4))
	base := k.Mem.read64(at("kallsyms_relative_base"))
	index, table := read(at("kallsyms_token_index"), 512), at("kallsyms_token_table")
	names, offsets := at("kallsyms_names"), at("kallsyms_offsets")
	var outNames []string
	var outAddrs []uint64
	for i := range uint64(n) {
		l := uint64(read(names, 1)[0])
		names++
		if l&0x80 != 0 {
			l = l&0x7f | uint64(read(names, 1)[0])<<7
			names++
		}
		var name []byte
		for _, tok := range read(names, l) {
			from := table + uint64(binary.LittleEndian.Uint16(index[2*uint64(tok):]))
			name = append(name, bytes.TrimRight(read(from, 2)[:1], "\x00")...)
		}
		names += l
		outNames = append(outNames, string(name))
		off := int32(binary.LittleEndian.Uint32(read(offsets+4*i, 4)))
		addr := uint64(off)
		if off < 0 {
			addr = base - 1 - uint64(int64(off))
		}
		outAddrs = append(outAddrs, addr)
	}
	return outNames, outAddrs
}

func TestKallsymsTablesDecodeAsTheKernelReadsThem(t *testing.T) {
	k := NewKernel(0, 0)
	const base = 0xffffffff81000000
	long := string(bytes.Repeat([]byte("a"), 0x90))
	k.AddKallsyms(base, []KSym{{'T', "_etext", base + 0x1000}, {'T', "_stext", base}, {'t', long, base + 0x10},
		{'A', "fixed_percpu_data", 0x40}})
	names, addrs := decodeKallsyms(t, k)
	wantNames := []string{"Afixed_percpu_data", "T_stext", "t" + long, "T_etext"}
	wantAddrs := []uint64{0x40, base, base + 0x10, base + 0x1000}
	if !slices.Equal(names, wantNames) || !slices.Equal(addrs, wantAddrs) {
		t.Errorf("decoded %q at %#x", names, addrs)
	}
	if s, err := k.Table.LookupSymbol("_etext"); err != nil || s.Address != base+0x1000 {
		t.Errorf("_etext symbol %#x, %v", s.Address, err)
	}
}

// lookupXArray walks a node tree as xas_descend does (lib/xarray.c).
func lookupXArray(k *Kernel, root, index uint64) uint64 {
	entry := k.Mem.read64(root + XArrayXAHead)
	for entry&3 == xaNodeTag {
		node := entry &^ 3
		shift, _ := k.Mem.ReadAt(node+XANodeShift, 1)
		slot := index >> shift[0] % xaSlots
		entry = k.Mem.read64(node + XANodeSlots + 8*slot)
	}
	return entry
}

func TestXArrayEntriesAreFoundByIndex(t *testing.T) {
	for _, entries := range []map[uint64]uint64{{1: Base + 0x100, 63: Base + 0x200}, {2: Base + 0x300, 130: Base + 0x400}} {
		k := NewKernel(0, 0)
		AddPIDTypes(k)
		root := k.Alloc(xarraySize)
		k.XArray(root, entries)
		for i, want := range entries {
			if got := lookupXArray(k, root, i); got != want {
				t.Errorf("index %d = %#x, want %#x", i, got, want)
			}
		}
	}
}

func TestTasksAndThreadsAreCircularLists(t *testing.T) {
	k := NewKernel(0, 0)
	a, b := k.AddTask(Task{PID: 1, TGID: 1}), k.AddTask(Task{PID: 2, TGID: 1})
	k.LinkTasks(a)
	k.LinkThreads(a, b)
	if k.Mem.read64(k.InitTask+TaskTasks) != a+TaskTasks || k.Mem.read64(a+TaskTasks) != k.InitTask+TaskTasks {
		t.Error("init_task and the task are not one list")
	}
	head := k.Mem.read64(a+TaskSignal) + SignalThreadHead
	if k.Mem.read64(b+TaskSignal)+SignalThreadHead != head || k.Mem.read64(b+TaskThreadNode) != head {
		t.Error("the thread is not on the leader's thread_head")
	}
}

func TestMemoryRefusesHolesAsUnmapped(t *testing.T) {
	m := NewMemory()
	m.Write(Base+pageSize-2, []byte("abcd"))
	if b, err := m.ReadAt(Base+pageSize-2, 4); err != nil || string(b) != "abcd" {
		t.Fatalf("across a page: %q, %v", b, err)
	}
	if _, err := m.ReadAt(Base+8*pageSize, 1); !errors.Is(err, memory.ErrUnmapped) {
		t.Errorf("a hole: %v", err)
	}
	if _, err := (&Flat{Buf: make([]byte, 4)}).ReadAt(2, 3); !errors.Is(err, memory.ErrOutOfBounds) {
		t.Errorf("past a flat image: %v", err)
	}
}

func FuzzMemoryWriteReadsBack(f *testing.F) {
	f.Add(uint64(Base), []byte("x"))
	f.Add(uint64(pageSize-1), []byte("across"))
	f.Fuzz(func(t *testing.T, at uint64, data []byte) {
		if len(data) == 0 || len(data) > 3*pageSize || at+uint64(len(data))-1 < at {
			return
		}
		m := NewMemory()
		m.Write(at, data)
		got, err := m.ReadAt(at, uint64(len(data)))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("read back %x, %v", got, err)
		}
	})
}
