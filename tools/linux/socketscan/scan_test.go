package socketscan

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	directMap  = uint64(0xffff888000000000)
	text0      = uint64(0xffffffff81000000)
	filePriv   = 0x30
	socketFile = 0x10
	physSize   = 0x400000
)

type physical struct{ m *lt.Memory }

func (p physical) ReadAt(off, size uint64) ([]byte, error) {
	if off+size < off || off+size > p.Size() {
		return nil, memory.ErrOutOfBounds
	}
	out := make([]byte, 0, size)
	for size > 0 {
		n := min(0x1000-off%0x1000, size)
		b, err := p.m.ReadAt(off+directMap, n)
		if err != nil {
			b = make([]byte, n)
		}
		out = append(out, b...)
		off, size = off+n, size-n
	}
	return out, nil
}

func (p physical) Size() uint64 { return physSize }

type kernelSpace struct{ *lt.Memory }

func (s kernelSpace) Translate(va uint64) (uint64, error) {
	if _, err := s.ReadAt(va, 1); err != nil || va < directMap {
		return 0, memory.ErrUnmapped
	}
	return va - directMap, nil
}

var destructorAt = map[string]uint64{}

type fixture struct {
	k *lt.Kernel
	n *lt.Net
}

func newFixture() *fixture {
	k := lt.NewKernel(1700000000, 0)
	n := lt.AddNetTypes(k)
	net := n.AddNamespace(4026531840)
	nsproxy := k.Alloc(0x40)
	k.Mem.U64(k.InitTask+lt.TaskNsproxy, nsproxy)
	k.Mem.U64(nsproxy+lt.NetNsproxyNetNS, net)
	ptr := func(name string) symbols.TypeRef {
		return symbols.TypeRef{Name: name, IsPointer: true, Element: &symbols.TypeRef{Name: name}}
	}
	k.Table.AddStruct(symbols.StructType{Name: "file", Size: lt.NetFileSize, Fields: []symbols.Field{
		{Name: "f_path", Offset: lt.NetFilePath, Type: symbols.TypeRef{Name: "path"}},
		{Name: "f_op", Offset: lt.NetFileOp, Type: ptr("file_operations")},
		{Name: "private_data", Offset: filePriv, Type: ptr("void")},
	}})
	k.Table.AddStruct(symbols.StructType{Name: "socket", Size: lt.NetSocketSize, Fields: []symbols.Field{
		{Name: "state", Offset: lt.NetSocketState, Type: symbols.TypeRef{Name: "unsigned int"}},
		{Name: "file", Offset: socketFile, Type: ptr("file")},
		{Name: "sk", Offset: lt.NetSocketSk, Type: ptr("sock")},
	}})
	for i, d := range destructors {
		at := text0 + 0x100*uint64(i)
		destructorAt[d.symbol] = at
		k.Table.AddSymbol(symbols.Symbol{Name: d.symbol, Address: at})
	}
	return &fixture{k: k, n: n}
}

func (f *fixture) sock(family, typ uint16, destructor string, withFile bool) (sock, socket uint64) {
	m := f.k.Mem
	sock, file := f.n.AddSock(lt.Sock{Size: lt.ChildSockSize, Family: family, Type: typ, State: 7, Ino: 9})
	socket = f.read(sock + lt.SkSocket)
	m.U64(socket+socketFile, file)
	m.U64(file+filePriv, socket)
	if !withFile {
		m.U64(file+lt.NetFileOp, f.n.OtherFileOps)
	}
	if destructor != "" {
		m.U64(sock+lt.SkDestruct, destructorAt[destructor])
	}
	return sock, socket
}

func (f *fixture) read(addr uint64) uint64 {
	b, _ := f.k.Mem.ReadAt(addr, 8)
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func (f *fixture) context(options map[string]any) (ctxOpts map[string]any) {
	if options == nil {
		options = map[string]any{}
	}
	options["physical_memory"] = physical{f.k.Mem}
	return options
}

func TestRunFindsSocksTheTwoWaysAndSaysHowTheyLink(t *testing.T) {
	f := newFixture()
	unix, unixSocket := f.sock(1, 1, "unix_sock_destructor", true)
	orphan, _ := f.sock(2, 1, "inet_sock_destruct", false)
	f.k.Mem.U64(orphan+lt.SkSocket, 0)
	stale, _ := f.sock(10, 2, "udpv6_destruct_sock", false)
	_, other := f.sock(1, 1, "", false)
	f.k.Mem.U64(stale+lt.SkSocket, other)
	qrtr, _ := f.sock(42, 2, "sock_def_destruct", false)
	f.sock(2, 1, "unix_sock_destructor", false)
	f.sock(1, 9, "unix_sock_destructor", false)

	ctx, diags := f.k.Context(f.context(nil))
	ctx.Memory = kernelSpace{f.k.Mem}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	type got struct {
		at     uint64
		found  FoundBy
		link   Link
		family string
		socket uint64
	}
	var have []got
	for _, r := range rows {
		have = append(have, got{r.SockPhysical, r.Found, r.Link, r.Family, r.SocketAddress})
	}
	const mask48 = uint64(1)<<48 - 1
	want := []got{
		{unix - directMap, FoundByDestructor | FoundByFile, LinkBack, "AF_UNIX", unixSocket & mask48},
		{orphan - directMap, FoundByDestructor, LinkOrphan, "AF_INET", 0},
		{stale - directMap, FoundByDestructor, LinkElsewhere, "AF_INET6", other & mask48},
		{qrtr - directMap, FoundByDestructor, LinkBack, "AF_QIPCRTR", f.read(qrtr+lt.SkSocket) & mask48},
	}
	if !slices.Equal(have, want) {
		t.Errorf("got\n%+v\nwant\n%+v\ndiagnostics %q", have, want, *diags)
	}
	if rows[0].LocalAddress.Value != "" || rows[3].Coverage != "family not decoded" {
		t.Errorf("decoded %+v / %+v", rows[0].Decoded, rows[3].Decoded)
	}
	joined := strings.Join(*diags, "\n")
	for _, w := range []string{"unix_sock_destructor: 2 of 3 words are not a sock (1 family, 1 type, 0 unread)"} {
		if !strings.Contains(joined, w) {
			t.Errorf("diagnostics lack %q: %q", w, *diags)
		}
	}
}

func TestAFileWhoseSockDoesNotLeadBackIsPassedOver(t *testing.T) {
	f := newFixture()
	sock, _ := f.sock(1, 1, "", true)
	f.k.Mem.U64(sock+lt.SkSocket, 0)
	ctx, diags := f.k.Context(f.context(nil))
	ctx.Memory = kernelSpace{f.k.Mem}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "1 files holding socket_file_ops are passed over: sock.sk_socket does not lead back") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestWithoutATranslatorOnlyDestructorsAreFollowed(t *testing.T) {
	f := newFixture()
	unix, _ := f.sock(1, 1, "unix_sock_destructor", true)
	ctx, diags := f.k.Context(f.context(nil))
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SockPhysical != unix-directMap || rows[0].Found != FoundByDestructor ||
		rows[0].Link != LinkUnchecked {
		t.Errorf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "does not translate") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestRunRefuses(t *testing.T) {
	f := newFixture()
	ctx, _ := f.k.Context(nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Errorf("no physical memory: %v", err)
	}
	k := lt.NewKernel(1700000000, 0)
	lt.AddNetTypes(k)
	tab := symbols.NewTable("bare", 8)
	for _, name := range []string{"sock", "sock_common", "file", "socket"} {
		st, _ := k.Table.Struct(name)
		tab.AddStruct(st)
	}
	ctx, _ = k.Context(map[string]any{"physical_memory": physical{k.Mem}})
	ctx.Symbols = tab
	if _, err := Run(ctx); !errors.Is(err, ErrNoNeedles) {
		t.Errorf("no needles: %v", err)
	}
}
