package socketlist

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	taskFiles = 0x110

	filesFdt   = 0x20
	fdtMax     = 0x00
	fdtFD      = 0x08
	fileSize   = 0x100
	fileOp     = 0x28
	filePriv   = 0x30
	socketFile = 0x10
	socketSk   = 0x18
	allocInode = 0x40
	allocSize  = 0xc0
	inodeIno   = 0x40

	netNs      = 0x10
	nsInum     = 0x10
	netDevHead = 0x30
	netSize    = 0x100
	devName    = 0x00
	devList    = 0x10
	devIndex   = 0x20
	devSize    = 0x100

	skcDaddr    = 0x00
	skcRcvSaddr = 0x04
	skcDport    = 0x0c
	skcNum      = 0x0e
	skcFamily   = 0x10
	skcState    = 0x12
	skcNet      = 0x30
	skcV6Daddr  = 0x38
	skcV6Saddr  = 0x48
	skFilter    = 0x98
	skSocket    = 0xa8
	skType      = 0xb0
	skProtocol  = 0xb2
	sockSize    = 0x100
	familySize  = 0x140

	inetSport   = 0x100
	unixAddr    = 0x100
	unixPeer    = 0x108
	uaLen       = 0x04
	uaName      = 0x08
	sunPath     = 0x02
	nlPortid    = 0x100
	nlDstPortid = 0x104
	nlDstGroup  = 0x108
	nlGroups    = 0x110
	pktIfindex  = 0x100
	pktNum      = 0x104
	xdpDev      = 0x100
	xdpQueue    = 0x108
	xdpState    = 0x10c
	vsLocal     = 0x100
	vsRemote    = 0x110
	svmPort     = 0x04
	svmCid      = 0x08

	sfProg    = 0x18
	progAux   = 0x38
	progOrig  = 0x40
	fprogLen  = 0x00
	auxID     = 0x20
	auxName   = 0x30
	initInum  = 4026531840
	otherInum = 4026532200
)

type fixture struct {
	k       *lt.Kernel
	ops     uint64
	other   uint64
	initNet uint64
	netB    uint64
	tasks   []uint64
}

func field(name string, off uint64, typ symbols.TypeRef) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: typ}
}

func named(name string) symbols.TypeRef { return symbols.TypeRef{Name: name} }

func pointer(name string) symbols.TypeRef {
	return symbols.TypeRef{Name: name, IsPointer: true, Element: &symbols.TypeRef{Name: name}}
}

func chars(n uint64) symbols.TypeRef {
	return symbols.TypeRef{Name: "char", IsArray: true, ArrayLength: n, Element: &symbols.TypeRef{Name: "char"}}
}

type layout struct {
	noVsock     bool
	noNetNSType bool
	noFileOps   bool
}

func newFixture(l layout) *fixture {
	k := lt.NewKernel(1700000000, 0)
	t := k.Table
	u8, u16, u32, u64 := named("unsigned char"), named("short unsigned int"), named("unsigned int"),
		named("long long unsigned int")
	task, _ := t.Struct("task_struct")
	task.Fields = append(task.Fields, field("files", taskFiles, pointer("files_struct")))
	t.AddStruct(task)
	filep := pointer("file")
	t.AddStruct(symbols.StructType{Name: "files_struct", Size: 0x40, Fields: []symbols.Field{
		field("fdt", filesFdt, pointer("fdtable"))}})
	t.AddStruct(symbols.StructType{Name: "fdtable", Size: 0x20, Fields: []symbols.Field{
		field("max_fds", fdtMax, u32), field("fd", fdtFD, symbols.TypeRef{Name: "file", IsPointer: true, Element: &filep})}})
	t.AddStruct(symbols.StructType{Name: "file", Size: fileSize, Fields: []symbols.Field{
		field("f_op", fileOp, pointer("file_operations")), field("private_data", filePriv, pointer("void"))}})
	t.AddStruct(symbols.StructType{Name: "socket", Size: 0x30, Fields: []symbols.Field{
		field("state", 0, u32), field("file", socketFile, pointer("file")), field("sk", socketSk, pointer("sock"))}})
	t.AddStruct(symbols.StructType{Name: "inode", Size: 0x80, Fields: []symbols.Field{field("i_ino", inodeIno, u64)}})
	t.AddStruct(symbols.StructType{Name: "socket_alloc", Size: allocSize, Fields: []symbols.Field{
		field("socket", 0, named("socket")), field("vfs_inode", allocInode, named("inode"))}})
	if l.noNetNSType {
		t.AddStruct(symbols.StructType{Name: "possible_net_t", Size: 0})
	} else {
		t.AddStruct(symbols.StructType{Name: "possible_net_t", Size: 8, Fields: []symbols.Field{field("net", 0, pointer("net"))}})
	}
	t.AddStruct(symbols.StructType{Name: "ns_common", Size: 0x18, Fields: []symbols.Field{field("inum", nsInum, u32)}})
	t.AddStruct(symbols.StructType{Name: "net", Size: netSize, Fields: []symbols.Field{
		field("ns", netNs, named("ns_common")), field("dev_base_head", netDevHead, named("list_head"))}})
	t.AddStruct(symbols.StructType{Name: "net_device", Size: devSize, Fields: []symbols.Field{
		field("name", devName, chars(16)), field("dev_list", devList, named("list_head")),
		field("ifindex", devIndex, named("int"))}})
	t.AddStruct(symbols.StructType{Name: "in6_addr", Size: 16})
	t.AddStruct(symbols.StructType{Name: "sock_common", Size: 0x88, Fields: []symbols.Field{
		field("skc_daddr", skcDaddr, u32), field("skc_rcv_saddr", skcRcvSaddr, u32),
		field("skc_dport", skcDport, u16), field("skc_num", skcNum, u16), field("skc_family", skcFamily, u16),
		field("skc_state", skcState, u8), field("skc_net", skcNet, named("possible_net_t")),
		field("skc_v6_daddr", skcV6Daddr, named("in6_addr")), field("skc_v6_rcv_saddr", skcV6Saddr, named("in6_addr"))}})
	t.AddStruct(symbols.StructType{Name: "sock", Size: sockSize, Fields: []symbols.Field{
		field("__sk_common", 0, named("sock_common")), field("sk_filter", skFilter, pointer("sk_filter")),
		field("sk_socket", skSocket, pointer("socket")), field("sk_type", skType, u16),
		field("sk_protocol", skProtocol, u16)}})
	family := func(name string, fields ...symbols.Field) {
		t.AddStruct(symbols.StructType{Name: name, Size: familySize,
			Fields: append([]symbols.Field{field("sk", 0, named("sock"))}, fields...)})
	}
	family("inet_sock", field("inet_sport", inetSport, u16))
	family("unix_sock", field("addr", unixAddr, pointer("unix_address")), field("peer", unixPeer, pointer("sock")))
	t.AddStruct(symbols.StructType{Name: "unix_address", Size: 8, Fields: []symbols.Field{
		field("refcnt", 0, u32), field("len", uaLen, named("int")),
		field("name", uaName, symbols.TypeRef{Name: "sockaddr_un", IsArray: true, Element: &symbols.TypeRef{Name: "sockaddr_un"}})}})
	t.AddStruct(symbols.StructType{Name: "sockaddr_un", Size: 110, Fields: []symbols.Field{
		field("sun_family", 0, u16), field("sun_path", sunPath, chars(108))}})
	family("netlink_sock", field("portid", nlPortid, u32), field("dst_portid", nlDstPortid, u32),
		field("dst_group", nlDstGroup, u32), field("groups", nlGroups, pointer("long unsigned int")))
	family("packet_sock", field("ifindex", pktIfindex, named("int")), field("num", pktNum, u16))
	t.AddEnum(symbols.EnumType{Name: "xsk_state", Size: 4, Values: []symbols.EnumValue{
		{Name: "XSK_READY", Value: 0}, {Name: "XSK_BOUND", Value: 1}, {Name: "XSK_UNBOUND", Value: 2}}})
	family("xdp_sock", field("dev", xdpDev, pointer("net_device")), field("queue_id", xdpQueue, u16),
		field("state", xdpState, named("xsk_state")))
	if !l.noVsock {
		family("vsock_sock", field("local_addr", vsLocal, named("sockaddr_vm")), field("remote_addr", vsRemote, named("sockaddr_vm")))
	}
	t.AddStruct(symbols.StructType{Name: "sockaddr_vm", Size: 16, Fields: []symbols.Field{
		field("svm_family", 0, u16), field("svm_port", svmPort, u32), field("svm_cid", svmCid, u32)}})
	t.AddStruct(symbols.StructType{Name: "sk_filter", Size: 0x20, Fields: []symbols.Field{field("prog", sfProg, pointer("bpf_prog"))}})
	t.AddStruct(symbols.StructType{Name: "bpf_prog", Size: 0x48, Fields: []symbols.Field{
		field("aux", progAux, pointer("bpf_prog_aux")), field("orig_prog", progOrig, pointer("sock_fprog_kern"))}})
	t.AddStruct(symbols.StructType{Name: "sock_fprog_kern", Size: 0x10, Fields: []symbols.Field{field("len", fprogLen, u16)}})
	t.AddStruct(symbols.StructType{Name: "bpf_prog_aux", Size: 0x40, Fields: []symbols.Field{
		field("id", auxID, u32), field("name", auxName, chars(16))}})

	f := &fixture{k: k, ops: k.Alloc(0x100), other: k.Alloc(0x100)}
	if !l.noFileOps {
		t.AddSymbol(symbols.Symbol{Name: "socket_file_ops", Address: f.ops, Type: "file_operations"})
	}
	f.initNet = f.namespace(initInum)
	f.netB = f.namespace(otherInum)
	t.AddSymbol(symbols.Symbol{Name: "init_net", Address: f.initNet, Type: "net"})
	return f
}

func (f *fixture) namespace(inum uint32) uint64 {
	net := f.k.Alloc(netSize)
	f.k.Mem.U32(net+netNs+nsInum, inum)
	f.k.Circle(net + netDevHead)
	return net
}

func (f *fixture) devices(net uint64, names ...string) []uint64 {
	heads := []uint64{net + netDevHead}
	var out []uint64
	for i, n := range names {
		d := f.k.Alloc(devSize)
		f.k.Mem.Write(d+devName, append([]byte(n), 0))
		f.k.Mem.U32(d+devIndex, uint32(i+1))
		heads = append(heads, d+devList)
		out = append(out, d)
	}
	f.k.Circle(heads...)
	return out
}

func (f *fixture) u16(at uint64, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	f.k.Mem.Write(at, b[:])
}

func (f *fixture) be16(at uint64, v uint16) { f.k.Mem.Write(at, []byte{byte(v >> 8), byte(v)}) }

type spec struct {
	family, typ, proto uint16
	state              uint8
	net                uint64
	ino                uint64
}

type made struct{ sk, socket, file uint64 }

func (f *fixture) sock(s spec) made {
	m := f.k.Mem
	alloc := f.k.Alloc(allocSize)
	sk := f.k.Alloc(familySize)
	file := f.k.Alloc(fileSize)
	m.U64(file+fileOp, f.ops)
	m.U64(file+filePriv, alloc)
	m.U64(alloc+socketFile, file)
	m.U64(alloc+socketSk, sk)
	ino := s.ino
	if ino == 0 {
		ino = 1000 + (sk>>6)&0xffff
	}
	m.U64(alloc+allocInode+inodeIno, ino)
	f.u16(sk+skcFamily, s.family)
	m.Write(sk+skcState, []byte{s.state})
	net := s.net
	if net == 0 {
		net = f.initNet
	}
	m.U64(sk+skcNet, net)
	m.U64(sk+skSocket, alloc)
	f.u16(sk+skType, s.typ)
	f.u16(sk+skProtocol, s.proto)
	return made{sk: sk, socket: alloc, file: file}
}

func (f *fixture) plainFile() uint64 {
	file := f.k.Alloc(fileSize)
	f.k.Mem.U64(file+fileOp, f.other)
	return file
}

func (f *fixture) unixName(sk uint64, name []byte) {
	a := f.k.Alloc(0x80)
	f.k.Mem.U32(a+uaLen, uint32(sunPath+len(name)))
	f.k.Mem.Write(a+uaName+sunPath, name)
	f.k.Mem.U64(sk+unixAddr, a)
}

func (f *fixture) files(slots uint32, files ...uint64) uint64 {
	k := f.k
	fs, fdt := k.Alloc(0x40), k.Alloc(0x20)
	fd := k.Alloc(uint64(slots) * 8)
	for i, file := range files {
		k.Mem.U64(fd+uint64(i)*8, file)
	}
	k.Mem.U32(fdt+fdtMax, slots)
	k.Mem.U64(fdt+fdtFD, fd)
	k.Mem.U64(fs+filesFdt, fdt)
	return fs
}

func (f *fixture) task(pid, tgid int32, comm string, files uint64) uint64 {
	t := f.k.AddTask(lt.Task{PID: pid, TGID: tgid, Comm: comm})
	f.k.Mem.U64(t+taskFiles, files)
	return t
}

func (f *fixture) link() { f.k.LinkTasks(f.tasks...) }

func newKernel(f *fixture) *linuxobj.Kernel {
	ctx, _ := f.k.Context(nil)
	return linuxobj.New(ctx)
}
