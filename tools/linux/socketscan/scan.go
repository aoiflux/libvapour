package socketscan

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linux/socketlist"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.socket.scan"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Scan Linux physical memory for socks, live or freed, by their destructor and by the files that hold them",
		},
		RunAny,
	)
}

type FoundBy uint8

const (
	FoundByDestructor FoundBy = 1 << iota
	FoundByFile
)

type Link string

const (
	LinkBack      Link = "socket points back"
	LinkOrphan    Link = "no socket"
	LinkElsewhere Link = "socket points elsewhere"
	LinkUnread    Link = "socket does not read"
	LinkUnchecked Link = "not translated"
)

type Socket struct {
	SockPhysical  uint64
	Found         FoundBy
	Link          Link
	SocketAddress uint64
	socketlist.Decoded
}

var (
	ErrNoPhysicalMemory = errors.New("socketscan: session has no physical memory to scan")
	ErrNoNeedles        = errors.New("socketscan: symbol table has none of the sock destructors or socket_file_ops")
)

const (
	anyFamily = 0
	afUnix    = 1
	afInet    = 2
	afInet6   = 10
	afNetlink = 16
	afPacket  = 17
)

// S62 SS1, SS2: each destructor and the families whose socks it is set on.
var destructors = []struct {
	symbol   string
	families []uint64
}{
	{"sock_def_destruct", []uint64{anyFamily}},
	{"inet_sock_destruct", []uint64{afInet, afInet6}},
	{"inet6_sock_destruct", []uint64{afInet6}},
	{"udp_destruct_sock", []uint64{afInet, afInet6}},
	{"udpv6_destruct_sock", []uint64{afInet6}},
	{"unix_sock_destructor", []uint64{afUnix}},
	{"netlink_sock_destruct", []uint64{afNetlink}},
	{"packet_sock_destruct", []uint64{afPacket}},
}

const fileOperations = "socket_file_ops"

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Socket, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	phys := ctx.PhysicalMemory()
	if phys == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysicalMemory)
	}
	k := linuxobj.New(ctx)
	s, err := newScan(ctx, k, phys)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	cov := s.sweep()
	if err := cov.Incomplete(); err != nil {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: strict mode: physical memory scan: %w", Name, err)
		}
		ctx.AddDiagnostic("%s: physical memory scan: %v", Name, err)
	}
	out := s.rows()
	s.report()
	return out, nil
}

type needle struct {
	value     uint64
	file      bool
	families  []uint64
	symbol    string
	hits      int
	rejected  int
	accepted  int
	byFamily  int
	byType    int
	byReadErr int
}

type candidate struct {
	found  FoundBy
	link   Link
	socket uint64
}

type translator interface {
	Translate(virtualAddress uint64) (uint64, error)
}

type scan struct {
	ctx     tools.Context
	k       *linuxobj.Kernel
	phys    memory.MemoryReader
	tr      translator
	dec     *socketlist.Decoder
	needles []*needle
	width   uint64

	destructAt, socketAt, fileOpAt, commonAt uint64

	found     map[uint64]*candidate
	fileMiss  map[string]int
	decodeErr int
	firstErr  string
}

func newScan(ctx tools.Context, k *linuxobj.Kernel, phys memory.MemoryReader) (*scan, error) {
	dec, err := socketlist.NewDecoder(k)
	if err != nil {
		return nil, err
	}
	s := &scan{ctx: ctx, k: k, phys: phys, dec: dec, width: k.PointerSize(), found: map[uint64]*candidate{},
		fileMiss: map[string]int{}}
	for _, m := range []struct {
		typ, member string
		to          *uint64
	}{{"sock", "sk_destruct", &s.destructAt}, {"sock", "sk_socket", &s.socketAt}, {"file", "f_op", &s.fileOpAt},
		{"sock", "__sk_common", &s.commonAt}} {
		f, err := k.Member(m.typ, m.member)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", m.typ, m.member, err)
		}
		*m.to = f.Offset
	}
	var missing []string
	for _, d := range destructors {
		if sym, err := k.Symbol(d.symbol); err == nil {
			s.needles = append(s.needles, &needle{value: k.Canonical(sym.Address), families: d.families, symbol: d.symbol})
		} else {
			missing = append(missing, d.symbol)
		}
	}
	if sym, err := k.Symbol(fileOperations); err == nil {
		s.needles = append(s.needles, &needle{value: k.Canonical(sym.Address), file: true, symbol: fileOperations})
	} else {
		missing = append(missing, fileOperations)
	}
	if len(s.needles) == 0 {
		return nil, ErrNoNeedles
	}
	if len(missing) > 0 {
		ctx.AddDiagnostic("%s: not in the symbol table, so not searched for: %s", Name, strings.Join(missing, ", "))
	}
	if tr, ok := ctx.Memory.(translator); ok {
		s.tr = tr
	} else {
		ctx.AddDiagnostic("%s: the kernel layer does not translate, so socks are not followed back from their socket and files are not followed", Name)
	}
	return s, nil
}

// S62 SS4: a pointer member sits at an offset that is a multiple of the
// pointer size in an object at least that aligned, so only aligned words are
// compared.
func (s *scan) sweep() memory.Coverage {
	const step = 1 << 20
	w := s.width
	return memory.ScanWindows(s.phys, step, w-1, func(off uint64, window []byte) bool {
		start := (w - off%w) % w
		for i := start; i+w <= uint64(len(window)) && i < step; i += w {
			var v uint64
			if w == 8 {
				v = binary.LittleEndian.Uint64(window[i:])
			} else {
				v = uint64(binary.LittleEndian.Uint32(window[i:]))
			}
			for _, n := range s.needles {
				if v == n.value {
					n.hits++
					s.hit(n, off+i)
					break
				}
			}
		}
		return false
	})
}

func (s *scan) hit(n *needle, at uint64) {
	if n.file {
		if at >= s.fileOpAt {
			s.fromFile(at - s.fileOpAt)
		}
		return
	}
	if at < s.destructAt {
		n.rejected++
		return
	}
	base := at - s.destructAt
	if !s.plausible(n, base) {
		n.rejected++
		return
	}
	n.accepted++
	c := s.candidate(base)
	c.found |= FoundByDestructor
	if c.link == "" {
		c.link, c.socket = s.linkBack(base)
	}
}

func (s *scan) candidate(base uint64) *candidate {
	c, ok := s.found[base]
	if !ok {
		c = &candidate{}
		s.found[base] = c
	}
	return c
}

// S62 SS2, SS3: the family must be one the destructor is set on, and the
// type one socket(2) can leave in sk_type.
func (s *scan) plausible(n *needle, base uint64) bool {
	k := s.k
	family, err := k.Uint(s.phys, base+s.commonAt, "sock_common", "skc_family")
	if err != nil {
		n.byReadErr++
		return false
	}
	typ, err := k.Uint(s.phys, base, "sock", "sk_type")
	if err != nil {
		n.byReadErr++
		return false
	}
	if !familyAllowed(n.families, family) {
		n.byFamily++
		return false
	}
	if strings.HasPrefix(socketlist.TypeName(typ), "SOCK ") {
		n.byType++
		return false
	}
	return true
}

func familyAllowed(allowed []uint64, family uint64) bool {
	if family == 0 || strings.HasPrefix(socketlist.FamilyName(family), "AF ") {
		return false
	}
	return slices.Contains(allowed, anyFamily) || slices.Contains(allowed, family)
}

// S62 SS5: sock_graft links the two ways and sock_orphan clears sk_socket, so
// a sock whose socket does not point back has outlived it.
func (s *scan) linkBack(base uint64) (Link, uint64) {
	k := s.k
	socket, err := k.Pointer(s.phys, base, "sock", "sk_socket")
	if err != nil {
		return LinkUnread, 0
	}
	if k.Masked(socket) == 0 {
		return LinkOrphan, 0
	}
	if s.tr == nil {
		return LinkUnchecked, k.Masked(socket)
	}
	sk, err := k.Pointer(k.Memory(), socket, "socket", "sk")
	if err != nil || k.Masked(sk) == 0 {
		return LinkUnread, k.Masked(socket)
	}
	pa, err := s.tr.Translate(sk)
	if err != nil {
		return LinkUnread, k.Masked(socket)
	}
	if pa != base {
		return LinkElsewhere, k.Masked(socket)
	}
	return LinkBack, k.Masked(socket)
}

// S62 SS6: a file whose f_op is socket_file_ops holds its struct socket in
// private_data, and that socket's sock points back at it.
func (s *scan) fromFile(file uint64) {
	k := s.k
	if s.tr == nil {
		return
	}
	socket, err := k.Pointer(s.phys, file, "file", "private_data")
	if err != nil || k.Masked(socket) == 0 {
		s.fileMiss["private_data null or unread"]++
		return
	}
	sk, err := k.Pointer(k.Memory(), socket, "socket", "sk")
	if err != nil || k.Masked(sk) == 0 {
		s.fileMiss["socket.sk null or unread"]++
		return
	}
	back, err := k.Pointer(k.Memory(), sk, "sock", "sk_socket")
	if err != nil || k.Masked(back) != k.Masked(socket) {
		s.fileMiss["sock.sk_socket does not lead back"]++
		return
	}
	pa, err := s.tr.Translate(sk)
	if err != nil {
		s.fileMiss["sock does not translate"]++
		return
	}
	c := s.candidate(pa)
	c.found |= FoundByFile
	c.link, c.socket = LinkBack, k.Masked(socket)
}

func (s *scan) rows() []Socket {
	bases := make([]uint64, 0, len(s.found))
	for b := range s.found {
		bases = append(bases, b)
	}
	slices.Sort(bases)
	out := make([]Socket, 0, len(bases))
	for _, b := range bases {
		c := s.found[b]
		d, err := s.dec.Decode(s.phys, b)
		if err != nil {
			if s.decodeErr == 0 {
				s.firstErr = fmt.Sprintf("sock at physical %#x: %v", b, err)
			}
			s.decodeErr++
			continue
		}
		out = append(out, Socket{SockPhysical: b, Found: c.found, Link: c.link, SocketAddress: c.socket, Decoded: d})
	}
	slices.SortStableFunc(out, func(a, b Socket) int { return cmp.Compare(a.SockPhysical, b.SockPhysical) })
	return out
}

func (s *scan) report() {
	for _, n := range s.needles {
		if n.file || n.rejected == 0 {
			continue
		}
		s.ctx.AddDiagnostic("%s: %s: %d of %d words are not a sock (%d family, %d type, %d unread)", Name, n.symbol,
			n.rejected, n.hits, n.byFamily, n.byType, n.byReadErr)
	}
	for _, why := range slices.Sorted(maps.Keys(s.fileMiss)) {
		s.ctx.AddDiagnostic("%s: %d files holding %s are passed over: %s", Name, s.fileMiss[why], fileOperations, why)
	}
	if s.decodeErr > 0 {
		s.ctx.AddDiagnostic("%s: %d socks do not decode; first: %s", Name, s.decodeErr, s.firstErr)
	}
	s.dec.Report(s.ctx.AddDiagnostic, Name)
}
