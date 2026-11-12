package tracingftrace

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

type shape struct {
	k                 *linuxkern.Kernel
	r                 linuxwalk.Reader
	head, end         uint64
	fn, next, flags   symbols.IntField
	trampoline        *symbols.IntField
	filters           bool
	funcHash          symbols.IntField
	filterHash        symbols.IntField
	notraceHash       symbols.IntField
	sizeBits, buckets symbols.IntField
	count, hashFlags  symbols.IntField
	ip                symbols.IntField
	headSize          uint64
	first             symbols.IntField
	most, mostBuckets int
}

func newShape(k *linuxkern.Kernel) (*shape, error) {
	s := &shape{k: k, r: k.Walker()}
	lim := k.Context().Bounds()
	s.most, s.mostBuckets = lim.MaxListEntries, lim.MaxTableEntries
	var err1, err2 error
	s.head, err1 = k.Symbol("ftrace_ops_list")
	s.end, err2 = k.Symbol("ftrace_list_end")
	if err1 != nil || err2 != nil {
		return nil, ErrNoOpsList
	}
	for _, m := range []struct {
		name string
		to   *symbols.IntField
	}{{"func", &s.fn}, {"next", &s.next}, {"flags", &s.flags}} {
		f, err := symbols.ResolveIntField(k.Sym, "ftrace_ops", m.name)
		if err != nil {
			return nil, fmt.Errorf("tracingftrace: ftrace_ops.%s: %w: %w", m.name, ErrUnsupported, err)
		}
		*m.to = f
	}
	if f, err := symbols.ResolveIntField(k.Sym, "ftrace_ops", "trampoline"); err == nil {
		s.trampoline = &f
	}
	s.filters = s.resolveFilters() == nil
	return s, nil
}

// S15b 4.1 step 3: without every filter member the kernel was built without
// dynamic ftrace, where an ops traces every function.
func (s *shape) resolveFilters() error {
	t := s.k.Sym
	for _, m := range []struct {
		typ, name string
		to        *symbols.IntField
	}{
		{"ftrace_ops", "func_hash", &s.funcHash},
		{"ftrace_ops_hash", "filter_hash", &s.filterHash},
		{"ftrace_ops_hash", "notrace_hash", &s.notraceHash},
		{"ftrace_hash", "size_bits", &s.sizeBits},
		{"ftrace_hash", "buckets", &s.buckets},
		{"ftrace_hash", "count", &s.count},
		{"ftrace_hash", "flags", &s.hashFlags},
		{"ftrace_func_entry", "ip", &s.ip},
	} {
		f, err := symbols.ResolveIntField(t, m.typ, m.name)
		if err != nil {
			return err
		}
		*m.to = f
	}
	if _, err := t.Field("ftrace_func_entry", "hlist"); err != nil {
		return err
	}
	n, err := s.k.TypeSize("hlist_head")
	if err != nil {
		return err
	}
	first, err := symbols.ResolveIntField(t, "hlist_head", "first")
	if err != nil {
		return err
	}
	if n == 0 || first.Offset+first.Width > n {
		return fmt.Errorf("tracingftrace: hlist_head of %d bytes: %w", n, ErrUnsupported)
	}
	s.headSize, s.first = n, first
	return nil
}

func (s *shape) read(f symbols.IntField, at uint64) (uint64, error) {
	return f.Read(s.k.Mem, at)
}

func (s *shape) pointer(f symbols.IntField, at uint64) (uint64, error) {
	v, err := f.Read(s.k.Mem, at)
	return v & s.k.Mask, err
}

type ops struct {
	at, fn, flags, trampoline uint64
}

type opsWalk struct {
	ops  []ops
	stop string
	at   uint64
}

func (s *shape) opsList() (opsWalk, error) {
	var w opsWalk
	cur, err := s.k.ReadPointer(s.head)
	if err != nil {
		return w, ErrNoOpsList
	}
	seen := map[uint64]bool{}
	for cur != s.end {
		switch {
		case cur == 0:
			w.stop = "the next pointer is null before ftrace_list_end"
		case seen[cur]:
			w.stop = "the list comes back to an ops already walked"
		case len(w.ops) >= s.most:
			w.stop = "the walk reached Limits.MaxListEntries"
		}
		if w.stop != "" {
			w.at = cur
			return w, nil
		}
		o := ops{at: cur}
		var err1, err2, err3 error
		o.fn, err1 = s.pointer(s.fn, cur)
		o.flags, err2 = s.read(s.flags, cur)
		next, err3 := s.pointer(s.next, cur)
		if err := errors.Join(err1, err2, err3); err != nil {
			w.stop, w.at = "the ops does not read: "+err.Error(), cur
			return w, nil
		}
		if s.trampoline != nil {
			o.trampoline, _ = s.pointer(*s.trampoline, cur)
		}
		seen[cur] = true
		w.ops = append(w.ops, o)
		cur = next
	}
	return w, nil
}

type brokenChain struct {
	bucket uint64
	walk   chainEnd
}

type chainEnd struct {
	Entries int
	At      uint64
	End     linuxwalk.End
}

type hash struct {
	err    error
	empty  bool
	count  uint64
	ips    []uint64
	unread int
	capped bool
	broken []brokenChain
}

type filter struct {
	filterAt, notraceAt uint64
	filter, notrace     hash
}

func (s *shape) filterOf(at uint64) filter {
	var f filter
	fh, err := s.pointer(s.funcHash, at)
	if err == nil && fh == 0 {
		err = errNullFuncHash
	}
	if err != nil {
		f.filter.err, f.notrace.err = err, err
		return f
	}
	if f.filterAt, err = s.pointer(s.filterHash, fh); err != nil {
		f.filter.err = err
	} else {
		f.filter = s.hash(f.filterAt)
	}
	if f.notraceAt, err = s.pointer(s.notraceHash, fh); err != nil {
		f.notrace.err = err
	} else {
		f.notrace = s.hash(f.notraceAt)
	}
	return f
}

var (
	errNullFuncHash = errors.New("tracingftrace: func_hash is null")
	errSizeBits     = errors.New("tracingftrace: size_bits gives more buckets than the pointer width or Limits.MaxTableEntries allow")
)

// S15b F5: FTRACE_HASH_FL_MOD keeps a hash with no entries from being empty.
const hashFlagMod = 1

func (s *shape) hash(at uint64) hash {
	var h hash
	if at == 0 {
		h.empty = true
		return h
	}
	bits, err1 := s.read(s.sizeBits, at)
	buckets, err2 := s.pointer(s.buckets, at)
	count, err3 := s.read(s.count, at)
	flags, err4 := s.read(s.hashFlags, at)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		h.err = err
		return h
	}
	h.count = count
	if count == 0 && flags&hashFlagMod == 0 {
		h.empty = true
		return h
	}
	if bits >= 8*s.k.PtrSize || uint64(1)<<bits > uint64(s.mostBuckets) {
		h.err = fmt.Errorf("%w: size_bits %d", errSizeBits, bits)
		return h
	}
	n := uint64(1) << bits
	// Heads are read a page at a time so that a large bucket count over
	// memory that does not read fails at once, and null heads cost no walk.
	perPage := max(pageBytes/s.headSize, 1)
	for start := uint64(0); start < n; start += perPage {
		count := min(perPage, n-start)
		block, err := s.k.Read(buckets+start*s.headSize, count*s.headSize)
		if err != nil {
			h.err = err
			return h
		}
		for j := range count {
			first, err := s.first.Decode(block[j*s.headSize:])
			if err != nil {
				h.err = err
				return h
			}
			if first == 0 {
				continue
			}
			s.bucket(&h, start+j, buckets+(start+j)*s.headSize)
			if h.err != nil || h.capped {
				return h
			}
		}
	}
	return h
}

const pageBytes = 4096

func (s *shape) bucket(h *hash, i, head uint64) {
	l, err := s.r.HList(head, "ftrace_func_entry", "hlist")
	if err != nil {
		h.err = err
		return
	}
	for _, e := range l.Entries {
		if len(h.ips)+h.unread >= s.most {
			h.capped = true
			return
		}
		ip, err := s.pointer(s.ip, e)
		if err != nil {
			h.unread++
			continue
		}
		h.ips = append(h.ips, ip)
	}
	if l.Broken() {
		h.broken = append(h.broken, brokenChain{bucket: i, walk: chainEnd{Entries: len(l.Entries), At: l.At, End: l.End}})
	}
}

type version struct{ major, minor int }

func (v version) before(w version) bool {
	return v.major < w.major || v.major == w.major && v.minor < w.minor
}

var (
	v4_19 = version{4, 19}
	v4_20 = version{4, 20}
	v6_1  = version{6, 1}
	v6_14 = version{6, 14}
	v6_17 = version{6, 17}
)

type flagName struct {
	bit      int
	name     string
	from, to version
}

// S15b F8: a name holds from the first checked tag that has it. Bit 4 means
// the opposite at v4.19 and from v6.1, and no tag between them was checked,
// so neither name is given there.
var flagNames = []flagName{
	{0, "ENABLED", v4_19, version{}}, {1, "DYNAMIC", v4_19, version{}}, {2, "SAVE_REGS", v4_19, version{}},
	{3, "SAVE_REGS_IF_SUPPORTED", v4_19, version{}}, {4, "RECURSION_SAFE", v4_19, v4_20},
	{4, "RECURSION", v6_1, version{}}, {5, "STUB", v4_19, version{}}, {6, "INITIALIZED", v4_19, version{}},
	{7, "DELETED", v4_19, version{}}, {8, "ADDING", v4_19, version{}}, {9, "REMOVING", v4_19, version{}},
	{10, "MODIFYING", v4_19, version{}}, {11, "ALLOC_TRAMP", v4_19, version{}}, {12, "IPMODIFY", v4_19, version{}},
	{13, "PID", v4_19, version{}}, {14, "RCU", v4_19, version{}}, {15, "TRACE_ARRAY", v4_19, version{}},
	{16, "PERMANENT", v6_1, version{}}, {17, "DIRECT", v6_1, version{}}, {18, "SUBOP", v6_14, version{}},
	{19, "GRAPH", v6_17, version{}},
}

func parseRelease(release string) (version, bool) {
	var v version
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return v, false
	}
	minor := parts[1]
	if i := strings.IndexFunc(minor, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minor = minor[:i]
	}
	var err1, err2 error
	v.major, err1 = strconv.Atoi(parts[0])
	v.minor, err2 = strconv.Atoi(minor)
	return v, err1 == nil && err2 == nil && v.major >= 0 && v.minor >= 0
}

// Outside the checked releases a bit is named only when every checked tag
// that has it gives it the same name.
func bitName(bit int, v version, known bool) string {
	name, count := "", 0
	for _, f := range flagNames {
		if f.bit != bit {
			continue
		}
		count++
		if known && !v.before(f.from) && (f.to == version{} || v.before(f.to)) {
			return f.name
		}
		name = f.name
	}
	if known || count != 1 {
		return ""
	}
	return name
}

func FlagNames(bits uint64, release string) string {
	v, known := parseRelease(release)
	if known && v.before(v4_19) {
		known = false
	}
	var names []string
	for i := range 64 {
		if bits&(1<<i) == 0 {
			continue
		}
		if name := bitName(i, v, known); name != "" {
			names = append(names, name)
		} else {
			names = append(names, fmt.Sprintf("bit %d", i))
		}
	}
	return strings.Join(names, ",")
}
