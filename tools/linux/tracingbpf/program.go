package tracingbpf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxkern"
)

// S15a B9 at v6.17; each older tag's list is a prefix of this one.
var progTypes = [...]string{
	"BPF_PROG_TYPE_UNSPEC", "BPF_PROG_TYPE_SOCKET_FILTER", "BPF_PROG_TYPE_KPROBE", "BPF_PROG_TYPE_SCHED_CLS",
	"BPF_PROG_TYPE_SCHED_ACT", "BPF_PROG_TYPE_TRACEPOINT", "BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_PERF_EVENT",
	"BPF_PROG_TYPE_CGROUP_SKB", "BPF_PROG_TYPE_CGROUP_SOCK", "BPF_PROG_TYPE_LWT_IN", "BPF_PROG_TYPE_LWT_OUT",
	"BPF_PROG_TYPE_LWT_XMIT", "BPF_PROG_TYPE_SOCK_OPS", "BPF_PROG_TYPE_SK_SKB", "BPF_PROG_TYPE_CGROUP_DEVICE",
	"BPF_PROG_TYPE_SK_MSG", "BPF_PROG_TYPE_RAW_TRACEPOINT", "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
	"BPF_PROG_TYPE_LWT_SEG6LOCAL", "BPF_PROG_TYPE_LIRC_MODE2", "BPF_PROG_TYPE_SK_REUSEPORT",
	"BPF_PROG_TYPE_FLOW_DISSECTOR", "BPF_PROG_TYPE_CGROUP_SYSCTL", "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
	"BPF_PROG_TYPE_CGROUP_SOCKOPT", "BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_STRUCT_OPS", "BPF_PROG_TYPE_EXT",
	"BPF_PROG_TYPE_LSM", "BPF_PROG_TYPE_SK_LOOKUP", "BPF_PROG_TYPE_SYSCALL", "BPF_PROG_TYPE_NETFILTER",
}

const (
	tagBytes  = 8
	nameBytes = 16
)

type field struct {
	symbols.IntField
	ok bool
}

type shape struct {
	k                            *linuxkern.Kernel
	typ, aux                     symbols.IntField
	attach, length, jitedLen, fn field
	jited                        field
	tag                          uint64
	hasTag                       bool
	auxID, auxProg, auxLoad      field
	name                         uint64
	nameLen                      uint64
	hasName                      bool
	typeNames, attachNames       map[int64]string
}

func newShape(k *linuxkern.Kernel) (*shape, error) {
	s := &shape{k: k, nameLen: nameBytes}
	var err error
	if s.typ, err = symbols.ResolveIntField(k.Sym, "bpf_prog", "type"); err != nil {
		return nil, fmt.Errorf("tracingbpf: bpf_prog.type: %w: %w", ErrUnsupported, err)
	}
	if s.aux, err = symbols.ResolveIntField(k.Sym, "bpf_prog", "aux"); err != nil {
		return nil, fmt.Errorf("tracingbpf: bpf_prog.aux: %w: %w", ErrUnsupported, err)
	}
	s.attach = optional(k, "bpf_prog", "expected_attach_type")
	s.length = optional(k, "bpf_prog", "len")
	s.jitedLen = optional(k, "bpf_prog", "jited_len")
	s.jited = optional(k, "bpf_prog", "jited")
	s.fn = optional(k, "bpf_prog", "bpf_func")
	if f, err := k.Sym.Field("bpf_prog", "tag"); err == nil && f.Type.ArrayLength == tagBytes {
		s.tag, s.hasTag = f.Offset, true
	}
	s.auxID = optional(k, "bpf_prog_aux", "id")
	s.auxProg = optional(k, "bpf_prog_aux", "prog")
	s.auxLoad = optional(k, "bpf_prog_aux", "load_time")
	if f, err := k.Sym.Field("bpf_prog_aux", "name"); err == nil && f.Type.ArrayLength > 0 {
		s.name, s.nameLen, s.hasName = f.Offset, f.Type.ArrayLength, true
	}
	s.typeNames = enumNames(k.Sym, "bpf_prog_type")
	if s.typeNames == nil {
		s.typeNames = map[int64]string{}
		for v, n := range progTypes {
			s.typeNames[int64(v)] = n
		}
	}
	s.attachNames = enumNames(k.Sym, "bpf_attach_type")
	return s, nil
}

func optional(k *linuxkern.Kernel, typ, member string) field {
	f, err := symbols.ResolveIntField(k.Sym, typ, member)
	return field{IntField: f, ok: err == nil}
}

func enumNames(t symbols.SymbolTable, name string) map[int64]string {
	det, ok := t.(symbols.DeterministicLookup)
	if !ok {
		return nil
	}
	ty, err := det.LookupType(name)
	if err != nil || ty.Kind != symbols.TypeKindEnum || len(ty.Enum) == 0 {
		return nil
	}
	out := make(map[int64]string, len(ty.Enum))
	for _, e := range ty.Enum {
		if _, dup := out[e.Value]; !dup {
			out[e.Value] = e.Name
		}
	}
	return out
}

type decoded struct {
	Program
	auxErr       error
	backLink     uint64
	auxID        uint64
	unterminated bool
}

var errNullAux = errors.New("tracingbpf: aux pointer is null")

func (s *shape) read(at, id uint64) (decoded, error) {
	mem := s.k.Mem
	d := decoded{Program: Program{Address: at, ID: id}}
	typ, err := s.typ.Read(mem, at)
	if err != nil {
		return d, err
	}
	aux, err := s.aux.Read(mem, at)
	if err != nil {
		return d, err
	}
	d.TypeValue = int64(typ)
	d.Type = s.typeNames[d.TypeValue]
	if v, ok := s.value(s.attach, at); ok {
		d.AttachTypeValue = int64(v)
		d.AttachType = s.attachNames[d.AttachTypeValue]
	}
	d.Instructions, _ = s.value(s.length, at)
	d.JITedSize, _ = s.value(s.jitedLen, at)
	jited, _ := s.value(s.jited, at)
	d.JITed = jited&1 == 1
	if fn, ok := s.value(s.fn, at); ok {
		d.FuncAddress = fn & s.k.Mask
	}
	if s.hasTag {
		if b, err := s.k.Read(at+s.tag, tagBytes); err == nil {
			d.Tag = hex.EncodeToString(b)
		}
	}
	d.AuxAddress = aux & s.k.Mask
	d.auxErr = s.readAux(&d)
	return d, nil
}

func (s *shape) value(f field, at uint64) (uint64, bool) {
	if !f.ok {
		return 0, false
	}
	v, err := f.Read(s.k.Mem, at)
	return v, err == nil
}

func (s *shape) readAux(d *decoded) error {
	aux := d.AuxAddress
	if aux == 0 {
		return errNullAux
	}
	mem := s.k.Mem
	if s.auxID.ok {
		v, err := s.auxID.Read(mem, aux)
		if err != nil {
			return err
		}
		d.auxID = v
	}
	if s.auxProg.ok {
		v, err := s.auxProg.Read(mem, aux)
		if err != nil {
			return err
		}
		d.backLink = v & s.k.Mask
	}
	if s.auxLoad.ok {
		v, err := s.auxLoad.Read(mem, aux)
		if err != nil {
			return err
		}
		if v <= math.MaxInt64 {
			d.LoadedAfterBoot = time.Duration(v)
		}
	}
	if s.hasName {
		b, err := s.k.Read(aux+s.name, s.nameLen)
		if err != nil {
			return err
		}
		if n := bytes.IndexByte(b, 0); n >= 0 {
			d.Name = string(b[:n])
		} else {
			d.unterminated = true
		}
	}
	d.AuxRead = true
	d.Linked = !s.auxProg.ok || d.backLink == d.Address
	d.IDMatches = !s.auxID.ok || d.auxID == d.ID
	return nil
}
