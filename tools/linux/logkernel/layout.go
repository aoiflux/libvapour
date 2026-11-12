package logkernel

import (
	"fmt"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools/linuxkern"
)

type field struct {
	off    uint64
	bitOff uint8
	bitLen uint8
	length uint64
}

type layoutSource struct {
	k        *linuxkern.Kernel
	physical memory.MemoryReader
	bounds   limits.Limits
	scanned  bool
	tables   []autoload.VMCoreInfo
}

func (s *layoutSource) vmcoreinfo(key string) (uint64, bool) {
	if !s.scanned {
		s.scanned = true
		if s.physical != nil {
			if scan, err := autoload.ScanVMCoreInfo(s.physical, s.bounds); err == nil {
				s.tables = scan.Tables
			}
		}
	}
	for _, t := range s.tables {
		e, ok := t.Lookup(key)
		if !ok || e.Cut || e.Int == nil || e.Int.Sign() < 0 || !e.Int.IsUint64() {
			continue
		}
		return e.Int.Uint64(), true
	}
	return 0, false
}

func (s *layoutSource) member(typ, name string) (field, bool) {
	if m, err := s.k.Member(typ, name); err == nil {
		t := m.Field.Type
		return field{off: m.Offset, bitOff: t.BitOffset, bitLen: t.BitLength, length: t.ArrayLength}, true
	}
	if v, ok := s.vmcoreinfo("OFFSET(" + typ + "." + name + ")"); ok {
		return field{off: v}, true
	}
	return field{}, false
}

func (s *layoutSource) size(typ string) (uint64, bool) {
	if st, err := s.k.Sym.Struct(typ); err == nil && st.Size > 0 {
		return st.Size, true
	}
	return s.vmcoreinfo("SIZE(" + typ + ")")
}

func (s *layoutSource) length(typ, name, key string) (uint64, bool) {
	f, ok := s.member(typ, name)
	if !ok {
		return 0, false
	}
	if f.length > 0 {
		return f.length, true
	}
	return s.vmcoreinfo("LENGTH(" + key + ")")
}

type resolver struct {
	s       *layoutSource
	missing []string
}

func (r *resolver) off(typ, name string) uint64 {
	f, ok := r.s.member(typ, name)
	if !ok {
		r.missing = append(r.missing, typ+"."+name)
	}
	return f.off
}

func (r *resolver) size(typ string) uint64 {
	n, ok := r.s.size(typ)
	if !ok {
		r.missing = append(r.missing, "size of "+typ)
	}
	return n
}

func (r *resolver) err() error {
	if len(r.missing) == 0 {
		return nil
	}
	return fmt.Errorf("%v: %w", r.missing, ErrLayout)
}

type bitField struct {
	off   uint64
	shift uint8
	width uint8
}

func (b bitField) of(v byte) uint8 {
	return v >> b.shift & (1<<b.width - 1)
}

// priority places facility, flags and level from the table, or, when the
// table lacks them, after the u16 member they follow in every source layout.
func (s *layoutSource) priority(typ string, anchorOff uint64) (facility uint64, flags, level bitField) {
	facility, flags, level = anchorOff+2, bitField{off: anchorOff + 3, width: 5}, bitField{off: anchorOff + 3, shift: 5, width: 3}
	fa, okA := s.member(typ, "facility")
	fl, okF := s.member(typ, "flags")
	lv, okL := s.member(typ, "level")
	if !okA || !okF || !okL || !inByte(fl) || !inByte(lv) {
		return
	}
	return fa.off, bitField{off: fl.off + uint64(fl.bitOff/8), shift: fl.bitOff % 8, width: fl.bitLen},
		bitField{off: lv.off + uint64(lv.bitOff/8), shift: lv.bitOff % 8, width: lv.bitLen}
}

func inByte(f field) bool {
	return f.bitLen > 0 && f.bitOff%8+f.bitLen <= 8
}
