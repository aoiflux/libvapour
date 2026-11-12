package linuxobjtest

import (
	"encoding/binary"
	"fmt"
	"math"
	"slices"

	"github.com/aoiflux/libvapour/symbols"
)

type KSym struct {
	Type    byte
	Name    string
	Address uint64
}

// The section bounds the S38 reader takes from the symbol table rather than
// from the compressed names.
var kallsymsBoundaries = map[string]bool{"_stext": true, "_etext": true, "_sinittext": true, "_einittext": true, "_end": true}

// AddKallsyms writes the compressed kernel symbol tables of kernel/kallsyms.c
// v6.1 with base-relative, absolute-percpu offsets. Every token is one
// printable byte, so a name compresses to itself; a record is the type
// letter then the name, its length in one byte, or two when it is 0x80 or
// more (kallsyms_expand_symbol). A symbol of type 0 has an empty record.
func (k *Kernel) AddKallsyms(base uint64, syms []KSym) {
	sorted := slices.Clone(syms)
	slices.SortStableFunc(sorted, func(a, b KSym) int {
		switch {
		case a.Address < b.Address:
			return -1
		case a.Address > b.Address:
			return 1
		}
		return 0
	})
	put := func(name string, data []byte) {
		a := k.Alloc(uint64(len(data)) + 8)
		k.Mem.Write(a, data)
		k.Table.AddSymbol(symbols.Symbol{Name: name, Address: a})
	}
	put("kallsyms_num_syms", binary.LittleEndian.AppendUint32(nil, uint32(len(sorted))))
	put("kallsyms_relative_base", binary.LittleEndian.AppendUint64(nil, base))

	const tokens = 256
	index := make([]byte, 2*tokens)
	var table []byte
	for c := range tokens {
		binary.LittleEndian.PutUint16(index[2*c:], uint16(len(table)))
		if c >= ' ' && c <= '~' {
			table = append(table, byte(c))
		}
		table = append(table, 0)
	}
	put("kallsyms_token_index", index)
	put("kallsyms_token_table", table)

	var names, offsets []byte
	for _, s := range sorted {
		var record []byte
		if s.Type != 0 {
			record = append([]byte{s.Type}, s.Name...)
		}
		if n := len(record); n < 0x80 {
			names = append(names, byte(n))
		} else {
			names = append(names, 0x80|byte(n&0x7f), byte(n>>7))
		}
		names = append(names, record...)
		offsets = binary.LittleEndian.AppendUint32(offsets, uint32(kallsymsOffset(s, base)))
	}
	put("kallsyms_names", names)
	put("kallsyms_offsets", offsets)
	for _, s := range sorted {
		if kallsymsBoundaries[s.Name] {
			k.Table.AddSymbol(symbols.Symbol{Name: s.Name, Address: s.Address})
		}
	}
}

// kallsyms_sym_address reads a negative offset as base - 1 - offset and a
// non-negative one as the address itself.
func kallsymsOffset(s KSym, base uint64) int32 {
	off := int64(s.Address)
	if s.Address >= base {
		off = -1 - int64(s.Address-base)
	}
	if off < math.MinInt32 || off > math.MaxInt32 {
		panic(fmt.Sprintf("linuxobjtest: %s at %#x is too far from base %#x for kallsyms", s.Name, s.Address, base))
	}
	return int32(off)
}
