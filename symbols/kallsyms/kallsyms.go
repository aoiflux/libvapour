// Package kallsyms decodes the symbol table a Linux kernel links into itself
// (scripts/kallsyms.c writes it, kernel/kallsyms.c reads it), starting from the
// table addresses VMCOREINFO publishes.
package kallsyms

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols/autoload"
)

type Seeds struct {
	NumSyms, Names, TokenTable, TokenIndex, Offsets, RelativeBase uint64
	Stext                                                         uint64
}

var (
	ErrNoSeeds     = errors.New("kallsyms: vmcoreinfo does not locate the table")
	ErrCount       = errors.New("kallsyms: symbol count is out of range")
	ErrUnreadable  = errors.New("kallsyms: table does not read")
	ErrRecord      = errors.New("kallsyms: name record is malformed")
	ErrAddressRule = errors.New("kallsyms: _stext does not decide how offsets are read")
	ErrOrder       = errors.New("kallsyms: table is not in address order")
)

func SeedsFromVMCoreInfo(table autoload.VMCoreInfo) (Seeds, error) {
	var s Seeds
	fields := []struct {
		symbol string
		into   *uint64
	}{
		{"kallsyms_num_syms", &s.NumSyms},
		{"kallsyms_names", &s.Names},
		{"kallsyms_token_table", &s.TokenTable},
		{"kallsyms_token_index", &s.TokenIndex},
		{"kallsyms_offsets", &s.Offsets},
		{"kallsyms_relative_base", &s.RelativeBase},
		{"_stext", &s.Stext},
	}
	var absent []string
	for _, f := range fields {
		e, ok := table.Lookup("SYMBOL(" + f.symbol + ")")
		if !ok || e.Cut || e.Int == nil || !e.Int.IsUint64() {
			absent = append(absent, f.symbol)
			continue
		}
		*f.into = e.Int.Uint64()
	}
	if len(absent) > 0 {
		return Seeds{}, fmt.Errorf("%w: vmcoreinfo at 0x%x gives no address for %v", ErrNoSeeds, table.Offset, absent)
	}
	return s, nil
}

type AddressRule int

const (
	RuleAbsolutePercpu AddressRule = iota + 1
	RuleRelative
)

func (r AddressRule) String() string {
	switch r {
	case RuleAbsolutePercpu:
		return "absolute per-CPU"
	case RuleRelative:
		return "relative"
	}
	return fmt.Sprintf("address rule %d", int(r))
}

// The address of a stored offset under each rule of kallsyms_sym_address.
func (r AddressRule) address(offset int32, base uint64) uint64 {
	if r == RuleAbsolutePercpu {
		if offset >= 0 {
			return uint64(offset)
		}
		return base - 1 - uint64(int64(offset))
	}
	return base + uint64(uint32(offset))
}

// Size is the distance to the next higher address in the table, as
// get_symbol_pos computes it; 0 when there is none or it does not fit.
type Symbol struct {
	Name          string
	Type          byte
	Address       uint64
	Size          int64
	EncodedLength int
	Offset        int32
}

// Upper-case letters are global symbols; u, v and w are the unique-global and
// weak bindings, which are not local either.
func (s Symbol) Global() bool {
	return s.Type >= 'A' && s.Type <= 'Z' || s.Type == 'u' || s.Type == 'v' || s.Type == 'w'
}

type Table struct {
	Symbols      []Symbol
	Rule         AddressRule
	RelativeBase uint64
}

func (t Table) Lookup(name string) (Symbol, bool) {
	for _, s := range t.Symbols {
		if s.Name == name {
			return s, true
		}
	}
	return Symbol{}, false
}

const (
	tokenCount    = 256
	pageBytes     = 4096
	namesReadSize = 64 << 10
	lengthMore    = 0x80
	lengthLow     = 0x7f
)

// Every record's place in kallsyms_names follows from the lengths of all the
// records before it, so one unreadable record ends the decode.
func Decode(kernel memory.MemoryReader, s Seeds, l limits.Limits) (Table, error) {
	l = l.Effective()
	count, err := readWord(kernel, s.NumSyms, 4)
	if err != nil {
		return Table{}, fmt.Errorf("%w: kallsyms_num_syms at 0x%x: %w", ErrUnreadable, s.NumSyms, err)
	}
	if count == 0 || count > uint64(l.MaxTableEntries) {
		return Table{}, fmt.Errorf("%w: kallsyms_num_syms is %d, MaxTableEntries %d", ErrCount, count, l.MaxTableEntries)
	}
	base, err := readWord(kernel, s.RelativeBase, 8)
	if err != nil {
		return Table{}, fmt.Errorf("%w: kallsyms_relative_base at 0x%x: %w", ErrUnreadable, s.RelativeBase, err)
	}
	tokens, err := readTokens(kernel, s, uint64(l.MaxNameBytes))
	if err != nil {
		return Table{}, err
	}
	raw, err := kernel.ReadAt(s.Offsets, 4*count)
	if err != nil || uint64(len(raw)) != 4*count {
		return Table{}, fmt.Errorf("%w: kallsyms_offsets at 0x%x: %d entries: %v", ErrUnreadable, s.Offsets, count, err)
	}
	names := nameReader{r: kernel, at: s.Names, maxName: int(l.MaxNameBytes)}
	symbols := make([]Symbol, count)
	for i := range symbols {
		sym, err := names.next(&tokens)
		if err != nil {
			return Table{}, fmt.Errorf("kallsyms: symbol %d: %w", i, err)
		}
		sym.Offset = int32(binary.LittleEndian.Uint32(raw[4*i:]))
		symbols[i] = sym
	}
	rule, err := ruleFromStext(symbols, base, s.Stext)
	if err != nil {
		return Table{}, err
	}
	for i := range symbols {
		symbols[i].Address = rule.address(symbols[i].Offset, base)
		// get_symbol_pos binary-searches the table, so the kernel's own is in
		// order; one that is not was misread.
		if i > 0 && symbols[i].Address < symbols[i-1].Address {
			return Table{}, fmt.Errorf("%w: symbol %d at 0x%x follows 0x%x", ErrOrder, i, symbols[i].Address, symbols[i-1].Address)
		}
	}
	setSizes(symbols)
	return Table{Symbols: symbols, Rule: rule, RelativeBase: base}, nil
}

func readWord(r memory.MemoryReader, at, width uint64) (uint64, error) {
	b, err := r.ReadAt(at, width)
	if err != nil {
		return 0, err
	}
	if uint64(len(b)) != width {
		return 0, fmt.Errorf("read %d of %d bytes", len(b), width)
	}
	if width == 4 {
		return uint64(binary.LittleEndian.Uint32(b)), nil
	}
	return binary.LittleEndian.Uint64(b), nil
}

func readTokens(r memory.MemoryReader, s Seeds, maxBytes uint64) ([tokenCount]string, error) {
	var tokens [tokenCount]string
	index, err := r.ReadAt(s.TokenIndex, 2*tokenCount)
	if err != nil || len(index) != 2*tokenCount {
		return tokens, fmt.Errorf("%w: kallsyms_token_index at 0x%x: %v", ErrUnreadable, s.TokenIndex, err)
	}
	for i := range tokens {
		at := s.TokenTable + uint64(binary.LittleEndian.Uint16(index[2*i:]))
		if tokens[i], err = readString(r, at, maxBytes); err != nil {
			return tokens, fmt.Errorf("%w: token %d at 0x%x: %w", ErrUnreadable, i, at, err)
		}
	}
	return tokens, nil
}

// A token is read a page at a time, so one that ends just before an unmapped
// page still reads.
func readString(r memory.MemoryReader, at, maxBytes uint64) (string, error) {
	var out []byte
	for uint64(len(out)) < maxBytes {
		n := min(pageBytes-at%pageBytes, maxBytes-uint64(len(out)))
		b, err := r.ReadAt(at, n)
		if err != nil {
			return "", err
		}
		if end := bytes.IndexByte(b, 0); end >= 0 {
			return string(append(out, b[:end]...)), nil
		}
		out = append(out, b...)
		at += uint64(len(b))
		if len(b) == 0 {
			return "", errors.New("empty read")
		}
	}
	return "", fmt.Errorf("no NUL within MaxNameBytes (%d)", maxBytes)
}

type nameReader struct {
	r       memory.MemoryReader
	at      uint64
	maxName int
	buf     []byte
	bufAt   uint64
}

func (n *nameReader) take(size int) ([]byte, error) {
	if n.at < n.bufAt || n.at-n.bufAt+uint64(size) > uint64(len(n.buf)) {
		b, err := n.r.ReadAt(n.at, uint64(max(size, namesReadSize)))
		if err != nil || len(b) < size {
			// The large read may run past the end of the mapped table.
			if b, err = n.r.ReadAt(n.at, uint64(size)); err != nil || len(b) != size {
				return nil, fmt.Errorf("%w: kallsyms_names at 0x%x: %v", ErrUnreadable, n.at, err)
			}
		}
		n.buf, n.bufAt = b, n.at
	}
	from := n.at - n.bufAt
	n.at += uint64(size)
	return n.buf[from : from+uint64(size)], nil
}

// A record is its token count, in one byte or, with bit 7 set, two bytes low
// seven bits first, then that many token indexes; the expansion's first
// character is the type letter.
func (n *nameReader) next(tokens *[tokenCount]string) (Symbol, error) {
	head, err := n.take(1)
	if err != nil {
		return Symbol{}, err
	}
	length := int(head[0])
	if length&lengthMore != 0 {
		high, err := n.take(1)
		if err != nil {
			return Symbol{}, err
		}
		length = length&lengthLow | int(high[0])<<7
	}
	encoded, err := n.take(length)
	if err != nil {
		return Symbol{}, err
	}
	var expanded []byte
	for _, t := range encoded {
		expanded = append(expanded, tokens[t]...)
		if len(expanded) > n.maxName {
			return Symbol{}, fmt.Errorf("%w: at 0x%x expands past MaxNameBytes (%d)", ErrRecord, n.at-uint64(length), n.maxName)
		}
	}
	sym := Symbol{EncodedLength: length}
	if len(expanded) > 0 {
		sym.Type, sym.Name = expanded[0], string(expanded[1:])
	}
	return sym, nil
}

// VMCOREINFO's SYMBOL(_stext) is the kernel's own statement of where _stext
// is; the rule that places the table's _stext there is the rule the table was
// written with. When both rules or neither do, the table says nothing.
func ruleFromStext(symbols []Symbol, base, stext uint64) (AddressRule, error) {
	for i, s := range symbols {
		if s.Name != "_stext" {
			continue
		}
		absolute := RuleAbsolutePercpu.address(s.Offset, base) == stext
		relative := RuleRelative.address(s.Offset, base) == stext
		switch {
		case relative && !absolute:
			return RuleRelative, nil
		case absolute && !relative:
			return RuleAbsolutePercpu, nil
		}
		return 0, fmt.Errorf("%w: symbol %d has offset 0x%x from base 0x%x; vmcoreinfo gives 0x%x", ErrAddressRule, i, uint32(s.Offset), base, stext)
	}
	return 0, fmt.Errorf("%w: the table holds no _stext", ErrAddressRule)
}

// A symbol ends where the next higher address after it starts. After the last
// group the kernel takes the end of init text, of the image (_end, which only
// KALLSYMS_ALL tables hold) or of text, read here from the table itself.
func setSizes(symbols []Symbol) {
	bound := map[string]uint64{}
	for _, s := range symbols {
		switch s.Name {
		case "_sinittext", "_einittext", "_end", "_etext":
			if _, seen := bound[s.Name]; !seen {
				bound[s.Name] = s.Address
			}
		}
	}
	sinit, haveSinit := bound["_sinittext"]
	einit, haveEinit := bound["_einittext"]
	lastEnd := func(a uint64) (uint64, bool) {
		if haveSinit && haveEinit && a >= sinit && a < einit {
			return einit, true
		}
		if e, ok := bound["_end"]; ok {
			return e, true
		}
		e, ok := bound["_etext"]
		return e, ok
	}
	var higher []uint64
	for i := len(symbols) - 1; i >= 0; i-- {
		a := symbols[i].Address
		for len(higher) > 0 && higher[len(higher)-1] <= a {
			higher = higher[:len(higher)-1]
		}
		next, ok := lastEnd(a)
		if len(higher) > 0 {
			next, ok = higher[len(higher)-1], true
		}
		symbols[i].Size = 0
		if ok && next > a && next-a <= math.MaxInt64 {
			symbols[i].Size = int64(next - a)
		}
		higher = append(higher, a)
	}
}
