package kallsyms

import (
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols/autoload"
)

// space is a sparse kernel address space: byte runs at given addresses.
type space map[uint64][]byte

func (s space) ReadAt(offset, size uint64) ([]byte, error) {
	for at, b := range s {
		if offset >= at && offset-at <= uint64(len(b)) && size <= uint64(len(b))-(offset-at) {
			return append([]byte(nil), b[offset-at:offset-at+size]...), nil
		}
	}
	return nil, memory.ErrUnmapped
}

func (space) Size() uint64 { return math.MaxUint64 }

const (
	textBase  = 0xffffffff81000000
	tablesAt  = 0xffffffff82000000
	tokensAt  = 0xffffffff82100000
	namesAt   = 0xffffffff82200000
	offsetsAt = 0xffffffff82300000
)

// table is a kallsyms table as scripts/kallsyms.c lays it out. Token 1 is
// "T_s" and token 2 "text"; every printable byte is also its own token.
type table struct {
	records [][]byte
	offsets []int32
	base    uint64
	stext   uint64
}

func tokenSet() [256]string {
	var t [256]string
	for c := 0x20; c < 0x7f; c++ {
		t[c] = string(rune(c))
	}
	t[1], t[2] = "T_s", "text"
	return t
}

func record(tokens ...byte) []byte {
	n := len(tokens)
	if n <= 0x7f {
		return append([]byte{byte(n)}, tokens...)
	}
	return append([]byte{0x80 | byte(n&0x7f), byte(n >> 7)}, tokens...)
}

func text(s string) []byte { return record([]byte(s)...) }

func (tb table) build() (space, Seeds) {
	tokens := tokenSet()
	var strs, index []byte
	for _, t := range tokens {
		index = binary.LittleEndian.AppendUint16(index, uint16(len(strs)))
		strs = append(append(strs, t...), 0)
	}
	var names []byte
	for _, r := range tb.records {
		names = append(names, r...)
	}
	var offs []byte
	for _, o := range tb.offsets {
		offs = binary.LittleEndian.AppendUint32(offs, uint32(o))
	}
	head := binary.LittleEndian.AppendUint32(nil, uint32(len(tb.records)))
	head = append(head, 0, 0, 0, 0)
	head = binary.LittleEndian.AppendUint64(head, tb.base)
	s := space{tablesAt: toPage(head), tokensAt: toPage(append(index, strs...)), namesAt: toPage(names), offsetsAt: toPage(offs)}
	return s, Seeds{NumSyms: tablesAt, RelativeBase: tablesAt + 8, TokenIndex: tokensAt, TokenTable: tokensAt + 512,
		Names: namesAt, Offsets: offsetsAt, Stext: tb.stext}
}

// Kernel memory is mapped in whole pages.
func toPage(b []byte) []byte { return append(b, make([]byte, (4096-len(b)%4096)%4096)...) }

func decode(t *testing.T, tb table) Table {
	t.Helper()
	s, seeds := tb.build()
	got, err := Decode(s, seeds, limits.Limits{})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

func relativeKernel() table {
	return table{
		records: [][]byte{record(1, 2), text("Tfoo"), text("tfoo_alias"), text("tbar"), text("T_etext"), text("D_end")},
		offsets: []int32{0, 0x40, 0x40, 0x80, 0x100, 0x2000},
		base:    textBase,
		stext:   textBase,
	}
}

func TestTheTableDecodesByTheRelativeRule(t *testing.T) {
	got := decode(t, relativeKernel())
	if got.Rule != RuleRelative || got.RelativeBase != textBase || len(got.Symbols) != 6 {
		t.Fatalf("rule %s base 0x%x, %d symbols", got.Rule, got.RelativeBase, len(got.Symbols))
	}
	want := []struct {
		name string
		typ  byte
		at   uint64
		size int64
	}{
		{"_stext", 'T', textBase, 0x40},
		{"foo", 'T', textBase + 0x40, 0x40},
		{"foo_alias", 't', textBase + 0x40, 0x40},
		{"bar", 't', textBase + 0x80, 0x80},
		{"_etext", 'T', textBase + 0x100, 0x1f00},
		{"_end", 'D', textBase + 0x2000, 0},
	}
	for i, w := range want {
		s := got.Symbols[i]
		if s.Name != w.name || s.Type != w.typ || s.Address != w.at || s.Size != w.size {
			t.Errorf("symbol %d: %+v, want %+v", i, s, w)
		}
	}
	if s, ok := got.Lookup("foo_alias"); !ok || s.Global() || s.EncodedLength != 10 {
		t.Errorf("Lookup(foo_alias) = %+v %v", s, ok)
	}
	if _, ok := got.Lookup("baz"); ok {
		t.Error("Lookup found a name the table does not hold")
	}
}

func absolute(addr uint64) int32 { return int32(-1 - int64(addr-textBase)) }

func TestAnAbsolutePercpuTableKeepsPercpuOffsetsAsAddresses(t *testing.T) {
	got := decode(t, table{
		records: [][]byte{text("D__per_cpu_start"), text("Dcpu_number"), record(1, 2), text("T_etext")},
		offsets: []int32{0, 0x20, absolute(textBase), absolute(textBase + 0x400)},
		base:    textBase,
		stext:   textBase,
	})
	if got.Rule != RuleAbsolutePercpu {
		t.Fatalf("rule %s", got.Rule)
	}
	for i, w := range []uint64{0, 0x20, textBase, textBase + 0x400} {
		if got.Symbols[i].Address != w {
			t.Errorf("symbol %d at 0x%x, want 0x%x", i, got.Symbols[i].Address, w)
		}
	}
	if got.Symbols[0].Size != 0x20 || got.Symbols[1].Size != 0 || got.Symbols[2].Size != 0x400 || got.Symbols[3].Size != 0 {
		t.Errorf("sizes %d %d %d %d: a per-CPU symbol before text has no size", got.Symbols[0].Size, got.Symbols[1].Size, got.Symbols[2].Size, got.Symbols[3].Size)
	}
}

func TestOnlyStextDecidesTheRule(t *testing.T) {
	tb := relativeKernel()
	tb.stext = textBase + 8
	if s, seeds := tb.build(); true {
		if _, err := Decode(s, seeds, limits.Limits{}); !errors.Is(err, ErrAddressRule) {
			t.Errorf("_stext elsewhere: %v", err)
		}
	}
	tb = relativeKernel()
	tb.records[0] = text("T_start")
	if s, seeds := tb.build(); true {
		if _, err := Decode(s, seeds, limits.Limits{}); !errors.Is(err, ErrAddressRule) {
			t.Errorf("no _stext: %v", err)
		}
	}
	tb = relativeKernel()
	tb.base, tb.stext = 0, 0
	if s, seeds := tb.build(); true {
		if _, err := Decode(s, seeds, limits.Limits{}); !errors.Is(err, ErrAddressRule) {
			t.Errorf("base 0, where both rules agree: %v", err)
		}
	}
}

func TestATableOutOfAddressOrderIsRefused(t *testing.T) {
	tb := relativeKernel()
	tb.offsets[3] = 0x10
	s, seeds := tb.build()
	if _, err := Decode(s, seeds, limits.Limits{}); !errors.Is(err, ErrOrder) {
		t.Errorf("decode: %v", err)
	}
}

func TestSizesEndAtInitTextOrTheImageOrText(t *testing.T) {
	got := decode(t, table{
		records: [][]byte{record(1, 2), text("T_etext"), text("T_sinittext"), text("tinit_last"), text("T_einittext")},
		offsets: []int32{0, 0x100, 0x1000, 0x1010, 0x1040},
		base:    textBase,
		stext:   textBase,
	})
	if s := got.Symbols[4]; s.Size != 0 {
		t.Errorf("_einittext size %d", s.Size)
	}
	got = decode(t, table{
		records: [][]byte{record(1, 2), text("T_sinittext"), text("T_einittext"), text("tafter"), text("T_etext")},
		offsets: []int32{0, 0x10, 0x20, 0x30, 0x30},
		base:    textBase,
		stext:   textBase,
	})
	if s := got.Symbols[3]; s.Size != 0 {
		t.Errorf("the last group ends at _etext, which it is: size %d", s.Size)
	}
	got = decode(t, table{
		records: [][]byte{record(1, 2), text("tlast")},
		offsets: []int32{0, 0x10},
		base:    textBase,
		stext:   textBase,
	})
	if s := got.Symbols[1]; s.Size != 0 {
		t.Errorf("no bound in the table: size %d", s.Size)
	}
}

func TestATwoByteLengthCountsSevenBitsFromEachByte(t *testing.T) {
	name := "t" + strings.Repeat("x", 0x90)
	got := decode(t, table{
		records: [][]byte{record(1, 2), text(name), text("tafter")},
		offsets: []int32{0, 0x10, 0x20},
		base:    textBase,
		stext:   textBase,
	})
	if got.Symbols[1].Name != name[1:] || got.Symbols[1].EncodedLength != len(name) || got.Symbols[2].Name != "after" {
		t.Errorf("symbols %q (%d), %q", got.Symbols[1].Name, got.Symbols[1].EncodedLength, got.Symbols[2].Name)
	}
}

func TestWhatDoesNotReadOrFitIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(space, *Seeds)
		l      limits.Limits
		want   error
	}{
		"count zero":          {func(s space, _ *Seeds) { copy(s[tablesAt], []byte{0, 0, 0, 0}) }, limits.Limits{}, ErrCount},
		"count past the cap":  {func(space, *Seeds) {}, limits.Limits{MaxTableEntries: 5}, ErrCount},
		"no count":            {func(_ space, sd *Seeds) { sd.NumSyms = 0x1000 }, limits.Limits{}, ErrUnreadable},
		"no base":             {func(_ space, sd *Seeds) { sd.RelativeBase = 0x1000 }, limits.Limits{}, ErrUnreadable},
		"no token index":      {func(_ space, sd *Seeds) { sd.TokenIndex = 0x1000 }, limits.Limits{}, ErrUnreadable},
		"offsets short":       {func(s space, _ *Seeds) { s[offsetsAt] = s[offsetsAt][:8] }, limits.Limits{}, ErrUnreadable},
		"names short":         {func(s space, _ *Seeds) { s[namesAt] = s[namesAt][:10] }, limits.Limits{}, ErrUnreadable},
		"token without NUL":   {func(s space, _ *Seeds) { fill(s[tokensAt][512:], 'x') }, limits.Limits{}, ErrUnreadable},
		"name past the bound": {func(space, *Seeds) {}, limits.Limits{MaxNameBytes: 5}, ErrRecord},
	} {
		s, seeds := relativeKernel().build()
		tc.change(s, &seeds)
		if _, err := Decode(s, seeds, tc.l); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func fill(b []byte, c byte) {
	for i := range b {
		b[i] = c
	}
}

func TestATokenEndingBeforeAnUnmappedPageReads(t *testing.T) {
	tb := relativeKernel()
	s, seeds := tb.build()
	n := 512
	for _, tk := range tokenSet() {
		n += len(tk) + 1
	}
	tokens := s[tokensAt][:n]
	delete(s, tokensAt)
	end := uint64(0xffffffff82101000)
	at := end - uint64(len(tokens))
	s[at] = tokens
	seeds.TokenIndex, seeds.TokenTable = at, at+512
	if _, err := Decode(s, seeds, limits.Limits{}); err != nil {
		t.Errorf("decode: %v", err)
	}
}

func TestSeedsAreTheVMCoreInfoSymbols(t *testing.T) {
	entries := []autoload.VMCoreInfoEntry{}
	for i, name := range []string{"kallsyms_num_syms", "kallsyms_names", "kallsyms_token_table", "kallsyms_token_index", "kallsyms_offsets", "kallsyms_relative_base", "_stext"} {
		entries = append(entries, autoload.VMCoreInfoEntry{Key: "SYMBOL(" + name + ")", Int: big.NewInt(int64(0x1000 * (i + 1)))})
	}
	s, err := SeedsFromVMCoreInfo(autoload.VMCoreInfo{Entries: entries})
	if err != nil || s != (Seeds{NumSyms: 0x1000, Names: 0x2000, TokenTable: 0x3000, TokenIndex: 0x4000, Offsets: 0x5000, RelativeBase: 0x6000, Stext: 0x7000}) {
		t.Fatalf("seeds %+v (%v)", s, err)
	}
	entries[1].Cut = true
	if _, err := SeedsFromVMCoreInfo(autoload.VMCoreInfo{Offset: 0x40, Entries: entries[:6]}); !errors.Is(err, ErrNoSeeds) ||
		!strings.Contains(err.Error(), "kallsyms_names") || !strings.Contains(err.Error(), "_stext") {
		t.Errorf("a cut and an absent key: %v", err)
	}
}

func TestTheAddressRulesAreTheKernels(t *testing.T) {
	for _, tc := range []struct {
		rule   AddressRule
		offset int32
		want   uint64
	}{
		{RuleRelative, 0x10, textBase + 0x10},
		{RuleRelative, -1, 0x80ffffff},
		{RuleAbsolutePercpu, 0x10, 0x10},
		{RuleAbsolutePercpu, -1, textBase},
		{RuleAbsolutePercpu, -0x11, textBase + 0x10},
	} {
		if got := tc.rule.address(tc.offset, textBase); got != tc.want {
			t.Errorf("%s(%d) = 0x%x, want 0x%x", tc.rule, tc.offset, got, tc.want)
		}
	}
	if RuleRelative.String() != "relative" || RuleAbsolutePercpu.String() != "absolute per-CPU" || AddressRule(9).String() != "address rule 9" {
		t.Error("rule names")
	}
	for c, want := range map[byte]bool{'T': true, 'D': true, 'u': true, 'v': true, 'w': true, 't': false, 'd': false, 'b': false} {
		if (Symbol{Type: c}).Global() != want {
			t.Errorf("letter %c global %v", c, !want)
		}
	}
}
