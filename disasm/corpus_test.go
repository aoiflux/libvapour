package disasm

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The corpus holds, for each encoding, an independent decoder's reading:
// encodings from the .text of 64- and 32-bit ntdll.dll, random bytes, and
// hand-picked cases. Where the two decoders disagree, the processor manual
// decides, and each disagreement is pinned to a rule below with its count.
type sample struct {
	line       int
	mode       Mode
	code       []byte
	origin     string
	decoded    bool
	length     int
	mnemonic   string
	writesAcc  bool
	writesR10  bool
	zeroOpcode bool
	ripRel     bool
	ripTarget  uint64
}

func (s sample) String() string {
	return fmt.Sprintf("line %d %d-bit %x (%s %q)", s.line, s.mode, s.code, s.origin, s.mnemonic)
}

func loadSamples(t *testing.T) []sample {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "disasm_corpus.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []sample
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		c := strings.Split(text, "\t")
		if len(c) != 12 {
			t.Fatalf("line %d: %d columns", line, len(c))
		}
		code, err1 := hex.DecodeString(c[1])
		length, err2 := strconv.Atoi(c[4])
		target, err3 := strconv.ParseUint(c[11], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			t.Fatalf("line %d: %v %v %v", line, err1, err2, err3)
		}
		mode := Mode64
		if c[0] == "32" {
			mode = Mode32
		}
		out = append(out, sample{
			line: line, mode: mode, code: code, origin: c[2], decoded: c[3] == "ok", length: length,
			mnemonic: c[5], writesAcc: c[6] == "1", writesR10: c[7] == "1",
			zeroOpcode: c[9] == "1", ripRel: c[10] == "1", ripTarget: target,
		})
	}
	if len(out) != 5278 {
		t.Fatalf("%d samples, want 5278", len(out))
	}
	return out
}

func opcodeAt(s sample) (int, bool) {
	p := 0
	for p < len(s.code) && (isLegacyPrefix(s.code[p]) || (s.mode == Mode64 && s.code[p]&0xF0 == 0x40)) {
		p++
	}
	return p, p < len(s.code)
}

func modrmReg(s sample, p int) int {
	if p+1 >= len(s.code) {
		return -1
	}
	return int(s.code[p+1]>>3) & 7
}

type decodeRule struct {
	name  string
	count int
	holds func(s sample) bool
}

// Every encoding the two decoders read differently, with the manual's reason.
var decodeRules = []decodeRule{
	{"valid outside 64-bit mode, refused by the library (82, D6 SALC)", 13, func(s sample) bool {
		p, ok := opcodeAt(s)
		return ok && s.mode == Mode32 && (s.code[p] == 0x82 || s.code[p] == 0xD6)
	}},
	{"blank in the opcode map (shift group /6, F6/F7 /1, D9 D8)", 16, func(s sample) bool {
		p, ok := opcodeAt(s)
		if !ok {
			return false
		}
		switch op := s.code[p]; {
		case op == 0xC0 || op == 0xC1 || (op >= 0xD0 && op <= 0xD3):
			return modrmReg(s, p) == 6
		case op == 0xF6 || op == 0xF7:
			return modrmReg(s, p) == 1
		case op == 0xD9:
			return p+1 < len(s.code) && s.code[p+1] == 0xD8
		}
		return false
	}},
	{"REX not next to the opcode is ignored by the processor, refused by the library", 9, func(s sample) bool {
		if s.mode != Mode64 {
			return false
		}
		p, _ := opcodeAt(s)
		for i := 0; i < p-1; i++ {
			if s.code[i]&0xF0 == 0x40 {
				return true
			}
		}
		return false
	}},
	{"RDSEED (0F C7 /7), absent from the library", 1, func(s sample) bool {
		p, ok := opcodeAt(s)
		return ok && p+2 < len(s.code) && s.code[p] == 0x0F && s.code[p+1] == 0xC7 && (s.code[p+2]>>3)&7 == 7
	}},
	{"SYSCALL and SYSRET outside 64-bit mode raise #UD", 5, func(s sample) bool {
		p, ok := opcodeAt(s)
		return ok && s.mode == Mode32 && p+1 < len(s.code) && s.code[p] == 0x0F && (s.code[p+1] == 0x05 || s.code[p+1] == 0x07)
	}},
	{"LOCK with a register destination raises #UD", 1, func(s sample) bool {
		return len(s.code) > 0 && s.code[0] == 0xF0 && strings.HasPrefix(s.mnemonic, "lock ")
	}},
}

func TestEveryDecodeDisagreementHasAManualReason(t *testing.T) {
	counts := map[string]int{}
	agreed := 0
	for _, s := range loadSamples(t) {
		_, ok := Decode(s.code, 0, s.mode)
		if ok == s.decoded {
			agreed++
			continue
		}
		var rules []string
		for _, r := range decodeRules {
			if r.holds(s) {
				rules = append(rules, r.name)
			}
		}
		switch {
		case len(rules) != 1:
			t.Errorf("%s: decoded %v against %v, rules %v", s, ok, s.decoded, rules)
		case ok:
			t.Errorf("%s: decoded here only, by rule %q", s, rules[0])
		case s.origin == "ntdll":
			t.Errorf("%s: compiled code falls under %q", s, rules[0])
		default:
			counts[rules[0]]++
		}
	}
	for _, r := range decodeRules {
		if counts[r.name] != r.count {
			t.Errorf("%q: %d samples, want %d", r.name, counts[r.name], r.count)
		}
	}
	if agreed != 5278-45 {
		t.Errorf("%d samples agree, want %d", agreed, 5278-45)
	}
}

func TestDecodeRulesLeaveOrdinaryEncodingsAlone(t *testing.T) {
	for _, c := range []struct {
		mode Mode
		hex  string
	}{
		{Mode64, "4c8bd1"}, {Mode64, "b818000000"}, {Mode64, "0f05"}, {Mode64, "c3"},
		{Mode64, "d1e0"}, {Mode64, "f7e1"}, {Mode64, "80c101"}, {Mode64, "48f7f1"},
		{Mode64, "f00fb111"}, {Mode32, "61"}, {Mode32, "80c101"},
	} {
		code, _ := hex.DecodeString(c.hex)
		s := sample{mode: c.mode, code: code}
		for _, r := range decodeRules {
			if r.holds(s) {
				t.Errorf("%s in %d-bit mode falls under %q", c.hex, c.mode, r.name)
			}
		}
		if _, ok := Decode(code, 0, c.mode); !ok {
			t.Errorf("%s in %d-bit mode does not decode", c.hex, c.mode)
		}
	}
}

func bothDecoded(t *testing.T) []struct {
	s    sample
	inst Inst
} {
	var out []struct {
		s    sample
		inst Inst
	}
	for _, s := range loadSamples(t) {
		if inst, ok := Decode(s.code, 0, s.mode); ok && s.decoded {
			out = append(out, struct {
				s    sample
				inst Inst
			}{s, inst})
		}
	}
	return out
}

func TestLengthsAgreeWhereBothDecode(t *testing.T) {
	pairs := bothDecoded(t)
	for _, p := range pairs {
		if p.inst.Len != p.s.length {
			t.Errorf("%s: length %d, corpus %d", p.s, p.inst.Len, p.s.length)
		}
	}
	if len(pairs) != 5080-45 {
		t.Errorf("%d samples decoded by both", len(pairs))
	}
}

// The corpus spells some control transfers differently: far forms as ljmp and
// lcall, a prefix folded into the mnemonic, CD 03 as int. The manual's reading
// of each is what the predicates follow.
func branchKind(s sample) string {
	m := s.mnemonic
	for _, prefix := range []string{"bnd ", "repz ", "repnz ", "rep ", "repne "} {
		m = strings.TrimPrefix(m, prefix)
	}
	switch m {
	case "ljmp":
		return "jmp"
	case "lcall":
		return "call"
	case "int":
		if p, ok := opcodeAt(s); ok && p+1 < len(s.code) && s.code[p] == 0xCD && s.code[p+1] == breakpointVector {
			return "int3"
		}
	}
	return m
}

func TestControlTransferPredicatesFollowTheManualReading(t *testing.T) {
	predicates := map[string]func(Inst) bool{
		"jmp": Inst.IsJmp, "call": Inst.IsCall, "ret": Inst.IsRet, "leave": Inst.IsLeave,
		"int3": Inst.IsInt3, "syscall": Inst.IsSyscall, "mov": Inst.IsMov, "lea": Inst.IsLea,
	}
	seen := map[string]int{}
	respelled := 0
	for _, p := range bothDecoded(t) {
		kind := branchKind(p.s)
		if _, ok := predicates[kind]; ok && kind != p.s.mnemonic {
			respelled++
		}
		for name, f := range predicates {
			if got := f(p.inst); got != (kind == name) {
				t.Errorf("%s: %s %v, corpus kind %q", p.s, name, got, kind)
			}
		}
		if _, ok := predicates[kind]; ok {
			seen[kind]++
		}
	}
	if len(seen) != len(predicates) {
		t.Errorf("corpus reaches %v", seen)
	}
	t.Logf("kinds reached %v", seen)
	if respelled != 12 {
		t.Errorf("%d respelled mnemonics, want 12", respelled)
	}
}

func TestRIPRelativeTargetsAndZeroOpcodesAgree(t *testing.T) {
	relative, backward, compiled := 0, 0, 0
	for _, p := range bothDecoded(t) {
		target, ok := p.inst.RIPRelativeTarget()
		if ok != p.s.ripRel || (ok && target != p.s.ripTarget) {
			t.Errorf("%s: target %#x %v, corpus %#x %v", p.s, target, ok, p.s.ripTarget, p.s.ripRel)
		}
		if ok {
			relative++
			if int64(target) < 0 {
				backward++
			}
			if p.s.origin == "ntdll" {
				compiled++
			}
		}
		if p.inst.HasZeroOpcode() != p.s.zeroOpcode {
			t.Errorf("%s: zero opcode %v", p.s, p.inst.HasZeroOpcode())
		}
	}
	if relative == 0 || backward == 0 || compiled == 0 {
		t.Errorf("RIP-relative samples: %d, %d backward, %d compiled", relative, backward, compiled)
	}
	t.Logf("RIP-relative samples: %d, %d backward, %d compiled", relative, backward, compiled)
}

type writeRule struct {
	name  string
	count int
	fix   func(s sample, inst Inst, acc, r10 *bool) bool
}

// Register writes where the corpus and the manual differ.
var writeRules = []writeRule{
	{"TEST sets flags only", 12, func(s sample, _ Inst, acc, _ *bool) bool {
		if s.mnemonic == "test" && *acc {
			*acc = false
			return true
		}
		return false
	}},
	{"CDQ and CQO write only EDX or RDX", 12, func(s sample, _ Inst, acc, _ *bool) bool {
		if (s.mnemonic == "cdq" || s.mnemonic == "cqo") && *acc {
			*acc = false
			return true
		}
		return false
	}},
	{"BOUND reads its register operand", 1, func(s sample, _ Inst, acc, _ *bool) bool {
		if s.mnemonic == "bound" && *acc {
			*acc = false
			return true
		}
		return false
	}},
	{"a 32-bit destination zero-extends into R10", 8, func(s sample, inst Inst, _, r10 *bool) bool {
		if !*r10 && s.mode == Mode64 && strings.Contains(inst.Text, " r10d,") {
			*r10 = true
			return true
		}
		return false
	}},
}

func TestRegisterWritesFollowTheManual(t *testing.T) {
	counts := map[string]int{}
	acc, r10 := 0, 0
	for _, p := range bothDecoded(t) {
		wantAcc, wantR10 := p.s.writesAcc, p.s.writesR10
		for _, r := range writeRules {
			if r.fix(p.s, p.inst, &wantAcc, &wantR10) {
				counts[r.name]++
			}
		}
		if p.inst.WritesAccumulator() != wantAcc || p.inst.WritesR10() != wantR10 {
			t.Errorf("%s %q: accumulator %v r10 %v, want %v %v", p.s, p.inst.Text,
				p.inst.WritesAccumulator(), p.inst.WritesR10(), wantAcc, wantR10)
		}
		if wantAcc {
			acc++
		}
		if wantR10 {
			r10++
		}
	}
	for _, r := range writeRules {
		if counts[r.name] != r.count {
			t.Errorf("%q: %d samples, want %d", r.name, counts[r.name], r.count)
		}
	}
	if acc == 0 || r10 == 0 {
		t.Errorf("%d accumulator and %d r10 writes", acc, r10)
	}
	t.Logf("%d accumulator and %d r10 writes", acc, r10)
}
