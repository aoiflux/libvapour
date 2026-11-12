package linuxmodule

import (
	"fmt"
	"strings"
)

// taintNames are the kernel's flag names by bit, with the TAINT_ prefix
// dropped as TAINT_FLAG does for desc (S07 T2, T3).
var taintNames = [...]struct {
	name   string
	letter byte
	module bool
}{
	{"PROPRIETARY_MODULE", 'P', true}, {"FORCED_MODULE", 'F', true}, {"CPU_OUT_OF_SPEC", 'S', false},
	{"FORCED_RMMOD", 'R', false}, {"MACHINE_CHECK", 'M', false}, {"BAD_PAGE", 'B', false},
	{"USER", 'U', false}, {"DIE", 'D', false}, {"OVERRIDDEN_ACPI_TABLE", 'A', false},
	{"WARN", 'W', false}, {"CRAP", 'C', true}, {"FIRMWARE_WORKAROUND", 'I', false},
	{"OOT_MODULE", 'O', true}, {"UNSIGNED_MODULE", 'E', true}, {"SOFTLOCKUP", 'L', false},
	{"LIVEPATCH", 'K', true}, {"AUX", 'X', true}, {"RANDSTRUCT", 'T', true},
	{"TEST", 'N', true}, {"FWCTL", 'J', true},
}

type Taint struct {
	Bit    int
	Name   string
	Letter byte
	Module bool
	Known  bool
}

// Taints decodes a module's taint bits (S07 4.5).
func (m *Model) Taints(bits uint64) []Taint {
	var out []Taint
	for i := range int(8 * m.width) {
		if bits&(1<<i) == 0 {
			continue
		}
		t, ok := m.imageTaint(i)
		if !ok && i < len(taintNames) {
			e := taintNames[i]
			t, ok = Taint{Bit: i, Name: e.name, Letter: e.letter, Module: e.module, Known: true}, true
		}
		if !ok {
			t = Taint{Bit: i, Name: fmt.Sprintf("bit %d", i)}
		}
		out = append(out, t)
	}
	return out
}

func (m *Model) imageTaint(i int) (Taint, bool) {
	table, ok := m.symbol("taint_flags")
	if !ok {
		return Taint{}, false
	}
	size, err := m.size("taint_flag")
	if err != nil {
		return Taint{}, false
	}
	at := table + uint64(i)*size
	var off [3]uint64
	for j, name := range []string{"c_true", "c_false", "module"} {
		if off[j], err = m.offset("taint_flag", name); err != nil {
			return Taint{}, false
		}
	}
	rec, ok := m.bytes(at, size)
	if !ok || off[0] >= size || off[1] >= size || off[2] >= size {
		return Taint{}, false
	}
	letter, other, module := rec[off[0]], rec[off[1]], rec[off[2]]
	upper := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	if !upper(letter) || !(other == ' ' || upper(other)) || module > 1 {
		return Taint{}, false
	}
	t := Taint{Bit: i, Letter: letter, Module: module == 1, Known: true}
	if d, err := m.offset("taint_flag", "desc"); err == nil {
		if p, ok := m.pointer(at + d); ok {
			if name, _, ok := m.cstring(p, uint64(m.r.Limits.Effective().MaxNameBytes)); ok && name != "" {
				t.Name = name
			}
		}
	}
	if t.Name == "" && i < len(taintNames) {
		t.Name = taintNames[i].name
	}
	if t.Name == "" {
		t.Name = fmt.Sprintf("bit %d", i)
	}
	return t, true
}

// TaintNames is the default form: every set bit's name, in bit order.
func TaintNames(ts []Taint) string {
	names := make([]string, len(ts))
	for i, t := range ts {
		names[i] = t.Name
	}
	return strings.Join(names, ",")
}

// TaintLetters is the kernel's own form (S07 T4).
func TaintLetters(ts []Taint) string {
	var b strings.Builder
	for _, t := range ts {
		if t.Known && t.Module {
			b.WriteByte(t.Letter)
		}
	}
	return b.String()
}
