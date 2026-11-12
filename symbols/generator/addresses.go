package generator

import (
	"sort"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/btf"
	"github.com/aoiflux/libvapour/symbols/kallsyms"
)

type placed struct {
	address uint64
	global  bool
}

// A table holds link-time addresses. KASLR moves the kernel image by the
// virtual shift. A per-CPU symbol that CONFIG_KALLSYMS_ABSOLUTE_PERCPU
// stores as a non-negative offset is an absolute value the move never
// touched (kernel/kallsyms.c, kallsyms_sym_address).
func linkAddress(s kallsyms.Symbol, rule kallsyms.AddressRule, shift uint64) (uint64, bool) {
	if rule == kallsyms.RuleAbsolutePercpu && s.Offset >= 0 {
		return s.Address, true
	}
	if s.Address < shift {
		return 0, false
	}
	return s.Address - shift, true
}

// A name with one address keeps it. kallsyms records no source file, so
// among several addresses only a single global one can be chosen: the link
// editor allows one global definition of a name, and every reference from
// another file binds to it. Any other name with several addresses is left
// out, because the table could not say which one a tool means.
func linkedNames(k LinuxKernel, report *LinuxReport) map[string]uint64 {
	byName := map[string][]placed{}
	unplaced := map[string]bool{}
	notText := map[string]bool{}
	for _, s := range k.Symbols {
		if s.Name == "" {
			continue
		}
		if !utf8.ValidString(s.Name) {
			notText[s.Name] = true
			continue
		}
		a, ok := linkAddress(s, k.Rule, k.VirtualShift)
		if !ok {
			unplaced[s.Name] = true
			continue
		}
		byName[s.Name] = append(byName[s.Name], placed{address: a, global: s.Global()})
	}
	report.NotUTF8 = len(notText)
	for name := range unplaced {
		if _, ok := byName[name]; !ok {
			report.Unplaced++
		}
	}
	report.Names = len(byName) + report.NotUTF8 + report.Unplaced
	out := make(map[string]uint64, len(byName))
	for name, list := range byName {
		if a, ok := oneAddress(list); ok {
			out[name] = a
			continue
		}
		report.Ambiguous = append(report.Ambiguous, name)
	}
	sort.Strings(report.Ambiguous)
	return out
}

func oneAddress(list []placed) (uint64, bool) {
	all, globals := map[uint64]bool{}, map[uint64]bool{}
	for _, p := range list {
		all[p.address] = true
		if p.global {
			globals[p.address] = true
		}
	}
	pick := all
	if len(all) > 1 {
		pick = globals
	}
	if len(pick) != 1 {
		return 0, false
	}
	for a := range pick {
		return a, true
	}
	return 0, false
}

// BTF types variables through VAR, and DATASEC places each variable at an
// offset in its section. A variable's type is used only when every VAR of
// that name agrees, and, for the per-CPU section whose start the table
// knows, when the variable lies at that start plus its offset.
func (c *converter) variableTypes(linked map[string]uint64, report *LinuxReport) map[string]symbols.TypeRef {
	type found struct {
		shape shape
		ok    bool
	}
	vars := map[string]found{}
	for id := 1; id < len(c.spec.Types); id++ {
		t := c.spec.Types[id]
		if t.Kind != btf.KindVar || t.Name == "" {
			continue
		}
		s, err := c.shapeOf(t.Ref)
		if err == nil && !c.written(s) {
			err = refuseRefusedType
		}
		prev, seen := vars[t.Name]
		switch {
		case err != nil:
			vars[t.Name] = found{}
		case !seen:
			vars[t.Name] = found{shape: s, ok: true}
		case prev.ok && !c.sameTarget(prev.shape, s):
			vars[t.Name] = found{}
		}
	}
	misplaced := map[string]bool{}
	for id := 1; id < len(c.spec.Types); id++ {
		t := c.spec.Types[id]
		if t.Kind != btf.KindDatasec || t.Name != percpuSection {
			continue
		}
		start, ok := linked[percpuStart]
		if !ok {
			continue
		}
		for _, v := range t.Vars {
			name := c.spec.Types[v.Type].Name
			if a, ok := linked[name]; ok && a != start+uint64(v.Offset) {
				misplaced[name] = true
			}
		}
	}
	out := map[string]symbols.TypeRef{}
	for name, f := range vars {
		if _, ok := linked[name]; !ok {
			continue
		}
		if !f.ok {
			report.Untyped++
			continue
		}
		if misplaced[name] {
			report.Misplaced++
			continue
		}
		out[name] = c.typeRef(f.shape, 0, 0)
	}
	report.Typed = len(out)
	return out
}
