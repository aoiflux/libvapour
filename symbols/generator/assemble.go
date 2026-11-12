package generator

import (
	"bytes"
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/btf"
	"github.com/aoiflux/libvapour/symbols/kallsyms"
)

type LinuxKernel struct {
	Banner       []byte
	Symbols      []kallsyms.Symbol
	Rule         kallsyms.AddressRule
	VirtualShift uint64
	BTF          *btf.Spec
	PointerSize  int64
	Limits       limits.Limits
}

type TypeReport struct {
	Merged         int
	NamedByMembers int
	Suffixed       int
	Conflicts      []string
	Aliases        int
	Forwards       int
	Padding        int
	Refused        map[string]int
}

type LinuxReport struct {
	Names     int
	Ambiguous []string
	Unplaced  int
	NotUTF8   int
	Typed     int
	Untyped   int
	Misplaced int
	Types     TypeReport
}

type BTFTypes struct {
	Scalars      []symbols.Scalar
	Records      []symbols.Record
	Enumerations []symbols.EnumType
	Report       TypeReport
}

func TypesFromBTF(spec *btf.Spec, pointerSize int64, l limits.Limits) (BTFTypes, error) {
	c, out, err := convertTypes(spec, pointerSize, l)
	if err != nil {
		return BTFTypes{}, err
	}
	out.Report = *c.report
	return out, nil
}

func convertTypes(spec *btf.Spec, pointerSize int64, l limits.Limits) (*converter, BTFTypes, error) {
	if spec == nil || len(spec.Types) == 0 {
		return nil, BTFTypes{}, ErrNoBTF
	}
	if pointerSize != 4 && pointerSize != 8 {
		return nil, BTFTypes{}, fmt.Errorf("%w: %d", ErrPointerSize, pointerSize)
	}
	if n := len(spec.Types) - 1; n > l.Effective().MaxTableEntries {
		return nil, BTFTypes{}, fmt.Errorf("%w: %d", ErrTooManyTypes, n)
	}
	c := newConverter(spec, l, &TypeReport{})
	return c, c.convert(), nil
}

func AssembleLinux(k LinuxKernel) (symbols.Declaration, LinuxReport, error) {
	var report LinuxReport
	if len(k.Banner) == 0 || !utf8.Valid(k.Banner) || bytes.IndexByte(k.Banner[:len(k.Banner)-1], 0) >= 0 {
		return symbols.Declaration{}, report, ErrBanner
	}
	if k.Rule != kallsyms.RuleAbsolutePercpu && k.Rule != kallsyms.RuleRelative {
		return symbols.Declaration{}, report, fmt.Errorf("%w: %v", ErrAddressRule, k.Rule)
	}
	c, types, err := convertTypes(k.BTF, k.PointerSize, k.Limits)
	if err != nil {
		return symbols.Declaration{}, report, err
	}
	linked := linkedNames(k, &report)
	if _, ok := linked["linux_banner"]; !ok {
		return symbols.Declaration{}, report, ErrBannerSymbol
	}
	typed := c.variableTypes(linked, &report)
	report.Types = *c.report
	d := symbols.Declaration{
		PointerWidth: uint8(k.PointerSize),
		LinuxBanner:  append([]byte(nil), k.Banner...),
		Scalars:      types.Scalars,
		Records:      types.Records,
		Enumerations: types.Enumerations,
		Addresses:    make([]symbols.Address, 0, len(linked)),
	}
	for name, a := range linked {
		entry := symbols.Address{Name: name, Address: a}
		if ref, ok := typed[name]; ok {
			entry.Type = &ref
		}
		d.Addresses = append(d.Addresses, entry)
	}
	sort.Slice(d.Addresses, func(i, j int) bool { return d.Addresses[i].Name < d.Addresses[j].Name })
	return d, report, nil
}
