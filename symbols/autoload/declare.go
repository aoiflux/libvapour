package autoload

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/symbols"
)

var errPDBUnusable = errors.New("autoload: pdb cannot give a symbol table")

// The table describes the PDB that was converted, so its build is read from
// the PDB itself and must be the one asked for: a server or proxy answering
// with another build's PDB would otherwise be cached as this build's table.
func pdbToDeclaration(pdbData []byte, fp *Fingerprint, maxDepth int) (symbols.Declaration, error) {
	c, err := readMSF(pdbData)
	if err != nil {
		return symbols.Declaration{}, err
	}
	stream := func(i int, label string) ([]byte, error) {
		if s := c.stream(i); s != nil {
			return s, nil
		}
		return nil, fmt.Errorf("%w: no %s stream (stream %d)", errPDBUnusable, label, i)
	}
	tpi, err := stream(pdbTypeStream, "type")
	if err != nil {
		return symbols.Declaration{}, err
	}
	graph, err := readTypeStream(tpi)
	if err != nil {
		return symbols.Declaration{}, err
	}
	graph.maxDepth = maxDepth
	dbi, err := stream(pdbDebugStream, "debug information")
	if err != nil {
		return symbols.Declaration{}, err
	}
	info, err := readDebugInfo(c, dbi)
	if err != nil {
		return symbols.Declaration{}, err
	}
	guid, err := pdbGUID(c.stream(pdbInfoStream))
	if err != nil {
		return symbols.Declaration{}, err
	}
	age := binary.LittleEndian.Uint32(dbi[debugAgeAt:])
	if !strings.EqualFold(guid, fp.GUID) || age != fp.Age {
		return symbols.Declaration{}, fmt.Errorf("%w: the pdb fetched for %s is build %s-%d, not the one requested", errPDBUnusable, fp, guid, age)
	}
	machine := binary.LittleEndian.Uint16(dbi[debugMachineAt:])
	_, width, ok := machinePointer(machine)
	if !ok {
		return symbols.Declaration{}, fmt.Errorf("%w: machine 0x%x has no known pointer width", errPDBUnusable, machine)
	}
	if len(info.sections) == 0 {
		return symbols.Declaration{}, fmt.Errorf("%w: no section headers to place a symbol with", errPDBUnusable)
	}
	addresses := collectAddresses(c, info, machine == machineI386)
	if len(addresses) == 0 {
		return symbols.Declaration{}, fmt.Errorf("%w: no symbol has a place in the image", errPDBUnusable)
	}
	records := collectRecords(graph)
	enums := collectEnumerations(graph)
	if graph.tooDeep {
		return symbols.Declaration{}, fmt.Errorf("%w: type records nest deeper than MaxRecursionDepth (%d), which only a cycle does",
			errPDBUnusable, graph.depthLimit())
	}
	return declaration(guid, age, width, records, enums, addresses), nil
}

func declaration(guid string, age uint32, width int, records map[string]pdbRecord, enums map[string]pdbEnum, addresses map[string]uint64) symbols.Declaration {
	d := symbols.Declaration{PointerWidth: uint8(width), WindowsPDB: &symbols.PDBBuild{GUID: guid, Age: age}}
	scalars := map[string]symbols.Scalar{"pointer": {Name: "pointer", Width: uint64(width), Kind: symbols.ScalarInteger}}
	for name, s := range declaredScalars {
		scalars[name] = s
	}
	for _, name := range keysInOrder(scalars) {
		d.Scalars = append(d.Scalars, scalars[name])
	}

	var recordAt textIndex
	for _, name := range keysInOrder(records) {
		r := records[name]
		if len(r.Fields) == 0 {
			continue
		}
		out := symbols.Record{Name: validText(name), Width: r.Size}
		var memberAt textIndex
		for _, field := range keysInOrder(r.Fields) {
			m := symbols.Member{Name: validText(field), Offset: r.Fields[field].Offset, Type: r.Fields[field].Type}
			put(&out.Members, &memberAt, m.Name, m)
		}
		put(&d.Records, &recordAt, out.Name, out)
	}

	var enumAt textIndex
	for _, name := range keysInOrder(enums) {
		e := enums[name]
		out := symbols.EnumType{Name: validText(name), Size: e.Size}
		if base, ok := scalars[e.Base]; ok && base.Width != 0 {
			out.Size = base.Width
		}
		var valueAt textIndex
		for _, constant := range keysInOrder(e.Constants) {
			v := symbols.EnumValue{Name: validText(constant), Value: e.Constants[constant]}
			put(&out.Values, &valueAt, v.Name, v)
		}
		put(&d.Enumerations, &enumAt, out.Name, out)
	}

	var addressAt textIndex
	for _, name := range keysInOrder(addresses) {
		a := symbols.Address{Name: validText(name), Address: addresses[name]}
		put(&d.Addresses, &addressAt, a.Name, a)
	}
	return d
}

// A table's names are UTF-8 text, so each byte that is not UTF-8 becomes
// U+FFFD.
// Two names that differ only in such bytes become one; the later in name
// order takes the earlier one's place, which keeps the result independent of
// map order.
type textIndex map[string]int

func put[T any](list *[]T, at *textIndex, name string, v T) {
	if *at == nil {
		*at = textIndex{}
	}
	if i, seen := (*at)[name]; seen {
		(*list)[i] = v
		return
	}
	(*at)[name] = len(*list)
	*list = append(*list, v)
}

func validText(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && n == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.WriteString(s[:n])
		}
		s = s[n:]
	}
	return b.String()
}

func keysInOrder[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
