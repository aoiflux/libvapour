package linuxmodule

import (
	"fmt"
	"strconv"
	"strings"
)

type paramKind uint8

const (
	paramUnknown paramKind = iota
	paramUnsigned
	paramSigned
	paramHex
	paramBool
	paramInvBool
	paramCharp
	paramString
	paramArray
)

type paramType struct {
	kind  paramKind
	width uint64
}

// paramOps maps each standard kernel_param_ops symbol to how its getter
// prints (S07 P2, P3). A width of 0 means pointer-width.
var paramOps = map[string]paramType{
	"param_ops_byte":             {paramUnsigned, 1},
	"param_ops_short":            {paramSigned, 2},
	"param_ops_ushort":           {paramUnsigned, 2},
	"param_ops_int":              {paramSigned, 4},
	"param_ops_uint":             {paramUnsigned, 4},
	"param_ops_long":             {paramSigned, 0},
	"param_ops_ulong":            {paramUnsigned, 0},
	"param_ops_ullong":           {paramUnsigned, 8},
	"param_ops_hexint":           {paramHex, 4},
	"param_ops_bool":             {paramBool, 1},
	"param_ops_bool_enable_only": {paramBool, 1},
	"param_ops_invbool":          {paramInvBool, 1},
	"param_ops_bint":             {paramSigned, 4},
	"param_ops_charp":            {paramCharp, 0},
	"param_ops_string":           {paramString, 0},
	"param_array_ops":            {paramArray, 0},
}

type Parameter struct {
	Name    string
	Value   string
	Decoded bool
}

type Parameters struct {
	List   []Parameter
	Unread int
	Capped bool
}

// paramValueBytes is PAGE_SIZE, the buffer every getter prints into (S07 P5).
const paramValueBytes = 4096

func (m *Model) opsTable() map[uint64]paramType {
	out := map[uint64]paramType{}
	for name, t := range paramOps {
		if at, ok := m.symbol(name); ok && at != 0 {
			if t.width == 0 && t.kind != paramCharp && t.kind != paramString && t.kind != paramArray {
				t.width = m.width
			}
			out[at] = t
		}
	}
	return out
}

// Parameters decodes a module's kernel_param table (S07 4.6).
func (m *Model) Parameters(mod Module) (Parameters, error) {
	s := &m.s
	if !s.hasParams {
		return Parameters{}, fmt.Errorf("linuxmodule: module.kp: %w", ErrUnsupported)
	}
	nameOff, err1 := m.offset("kernel_param", "name")
	opsOff, err2 := m.offset("kernel_param", "ops")
	argOff, err3 := m.offset("kernel_param", "arg")
	size, err4 := m.size("kernel_param")
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return Parameters{}, fmt.Errorf("linuxmodule: kernel_param: %w", ErrUnsupported)
	}
	kp, ok1 := m.pointer(mod.Address + s.kpPointer)
	count, ok2 := m.uintField(mod.Address, s.numKP)
	if !ok1 || !ok2 {
		return Parameters{}, ErrUnreadable
	}
	var out Parameters
	if lim := uint64(m.r.Limits.Effective().MaxTableEntries); lim > 0 && count > lim {
		count, out.Capped = lim, true
	}
	if count == 0 || kp == 0 {
		return out, nil
	}
	ops := m.opsTable()
	nameLimit := uint64(m.r.Limits.Effective().MaxNameBytes)
	for i := range count {
		at := kp + i*size
		namePtr, ok1 := m.pointer(at + nameOff)
		opsPtr, ok2 := m.pointer(at + opsOff)
		arg, ok3 := m.pointer(at + argOff)
		if !ok1 || !ok2 || !ok3 {
			out.Unread++
			continue
		}
		name, _, ok := m.cstring(namePtr, nameLimit)
		if !ok {
			out.Unread++
			continue
		}
		p := Parameter{Name: name}
		p.Value, p.Decoded = m.paramValue(ops, ops[opsPtr], arg, 0)
		out.List = append(out.List, p)
	}
	return out, nil
}

func (m *Model) paramValue(ops map[uint64]paramType, t paramType, arg uint64, depth int) (string, bool) {
	switch t.kind {
	case paramUnsigned, paramSigned, paramHex, paramBool, paramInvBool:
		v, ok := m.uintAt(arg, t.width)
		if !ok {
			return "", false
		}
		return formatScalar(t, v), true
	case paramCharp:
		p, ok := m.pointer(arg)
		if !ok {
			return "", false
		}
		if p == 0 {
			return "(null)", true
		}
		s, _, ok := m.cstring(p, paramValueBytes)
		return s, ok
	case paramString:
		off, err := m.offset("kparam_string", "string")
		if err != nil {
			return "", false
		}
		p, ok := m.pointer(arg + off)
		if !ok {
			return "", false
		}
		s, _, ok := m.cstring(p, paramValueBytes)
		return s, ok
	case paramArray:
		if depth > 0 {
			return "", false
		}
		return m.paramArray(ops, arg)
	}
	return "", false
}

func (m *Model) paramArray(ops map[uint64]paramType, arr uint64) (string, bool) {
	var off [5]uint64
	for i, name := range []string{"max", "elemsize", "num", "ops", "elem"} {
		var err error
		if off[i], err = m.offset("kparam_array", name); err != nil {
			return "", false
		}
	}
	maxN, ok1 := m.uintAt(arr+off[0], 4)
	elemSize, ok2 := m.uintAt(arr+off[1], 4)
	numPtr, ok3 := m.pointer(arr + off[2])
	opsPtr, ok4 := m.pointer(arr + off[3])
	elem, ok5 := m.pointer(arr + off[4])
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return "", false
	}
	count := maxN
	if numPtr != 0 {
		n, ok := m.uintAt(numPtr, 4)
		if !ok {
			return "", false
		}
		count = n
	}
	if lim := uint64(m.r.Limits.Effective().MaxTableEntries); lim > 0 && count > lim {
		return "", false
	}
	t, known := ops[opsPtr]
	if !known || t.kind == paramArray {
		return "", false
	}
	parts := make([]string, 0, count)
	for i := range count {
		v, ok := m.paramValue(ops, t, elem+i*elemSize, 1)
		if !ok {
			return "", false
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, ","), true
}

func formatScalar(t paramType, v uint64) string {
	switch t.kind {
	case paramSigned:
		shift := 64 - 8*t.width
		return strconv.FormatInt(int64(v<<shift)>>shift, 10)
	case paramHex:
		// C's # flag adds no 0x to zero, so %#08x prints 0 as eight zeros.
		if v == 0 {
			return "00000000"
		}
		return fmt.Sprintf("%#08x", v)
	case paramBool:
		if v&0xff != 0 {
			return "Y"
		}
		return "N"
	case paramInvBool:
		if v&0xff != 0 {
			return "N"
		}
		return "Y"
	}
	return strconv.FormatUint(v, 10)
}

// Text is the S07 4.6 step 5 form.
func (p Parameters) Text() string {
	parts := make([]string, len(p.List))
	for i, q := range p.List {
		if q.Decoded {
			parts[i] = q.Name + "=" + q.Value
		} else {
			parts[i] = q.Name
		}
	}
	return strings.Join(parts, " ")
}
