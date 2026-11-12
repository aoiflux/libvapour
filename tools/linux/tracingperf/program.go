package tracingperf

import (
	"encoding/hex"
	"errors"

	"github.com/aoiflux/libvapour/tools/linuxtrace"
)

// PE7: BPF_TAG_SIZE.
const tagBytes = 8

type program struct {
	id           uint64
	name, symbol string
	code         uint64
}

// PE7: bpf_get_prog_name (v4.19) and bpf_prog_ksym_set_name (from v5.x) both
// start the kernel symbol with "bpf_prog_" and the hexadecimal tag; v4.19
// adds "_" and the program's own name when it has one.
func programSymbol(tag []byte, name string) string {
	s := "bpf_prog_" + hex.EncodeToString(tag)
	if name != "" {
		s += "_" + name
	}
	return s
}

// PE6, PE7: the kernel's own symbol text is bpf_prog_aux.ksym.name where the
// table has it; otherwise it is built as v4.19 builds it.
func readProgram(k *linuxtrace.Kernel, prog uint64) (program, error) {
	var p program
	aux, err := k.Pointer(prog, "bpf_prog", "aux")
	if err != nil {
		return p, err
	}
	code, err := k.Pointer(prog, "bpf_prog", "bpf_func")
	if err != nil {
		return p, err
	}
	p.code = code
	if k.Masked(aux) == 0 {
		return p, errors.New("tracingperf: bpf_prog.aux is null")
	}
	if p.id, err = k.Uint(aux, "bpf_prog_aux", "id"); err != nil {
		return p, err
	}
	if p.name, err = k.CharArray(aux, "bpf_prog_aux", "name"); err != nil {
		return p, err
	}
	if k.Has("bpf_prog_aux", "ksym") && k.Has("bpf_ksym", "name") {
		f, err := k.Field("bpf_prog_aux", "ksym")
		if err != nil {
			return p, err
		}
		if p.symbol, err = k.CharArray(aux+f.Offset, "bpf_ksym", "name"); err != nil {
			return p, err
		}
		if p.symbol != "" {
			return p, nil
		}
	}
	f, err := k.Field("bpf_prog", "tag")
	if err != nil {
		return p, err
	}
	n := f.Type.ArrayLength
	if n != tagBytes {
		return p, errors.New("tracingperf: bpf_prog.tag is not BPF_TAG_SIZE bytes")
	}
	tag, err := k.Memory().ReadAt(prog+f.Offset, n)
	if err == nil && uint64(len(tag)) < n {
		err = errors.New("tracingperf: bpf_prog.tag reads short")
	}
	if err != nil {
		return p, err
	}
	p.symbol = programSymbol(tag, p.name)
	return p, nil
}
