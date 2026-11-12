package imagelayers

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/layers"
)

func FuzzKernelELFHeaders(f *testing.F) {
	f.Add([]byte{0, 0, 0x20, 0, 0, 0, 0, 0}, true)
	f.Add(make([]byte, 64), false)
	f.Fuzz(func(t *testing.T, b []byte, wide bool) {
		var runs []layers.MappedRun
		va := uint64(0xffff800000000000)
		for i := 0; i+2 <= len(b) && len(runs) < 512; i += 2 {
			size := (uint64(binary.LittleEndian.Uint16(b[i:]))%64 + 1) * 0x1000
			runs = append(runs, layers.MappedRun{Virtual: va, Physical: uint64(i) << 12, Size: size})
			va += size + 0x1000
		}
		machine := uint16(machine386)
		if wide {
			machine = machineX8664
		}
		head, offsets := elfHeaders(runs, machine)
		file, err := elf.NewFile(bytes.NewReader(head))
		if err != nil {
			t.Fatalf("%d runs: %v", len(runs), err)
		}
		if file.Type != elf.ET_CORE || uint16(file.Machine) != machine || len(file.Progs) != len(runs) {
			t.Fatalf("header %v %v, %d programs for %d runs", file.Type, file.Machine, len(file.Progs), len(runs))
		}
		for i, p := range file.Progs {
			r := runs[i]
			if p.Vaddr != r.Virtual || p.Paddr != r.Physical || p.Filesz != r.Size || p.Off != offsets[i] || p.Off%0x1000 != 0 {
				t.Fatalf("program %d %+v for run %+v", i, p.ProgHeader, r)
			}
		}
		if n := len(runs); n > 0 && elfSize(runs) != offsets[n-1]+runs[n-1].Size {
			t.Fatalf("size %#x", elfSize(runs))
		}
	})
}
