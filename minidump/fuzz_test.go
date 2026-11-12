package minidump

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/extract"
)

func FuzzValidate(f *testing.F) {
	var buf bytes.Buffer
	if _, err := Write(&buf, fullInput()); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
	f.Add(buf.Bytes()[:200])
	f.Add([]byte("MDMP\x93\xa7"))
	f.Fuzz(func(t *testing.T, data []byte) {
		a := Validate(data)
		if a.Size != uint64(len(data)) || uint64(len(a.Streams)) > uint64(a.NumberOfStreams) {
			t.Fatalf("audit %+v for %d bytes", a, len(data))
		}
		if len(data) < headerSize && a.OK() {
			t.Fatal("a file shorter than the header passed")
		}
	})
}

// Each 24-byte record becomes a region and a thread; whatever Write accepts
// must validate.
func FuzzWrite(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{1, 0, 0, 0, 2, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0x02, 0, 1, 0, 0, 0, 0, 0x10, 0, 0}, 3))
	f.Fuzz(func(t *testing.T, data []byte) {
		var in Input
		in.System.ProcessorArchitecture = ProcessorArchitectureAMD64
		states := []uint32{MemCommit, MemReserve, MemFree, 0}
		types := []uint32{MemPrivate, MemMapped, MemImage, 0}
		for len(data) >= 24 && len(in.Regions) < 64 {
			r := data[:24]
			data = data[24:]
			base := uint64(binary.LittleEndian.Uint32(r)) << 12
			size := uint64(r[4]) << 12
			in.Regions = append(in.Regions, Region{
				BaseAddress: base, Size: size, State: states[r[6]%4], Type: types[r[7]%4], Dumpable: r[8]&1 == 1,
			})
			th := Thread{ID: binary.LittleEndian.Uint32(r[9:]), StackBase: base + uint64(r[13])<<8, StackSize: uint64(binary.LittleEndian.Uint16(r[14:])), Teb: uint64(r[16])}
			if r[17]&1 == 1 {
				th.Context = AMD64Context{Flags: ContextAMD64 | ContextControl, Rip: base}.Bytes()
			}
			in.Threads = append(in.Threads, th)
			in.Modules = append(in.Modules, Module{Base: base, Size: size, Name: string(r[18:24])})
			in.Handles = append(in.Handles, Handle{Handle: uint64(r[18]), TypeName: string(r[19:21])})
		}
		in.ReadMemory = func(base, size uint64) ([]byte, extract.GapMap) {
			if base&0x1000 != 0 {
				return nil, extract.GapMap{{Start: base, Length: size}}
			}
			return bytes.Repeat([]byte{byte(base >> 12)}, int(size)), nil
		}
		var buf bytes.Buffer
		res, err := Write(&buf, in)
		if err != nil {
			for _, want := range []error{ErrRegionRange, ErrRegionOverlap, ErrRegionAttributes} {
				if errors.Is(err, want) {
					return
				}
			}
			t.Fatalf("unexpected refusal: %v", err)
		}
		if res.Size != uint64(buf.Len()) {
			t.Fatalf("Result.Size %d, file %d", res.Size, buf.Len())
		}
		if a := Validate(buf.Bytes()); !a.OK() {
			t.Fatalf("written dump fails: %q", a.Problems)
		}
	})
}
