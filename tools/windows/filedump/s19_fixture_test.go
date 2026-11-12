package filedump

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	fxKernel = uint64(0xFFFF800000000000)
	fxPages  = 96

	fxFO       = fxKernel + 0x1000
	fxFO2      = fxKernel + 0x1100
	fxDevice   = fxKernel + 0x2000
	fxSOP      = fxKernel + 0x3000
	fxFCB      = fxKernel + 0x4000
	fxNameBuf  = fxKernel + 0x5000
	fxDataCA   = fxKernel + 0x6000
	fxDataSeg  = fxKernel + 0x7000
	fxDataPTEs = fxKernel + 0x8000
	fxImageCA  = fxKernel + 0x9000
	fxImageSeg = fxKernel + 0xA000
	fxImgPTEs  = fxKernel + 0xB000
	fxMap      = fxKernel + 0xC000
	fxArraysAt = fxKernel + 0xD000
	fxHighest  = fxKernel + 0xD008
	fxArrays   = fxKernel + 0xD100
	fxHeader   = fxKernel + 0xE000
	fxView     = fxKernel + 0x40000

	fxName = `\docs\a.txt`
)

type kernelWriter struct {
	pm     *testsupport.PagedMemory
	va, pa uint64
}

func (k kernelWriter) at(va uint64) uint64 { return k.pa + (va - k.va) }

func (k kernelWriter) WriteU16(va uint64, v uint16) { k.pm.WriteU16(k.at(va), v) }
func (k kernelWriter) WriteU32(va uint64, v uint32) { k.pm.WriteU32(k.at(va), v) }
func (k kernelWriter) WriteU64(va uint64, v uint64) { k.pm.WriteU64(k.at(va), v) }

type fixture struct {
	pm    *testsupport.PagedMemory
	k     kernelWriter
	dtb   uint64
	table *symbols.Table
	data  []uint64
	diags []string
	opts  map[string]any
}

func fill(b byte) []byte { return bytes.Repeat([]byte{b}, 0x1000) }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := buildFixture()
	f.opts[tools.OptionOutputDir] = t.TempDir()
	return f
}

func buildFixture() *fixture {
	pm := testsupport.NewPagedMemory(2 << 20)
	f := &fixture{pm: pm, table: testsupport.S19Table()}
	base := pm.AllocPage()
	for i := 1; i < fxPages; i++ {
		pm.AllocPage()
	}
	for i := 0; i < 6; i++ {
		page := pm.AllocPage()
		pm.WriteAt(page, fill(byte('A'+i)))
		f.data = append(f.data, page)
	}
	as := pm.NewAddressSpace()
	for i := uint64(0); i < fxPages; i++ {
		as.Map(fxKernel+i*0x1000, base+i*0x1000)
	}
	f.dtb = as.DTB
	f.k = kernelWriter{pm: pm, va: fxKernel, pa: base}
	testsupport.S19AddVacbSymbols(f.table, fxArraysAt, fxHighest)

	name := utf16.Encode([]rune(fxName))
	for i, c := range name {
		f.k.WriteU16(fxNameBuf+uint64(2*i), c)
	}
	testsupport.WriteS19FileObject(f.k, testsupport.S19FileObject{Address: fxFO, Type: 5,
		Size: testsupport.S19FileObjectSize, Device: fxDevice, SOP: fxSOP, FsContext: fxFCB, Name: fxNameBuf,
		NameBytes: uint16(2 * len(name))})
	testsupport.WriteS19Device(f.k, fxDevice, deviceDisk)
	testsupport.WriteS19FileSize(f.k, fxFCB, 0x1800)
	testsupport.WriteS19SectionPointers(f.k, fxSOP, fxDataCA, 0, 0)

	testsupport.WriteS19ControlArea(f.k, testsupport.S19ControlArea{Address: fxDataCA, Segment: fxDataSeg,
		TotalPtes: 2, SizeOfSegment: 0x2000, File: true, FilePointer: fxFO | 3})
	testsupport.WriteS19Subsection(f.k, testsupport.S19Subsection{Address: fxDataCA + testsupport.S19ControlAreaSize,
		ControlArea: fxDataCA, Base: fxDataPTEs, Ptes: 2, FullSectors: 2})
	f.k.WriteU64(fxDataPTEs, testsupport.S19ValidPTE(f.data[0]))
	f.k.WriteU64(fxDataPTEs+8, testsupport.S19TransitionPTE(f.data[1]))

	f.k.WriteU64(fxArraysAt, fxArrays)
	f.k.WriteU32(fxHighest, 0)
	f.k.WriteU64(fxArrays, fxHeader)

	f.opts = map[string]any{
		"diagnostics":              &f.diags,
		tools.OptionPhysicalMemory: memory.MemoryReader(pm),
		OptionVirtAddr:             []uint64{fxFO},
	}
	return f
}

func (f *fixture) withImage(t *testing.T) {
	testsupport.WriteS19SectionPointers(f.k, fxSOP, 0, 0, fxImageCA)
	testsupport.WriteS19ControlArea(f.k, testsupport.S19ControlArea{Address: fxImageCA, Segment: fxImageSeg,
		TotalPtes: 2, SizeOfSegment: 0x2000, Image: true, File: true, FilePointer: fxFO})
	testsupport.WriteS19Subsection(f.k, testsupport.S19Subsection{Address: fxImageCA + testsupport.S19ControlAreaSize,
		ControlArea: fxImageCA, Base: fxImgPTEs, Next: fxImageCA + testsupport.S19ControlAreaSize + testsupport.S19SubsectionSize,
		Ptes: 1, FullSectors: 2})
	testsupport.WriteS19Subsection(f.k, testsupport.S19Subsection{Address: fxImageCA + testsupport.S19ControlAreaSize + testsupport.S19SubsectionSize,
		ControlArea: fxImageCA, Base: fxImgPTEs + 8, Ptes: 1, Sector: 2, FullSectors: 1})
	f.k.WriteU64(fxImgPTEs, testsupport.S19ValidPTE(f.data[2]))
	f.k.WriteU64(fxImgPTEs+8, testsupport.S19ValidPTE(f.data[3]))
	testsupport.WriteS19FileSize(f.k, fxFCB, 0x800)
}

func (f *fixture) withCacheMap(fileSize, sectionSize uint64, vacbs ...testsupport.S19Vacb) {
	testsupport.WriteS19SectionPointers(f.k, fxSOP, 0, fxMap, 0)
	testsupport.WriteS19CacheMap(f.k, testsupport.S19CacheMap{Address: fxMap, Node: sharedCacheMapNode,
		ByteSize: testsupport.S19CacheMapSize, FileSize: fileSize, SectionSize: sectionSize, FileRef: fxFO | 1})
	testsupport.WriteS19VacbArray(f.k, fxHeader, 0, vacbs)
}

func (f *fixture) context() tools.Context {
	return tools.Context{
		Memory:  layers.NewProcessLayer(f.pm, f.dtb, 0),
		Symbols: f.table,
		Profile: profiles.WindowsX64Profile{},
		Options: f.opts,
	}
}

func (f *fixture) run(t *testing.T) []Artifact {
	t.Helper()
	out, err := RunAny(f.context())
	if err != nil {
		t.Fatalf("RunAny: %v", err)
	}
	return out.([]Artifact)
}

func (f *fixture) said(parts ...string) bool {
	for _, d := range f.diags {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(d, p)
		}
		if all {
			return true
		}
	}
	return false
}

func (f *fixture) artefact(t *testing.T, a Artifact) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.opts[tools.OptionOutputDir].(string), a.FileName))
	if err != nil {
		t.Fatalf("artefact %s: %v", a.FileName, err)
	}
	return data
}

func only(t *testing.T, rows []Artifact, cache string) Artifact {
	t.Helper()
	var found []Artifact
	for _, r := range rows {
		if r.Cache == cache {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d %s rows in %+v", len(found), cache, rows)
	}
	return found[0]
}
