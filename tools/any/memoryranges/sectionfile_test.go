package memoryranges

import (
	"strings"
	"testing"
)

func fileNames(t *testing.T, img *tImage) FileNames {
	t.Helper()
	f, err := ResolveFileNames(img.ctx(nil))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestASectionViewNamesItsFile(t *testing.T) {
	img := fourKinds()
	f := fileNames(t, img)
	m, ok := f.Resolve(img.ctx(nil), nodeAt(2))
	page := tNodeBase + 2*tNodeStride
	if !ok || m.Path != `\Windows\System32\ntdll.dll` || m.ControlArea != page+0x500 || m.FileObject != page+0x600 || m.NameUnreadable {
		t.Errorf("Resolve = %+v, %v", m, ok)
	}
	if name, ok := f.Name(img.ctx(nil), nodeAt(2)); !ok || name != m.Path {
		t.Errorf("Name = %q, %v", name, ok)
	}
}

func TestAPrivateVADNamesNoFileWhateverFollowsIt(t *testing.T) {
	img := fourKinds()
	img.putFile(1, `\stale.dll`, true)
	f := fileNames(t, img)
	if m, ok := f.Resolve(img.ctx(nil), nodeAt(1)); ok || m != (MappedFile{NoFile: true}) {
		t.Errorf("Resolve on a private VAD = %+v, %v", m, ok)
	}
	if got := f.Of(img.ctx(nil), nodeAt(1)); got != "" {
		t.Errorf("Of = %q", got)
	}
}

func TestAControlAreaWithoutFileNamesNoFile(t *testing.T) {
	img := fourKinds()
	img.putFile(3, `\pagefile section`, false)
	f := fileNames(t, img)
	m, ok := f.Resolve(img.ctx(nil), nodeAt(3))
	if ok || m.FileObject != 0 || m.ControlArea == 0 || !m.NoFile {
		t.Errorf("Resolve = %+v, %v", m, ok)
	}
	if row := mappings(t, img, nil)[2]; !row.NoFile || row.PathUnreadable || row.Path != "" {
		t.Errorf("row %+v", row)
	}
}

func TestAFilePointerOfZeroNamesNoFile(t *testing.T) {
	img := fourKinds()
	page := tNodeBase + 3*tNodeStride
	img.mem.u64(page+0x500+tCAFile, 0)
	f := fileNames(t, img)
	if m, ok := f.Resolve(img.ctx(nil), nodeAt(3)); ok || !m.NoFile {
		t.Errorf("Resolve = %+v, %v", m, ok)
	}
}

func TestAControlAreaThatDoesNotReadIsNotNoFile(t *testing.T) {
	img := fourKinds()
	page := tNodeBase + 3*tNodeStride
	img.mem.drop(page+0x500+tCAFlags, 4)
	f := fileNames(t, img)
	if m, ok := f.Resolve(img.ctx(nil), nodeAt(3)); ok || m.NoFile {
		t.Errorf("Resolve = %+v, %v", m, ok)
	}
	if row := mappings(t, img, nil)[2]; row.NoFile || !row.PathUnreadable {
		t.Errorf("row %+v", row)
	}
}

func TestAnUnreadableNameIsSaidSo(t *testing.T) {
	img := fourKinds()
	page := tNodeBase + 3*tNodeStride
	img.mem.drop(page+0x800, 2)
	f := fileNames(t, img)
	m, ok := f.Resolve(img.ctx(nil), nodeAt(3))
	if !ok || !m.NameUnreadable || m.Path != "" {
		t.Errorf("Resolve = %+v, %v", m, ok)
	}
	if _, ok := f.Name(img.ctx(nil), nodeAt(3)); ok {
		t.Error("Name reported an unreadable name")
	}
	rows := mappings(t, img, nil)
	if !rows[2].PathUnreadable || rows[2].NoFile || rows[2].Path != "" {
		t.Errorf("row %+v", rows[2])
	}
}

func TestALongNameIsReadWhole(t *testing.T) {
	long := `\Device\HarddiskVolume3\` + strings.Repeat("d", 5000) + `.dll`
	img := newImage([]tVAD{{start: 0x10000, end: 0x10fff, file: long}})
	img.root(0)
	f := fileNames(t, img)
	if got := f.Of(img.ctx(nil), nodeAt(0)); got != long {
		t.Errorf("read %d characters, want %d", len(got), len(long))
	}
}

func TestWithoutPrivateMemoryTheTagMarksASectionView(t *testing.T) {
	img := fourKinds()
	img.t.AddStruct(symbolsWithout(img, "_MMVAD_FLAGS", "PrivateMemory"))
	f := fileNames(t, img)
	if _, ok := f.Resolve(img.ctx(nil), nodeAt(2)); !ok {
		t.Error(`a "Vad " VAD named no file`)
	}
	if _, ok := f.Resolve(img.ctx(nil), nodeAt(0)); ok {
		t.Error(`a "VadS" VAD named a file`)
	}
	vads, err := ProcessVADs(img.ctx(nil), tProcess)
	if err != nil {
		t.Fatal(err)
	}
	if vads[0].PrivateMemoryKnown || vads[0].IsMMVAD() || !vads[3].IsMMVAD() {
		t.Errorf("VADs %+v", vads)
	}
}

func TestFileNamesNeedTheirChain(t *testing.T) {
	img := fourKinds()
	img.t.AddStruct(symbolsWithout(img, "_MMVAD", "Subsection"))
	if _, err := ResolveFileNames(img.ctx(nil)); err == nil {
		t.Error("no error without _MMVAD.Subsection")
	}
	rows := mappings(t, img, nil)
	if rows[3].Path != "" || len(img.diags) != 1 || !strings.Contains(img.diags[0], "VAD file names not read") {
		t.Errorf("rows %+v diagnostics %q", rows[3], img.diags)
	}
}

func TestAnEmptyNameIsReadAndNamesNoPath(t *testing.T) {
	img := fourKinds()
	img.putFile(3, "", true)
	row := mappings(t, img, nil)[2]
	if row.Path != "" || row.PathUnreadable || row.NoFile {
		t.Errorf("row %+v", row)
	}
}
