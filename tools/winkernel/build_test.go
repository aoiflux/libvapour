package winkernel

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
)

// Separate readable pages; anything else does not read.
type pageMem map[uint64][]byte

func (m pageMem) ReadAt(at, size uint64) ([]byte, error) {
	page, ok := m[at&^0xfff]
	if !ok || at&0xfff+size > uint64(len(page)) {
		return nil, errors.New("not mapped")
	}
	off := at & 0xfff
	return append([]byte(nil), page[off:off+size]...), nil
}

func (m pageMem) Size() uint64 { return 0 }

const buildGlobal = uint64(0xFFFFF80000c3f000)

type buildImage struct {
	pointer              uint8
	members              []string
	noSymbol             bool
	noShared, noGlobal   bool
	major, minor, shared uint32
	global               uint32
}

func (b buildImage) open() (symbols.SymbolTable, pageMem) {
	if b.pointer == 0 {
		b.pointer = 8
	}
	if b.members == nil {
		b.members = []string{"NtBuildNumber", "NtMajorVersion", "NtMinorVersion"}
	}
	offsets := map[string]uint64{"NtBuildNumber": 0x260, "NtMajorVersion": 0x26c, "NtMinorVersion": 0x270}
	var fields []symbols.Field
	for _, m := range b.members {
		fields = append(fields, symbols.Field{Name: m, Offset: offsets[m]})
	}
	table := symbols.NewTable("k", b.pointer)
	table.AddStruct(symbols.StructType{Name: "_KUSER_SHARED_DATA", Size: 0x720, Fields: fields})
	if !b.noSymbol {
		table.AddSymbol(symbols.Symbol{Name: "NtBuildNumber", Address: buildGlobal + 0x10})
	}
	mem := pageMem{}
	if !b.noShared {
		page := make([]byte, 0x1000)
		binary.LittleEndian.PutUint32(page[0x260:], b.shared)
		binary.LittleEndian.PutUint32(page[0x26c:], b.major)
		binary.LittleEndian.PutUint32(page[0x270:], b.minor)
		base := sharedData64
		if b.pointer == 4 {
			base = sharedData32
		}
		mem[base] = page
	}
	if !b.noGlobal {
		page := make([]byte, 0x1000)
		binary.LittleEndian.PutUint32(page[0x10:], b.global)
		mem[buildGlobal] = page
	}
	return table, mem
}

func readImage(b buildImage) Build {
	table, mem := b.open()
	return ReadBuild("test.tool", mem, table)
}

func TestEveryBuildValueReads(t *testing.T) {
	got := readImage(buildImage{major: 10, minor: 0, shared: 19045, global: 0xF0000000 | 19045})
	want := Build{Major: 10, Minor: 0, Kernel: 19045, Decoration: 0xF, Shared: 19045}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got.Missing() != nil {
		t.Errorf("Missing: %v", got.Missing())
	}
}

func TestTheDecorationIsTheTopFourBits(t *testing.T) {
	got := readImage(buildImage{major: 10, global: 0xC0004A61})
	if got.Kernel != 0x4A61 || got.Decoration != 0xC {
		t.Errorf("kernel %d decoration %#x, want 19041 and 0xc", got.Kernel, got.Decoration)
	}
}

func TestAMissingMemberLeavesOnlyItsValueUnread(t *testing.T) {
	noMajor := readImage(buildImage{members: []string{"NtBuildNumber", "NtMinorVersion"}, major: 10, minor: 3, shared: 9600, global: 9600})
	if !errors.Is(noMajor.VersionErr, ErrBuildUnread) || noMajor.Major != 0 || noMajor.Minor != 0 {
		t.Errorf("no NtMajorVersion: %+v", noMajor)
	}
	if noMajor.SharedErr != nil || noMajor.KernelErr != nil || noMajor.Shared != 9600 {
		t.Errorf("no NtMajorVersion spoiled other values: %+v", noMajor)
	}
	if !errors.Is(noMajor.Missing(), ErrBuildUnread) {
		t.Errorf("Missing: %v", noMajor.Missing())
	}

	noMinor := readImage(buildImage{members: []string{"NtBuildNumber", "NtMajorVersion"}, major: 10})
	if !errors.Is(noMinor.VersionErr, ErrBuildUnread) || noMinor.Major != 0 {
		t.Errorf("no NtMinorVersion: %+v", noMinor)
	}

	noShared := readImage(buildImage{members: []string{"NtMajorVersion", "NtMinorVersion"}, major: 6, minor: 3, global: 9600})
	if !errors.Is(noShared.SharedErr, ErrBuildUnread) || noShared.VersionErr != nil || noShared.Kernel != 9600 {
		t.Errorf("no shared NtBuildNumber: %+v", noShared)
	}

	noSymbol := readImage(buildImage{noSymbol: true, major: 10, shared: 22631})
	if !errors.Is(noSymbol.KernelErr, ErrBuildUnread) || noSymbol.Shared != 22631 || noSymbol.Kernel != 0 {
		t.Errorf("no NtBuildNumber symbol: %+v", noSymbol)
	}
	if !errors.Is(noSymbol.Missing(), ErrBuildUnread) {
		t.Errorf("Missing: %v", noSymbol.Missing())
	}
}

func TestAReadThatFailsLeavesOnlyItsValueUnread(t *testing.T) {
	noPage := readImage(buildImage{noShared: true, global: 26100})
	if !errors.Is(noPage.VersionErr, ErrBuildUnread) || !errors.Is(noPage.SharedErr, ErrBuildUnread) || noPage.Kernel != 26100 {
		t.Errorf("no shared page: %+v", noPage)
	}
	noGlobal := readImage(buildImage{noGlobal: true, major: 10, shared: 26100})
	if !errors.Is(noGlobal.KernelErr, ErrBuildUnread) || noGlobal.VersionErr != nil || noGlobal.Shared != 26100 {
		t.Errorf("no global page: %+v", noGlobal)
	}
}

func TestAFourByteTableReadsTheX86SharedData(t *testing.T) {
	got := readImage(buildImage{pointer: 4, major: 6, minor: 1, shared: 7601, global: 0xF0000000 | 7601})
	if got.Major != 6 || got.Minor != 1 || got.Shared != 7601 || got.VersionErr != nil || got.SharedErr != nil {
		t.Errorf("got %+v", got)
	}
	if SharedDataAddress(symbols.NewTable("k", 4)) != 0xFFDF0000 || SharedDataAddress(symbols.NewTable("k", 8)) != 0xFFFFF78000000000 {
		t.Error("shared data address does not follow the pointer size")
	}
}

func TestNoReaderOrTableReadsNothing(t *testing.T) {
	table, _ := buildImage{}.open()
	for _, got := range []Build{ReadBuild("t", nil, table), ReadBuild("t", pageMem{}, nil)} {
		if !errors.Is(got.VersionErr, ErrBuildUnread) || !errors.Is(got.KernelErr, ErrBuildUnread) || !errors.Is(got.SharedErr, ErrBuildUnread) {
			t.Errorf("got %+v", got)
		}
	}
}

func TestAValueIsReturnedAsReadWithoutJudgement(t *testing.T) {
	got := readImage(buildImage{major: 0xffffffff, minor: 7, shared: 0, global: 0})
	if got.Major != 0xffffffff || got.Minor != 7 || got.Kernel != 0 || got.Shared != 0 || got.Missing() != nil {
		t.Errorf("got %+v", got)
	}
}

func TestFileSetBuildFoldsTheSharedReleasesOntoTheFirst(t *testing.T) {
	for in, want := range map[uint32]uint32{19040: 19040, 19041: 19041, 19042: 19041, 19044: 19041, 19045: 19041, 19046: 19046, 26100: 26100} {
		if got := FileSetBuild(in); got != want {
			t.Errorf("build %d: got %d, want %d", in, got, want)
		}
	}
}
