package filescan

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
)

func run(t *testing.T, k *testsupport.S69Kernel) map[uint64]File {
	t.Helper()
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64]File{}
	for _, r := range rows {
		out[r.VirtualOffset] = r
	}
	return out
}

func TestAFileObjectIsListedWithNameDeviceAndAccess(t *testing.T) {
	k := testsupport.NewS69Kernel()
	dev := k.AddDevice("HarddiskVolume3", 0, 7)
	f := k.AddFile(`\Windows\System32\config\SYSTEM`, dev, true, true, false, true, false, false)
	k.Write(f+testsupport.S69FileDeletePend, []byte{1})
	rows := run(t, k)
	got, ok := rows[f]
	if !ok || len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	if got.Name != `\Windows\System32\config\SYSTEM` || got.NameUnreadable || got.Device != "HarddiskVolume3" ||
		got.DeviceUnreadable {
		t.Errorf("file = %+v", got)
	}
	if !got.ReadAccess || !got.WriteAccess || got.DeleteAccess || !got.SharedRead || got.SharedWrite ||
		got.SharedDelete || !got.DeletePending {
		t.Errorf("access = %+v", got)
	}
	if got.Offset != k.Physical(f) {
		t.Errorf("Offset 0x%x, want 0x%x", got.Offset, k.Physical(f))
	}
}

func TestBodiesThatAreNotFileObjectsAreRefused(t *testing.T) {
	k := testsupport.NewS69Kernel()
	dev := k.AddDevice("Null", 0, 0x15)
	size := k.AddFile(`\a`, dev)
	k.U16(size+2, 0x100)
	k.AddFile(`\b`, 0x7ff600000000)
	k.AddFile(`\c`, 0)
	kind := k.AddFile(`\d`, dev)
	k.U16(kind, 4)
	if rows := run(t, k); len(rows) != 0 {
		t.Errorf("rows = %+v, want none", rows)
	}
}

func TestNamesAreShownAsFoundAndFlaggedOnlyWhenTheyDoNotRead(t *testing.T) {
	k := testsupport.NewS69Kernel()
	dev := k.AddDevice("", 0, 8)
	empty := k.AddFile("", dev)
	odd := k.AddFile(`\x`, dev)
	k.U16(odd+testsupport.S69FileName, 3)
	gone := k.AddFile(`\y`, dev)
	k.U64(gone+testsupport.S69FileName+8, k.Skip())
	ctl := k.AddFile("\\z\x01", dev)
	rows := run(t, k)
	if r := rows[empty]; r.Name != "" || r.NameUnreadable || !r.DeviceUnreadable {
		t.Errorf("unnamed file on an unnamed device = %+v", r)
	}
	for _, at := range []uint64{odd, gone} {
		if r := rows[at]; !r.NameUnreadable || r.Name != "" {
			t.Errorf("file = %+v, want the name flagged", r)
		}
	}
	if r := rows[ctl]; r.Name != "\\z\x01" || r.NameUnreadable {
		t.Errorf("file = %+v, want the name as found", r)
	}
}

func TestFailures(t *testing.T) {
	ctx := testsupport.NewS69Kernel().Context()
	delete(ctx.Options, "physical_memory")
	if _, err := Run(ctx); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Errorf("no physical memory: %v", err)
	}
	k := testsupport.NewS69Kernel()
	st, _ := k.Table.Struct("_FILE_OBJECT")
	st.Fields = st.Fields[:2]
	k.Table.AddStruct(st)
	if _, err := Run(k.Context()); !errors.Is(err, ErrNoFileType) {
		t.Errorf("missing DeviceObject: %v", err)
	}
}

func TestPlausibleName(t *testing.T) {
	for name, want := range map[string]bool{`\Users\a\NTUSER.DAT`: true, "": false, "a\x01": false, "\ufffd": false,
		`\$Extend\$UsnJrnl:$J`: true} {
		if got := PlausibleName(name); got != want {
			t.Errorf("PlausibleName(%q) = %v, want %v", name, got, want)
		}
	}
}

type bytesReader []byte

func (b bytesReader) Size() uint64 { return uint64(len(b)) }

func (b bytesReader) ReadAt(off, n uint64) ([]byte, error) {
	if off > uint64(len(b)) || n > uint64(len(b))-off {
		return nil, memory.ErrOutOfBounds
	}
	return b[off : off+n], nil
}

func FuzzFileObjectBody(f *testing.F) {
	k := testsupport.NewS69Kernel()
	l, err := resolve(k.Table)
	if err != nil {
		f.Fatal(err)
	}
	l.namer, _ = scan.NewObjectNamer(k.Table)
	seed := make([]byte, 0x200)
	binary.LittleEndian.PutUint16(seed[0x30+2:], uint16(testsupport.S69FileSize))
	binary.LittleEndian.PutUint64(seed[0x30+8:], 0x8000000000000100)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		r := bytesReader(raw)
		got, ok := l.decode(r, r, 0x8000000000000000, true, 0x30)
		if !ok {
			return
		}
		body := raw[0x30:]
		if binary.LittleEndian.Uint16(body[2:]) != uint16(testsupport.S69FileSize) {
			t.Error("accepted a Size other than the type's")
		}
		if binary.LittleEndian.Uint64(body[8:]) < 0x8000000000000000 {
			t.Error("accepted a device outside kernel space")
		}
		length := binary.LittleEndian.Uint16(body[testsupport.S69FileName:])
		if !got.NameUnreadable && len(got.Name) > 3*int(length) {
			t.Errorf("name %q longer than its Length %d allows", got.Name, length)
		}
	})
}
