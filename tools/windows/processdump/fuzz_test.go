package processdump

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/minidump"
	"github.com/aoiflux/libvapour/tools"
)

type pageMap struct {
	base     uint64
	resident []byte
}

func (p pageMap) ReadAt(off, n uint64) ([]byte, error) {
	i := (off - p.base) / tools.PageSize
	if off < p.base || i >= uint64(len(p.resident)) || p.resident[i]&1 == 0 {
		return nil, errors.New("not resident")
	}
	return make([]byte, n), nil
}

func (p pageMap) Size() uint64 { return 1 << 48 }

func FuzzResidentPieces(f *testing.F) {
	f.Add(uint64(0x10000), []byte{1, 0, 1, 1, 0})
	f.Add(uint64(0x7ff000000000), []byte{0})
	f.Fuzz(func(t *testing.T, base uint64, resident []byte) {
		if len(resident) == 0 || len(resident) > 512 {
			return
		}
		base = base &^ (tools.PageSize - 1) & (1<<47 - 1)
		size := uint64(len(resident)) * tools.PageSize
		r := minidump.Region{BaseAddress: base, AllocationBase: base, Size: size, Protect: 4, State: minidump.MemCommit, Type: minidump.MemPrivate}
		pieces := residentPieces(pageMap{base: base, resident: resident}, r)
		at := base
		for i, p := range pieces {
			if p.BaseAddress != at || p.Size == 0 || p.Size%tools.PageSize != 0 || p.AllocationBase != base || p.Protect != 4 {
				t.Fatalf("piece %d %+v does not follow at 0x%x", i, p, at)
			}
			if i > 0 && pieces[i-1].Dumpable == p.Dumpable {
				t.Fatalf("pieces %d and %d have the same residency", i-1, i)
			}
			for page := p.BaseAddress; page < p.BaseAddress+p.Size; page += tools.PageSize {
				if (resident[(page-base)/tools.PageSize]&1 == 1) != p.Dumpable {
					t.Fatalf("page 0x%x in a piece of the other residency", page)
				}
			}
			at += p.Size
		}
		if at != base+size {
			t.Fatalf("pieces end at 0x%x, the range at 0x%x", at, base+size)
		}
	})
}
