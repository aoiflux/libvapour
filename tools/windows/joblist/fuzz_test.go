package joblist

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

// The patch lands in a job object or in one process's _EPROCESS from its Job
// member on, so the counters, the list head, the JobLinks and the Job
// back-reference all get hit.
func FuzzJobsOfAPatchedWorld(f *testing.F) {
	f.Add(uint8(0), uint16(testsupport.S69JobListHead), bytes.Repeat([]byte{0xff}, 8))
	f.Add(uint8(0), uint16(testsupport.S69JobTotal), bytes.Repeat([]byte{0xff}, 4))
	f.Add(uint8(2), uint16(0), make([]byte, 8))
	f.Add(uint8(3), uint16(testsupport.S69ProcessJobLinks-testsupport.S69ProcessJob), binary.LittleEndian.AppendUint32(nil, 0x10))
	f.Fuzz(func(t *testing.T, target uint8, at uint16, patch []byte) {
		w := fixture()
		job := w.AddJob(5, 2, 1, 1, 100, 200)
		w.AddJob(1, 1, 0, 0, 300)
		ctx := w.Context()
		start, span := job, uint64(testsupport.S69JobSize)
		if pid := uint64(target%5) * 100; pid != 0 {
			ep, _ := w.EPROCESS(pid)
			start, span = ep+testsupport.S69ProcessJob, testsupport.S69ProcessJobLinks+16-testsupport.S69ProcessJob
		}
		tr := ctx.Memory.(translator)
		for i, b := range patch {
			pa, err := tr.Translate(start + (uint64(at)+uint64(i))%span)
			if err != nil {
				t.Fatal(err)
			}
			w.Memory.WriteAt(pa, []byte{b})
		}
		rows, err := Run(ctx)
		if err != nil {
			t.Fatalf("a lenient run failed: %v", err)
		}
		heads := map[uint64]bool{}
		members := map[uint64]bool{}
		var current uint64
		for i, r := range rows {
			switch {
			case r.Depth == 0:
				if heads[r.Job] || r.Job == 0 || r.IsJobLink || r.Process != OriginalProcessLabel {
					t.Fatalf("row %d heads job 0x%x badly: %+v", i, r.Job, r)
				}
				heads[r.Job], current = true, r.Job
				clear(members)
				checkCounters(t, r)
			case r.Depth == 1:
				if i == 0 || r.Job != current || !r.IsJobLink || members[r.EPROCESS] {
					t.Fatalf("member row %d out of its group: %+v", i, r)
				}
				members[r.EPROCESS] = true
			default:
				t.Fatalf("row %d at depth %d", i, r.Depth)
			}
		}
	})
}

func checkCounters(t *testing.T, r Row) {
	t.Helper()
	if (r.TotalUnreadable && r.Total != 0) || (r.ActiveUnreadable && r.Active != 0) ||
		(r.TerminatedUnreadable && r.Terminated != 0) || (r.JobSessionIDUnreadable && r.JobSessionID != 0) {
		t.Fatalf("an unread counter carries a value: %+v", r)
	}
}
