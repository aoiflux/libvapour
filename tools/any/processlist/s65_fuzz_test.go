package processlist

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzSnapshotCSV(f *testing.F) {
	f.Add([]byte("\xef\xbb\xbf\"ProcessId\",\"Name\"\n\"4\",\"System\"\n"))
	f.Add([]byte("#TYPE x\nPID,Image Name,EPROCESS\n 8 , smss.exe ,0x10\n"))
	f.Add([]byte("Id\n\"4\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rows, err := ParseSnapshotCSV(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, r := range rows {
			if r.Name != strings.TrimSpace(r.Name) {
				t.Fatalf("row %+v keeps the space around its name", r)
			}
		}
		_, _ = NewSnapshotCrossChecker(rows).Confirm(Process{PID: 4, Name: "MicrosoftEdgeU"})
	})
}
