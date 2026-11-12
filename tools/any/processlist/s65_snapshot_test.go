package processlist

import (
	"errors"
	"strings"
	"testing"
)

func TestSnapshotHeadersOfEachSource(t *testing.T) {
	for _, tc := range []struct{ name, csv string }{
		{"Win32_Process", "\"ProcessId\",\"ParentProcessId\",\"Name\"\n\"1300\",\"812\",\"svchost.exe\"\n"},
		{"tasklist", "\"Image Name\",\"PID\",\"Session Name\"\n\"svchost.exe\",\"1300\",\"Services\"\n"},
		{"Get-Process", "Id,ProcessName\n1300,svchost.exe\n"},
		{"address", " pid , name , eprocess \n1300, svchost.exe ,0xFFFF9E03F66A0040\n"},
	} {
		rows, err := ParseSnapshotCSV(strings.NewReader(tc.csv))
		if err != nil || len(rows) != 1 || rows[0].PID != 1300 || rows[0].Name != "svchost.exe" {
			t.Errorf("%s: %+v %v", tc.name, rows, err)
		}
		if tc.name == "address" && rows[0].EPROCESS != 0xffff9e03f66a0040 {
			t.Errorf("address column: %+v", rows[0])
		}
	}
}

func TestAByteOrderMarkAndATypeLineAreNotTheHeader(t *testing.T) {
	text := "\xef\xbb\xbf#TYPE System.Management.ManagementObject#root\\cimv2\\Win32_Process\n" +
		"\"ProcessId\",\"Name\"\n\"4\",\"System\"\n\n\"x\",\"bad\"\n"
	_, err := ParseSnapshotCSV(strings.NewReader(text))
	if err == nil || !strings.Contains(err.Error(), `snapshot csv line 5: pid "x" is not a decimal number`) {
		t.Errorf("bad pid: %v", err)
	}
	rows, err := ParseSnapshotCSV(strings.NewReader("\xef\xbb\xbf\"ProcessId\",\"Name\"\n\"4\",\"System\"\n"))
	if err != nil || len(rows) != 1 || rows[0].PID != 4 {
		t.Errorf("byte-order mark: %+v %v", rows, err)
	}
}

func TestASnapshotWithoutAPIDColumnIsRefused(t *testing.T) {
	if _, err := ParseSnapshotCSV(strings.NewReader("process_id,name\n4,System\n")); !errors.Is(err, ErrSnapshotNoPID) {
		t.Errorf("err %v", err)
	}
	if rows, err := ParseSnapshotCSV(strings.NewReader("")); rows != nil || err != nil {
		t.Errorf("empty: %v %v", rows, err)
	}
}

func TestASnapshotAddressThatDoesNotParseIsNoAddress(t *testing.T) {
	rows, err := ParseSnapshotCSV(strings.NewReader("PID,Name,EPROCESS\n8,smss.exe,zz\n12,a.exe\n"))
	if err != nil || len(rows) != 2 || rows[0].EPROCESS != 0 || rows[1].EPROCESS != 0 || rows[1].Name != "a.exe" {
		t.Errorf("%+v %v", rows, err)
	}
}

func TestTheCrossCheckerMatchesPIDNameAndAddress(t *testing.T) {
	c := NewSnapshotCrossChecker([]SnapshotProcess{
		{PID: 4, Name: "System"},
		{PID: 1300, Name: "MicrosoftEdgeUpdate.exe"},
		{PID: 2400, Name: "cmd.exe", EPROCESS: 0x5000},
		{PID: 2600},
		{PID: 2800, Name: "MicrosoftEdgeUpdate.exe"},
	})
	for _, tc := range []struct {
		p    Process
		want bool
	}{
		{Process{PID: 4, Name: "SYSTEM"}, true},
		{Process{PID: 4, Name: "smss.exe"}, false},
		{Process{PID: 1300, Name: "MicrosoftEdgeU"}, true},
		{Process{PID: 1300, Name: "MicrosoftEdge"}, false},
		{Process{PID: 2400, Name: "cmd.exe", EPROCESS: 0x5000}, true},
		{Process{PID: 2400, Name: "cmd.exe", EPROCESS: 0x6000}, false},
		{Process{PID: 2400, Name: "cmd.exe"}, true},
		{Process{PID: 2600, Name: "any.exe"}, true},
		{Process{PID: 2800, Name: "microsoftedgeu"}, true},
		{Process{PID: 9999, Name: "System"}, false},
	} {
		if got, err := c.Confirm(tc.p); got != tc.want || err != nil {
			t.Errorf("%+v: %v %v, want %v", tc.p, got, err, tc.want)
		}
	}
}

func TestLoadSnapshotNamesTheFile(t *testing.T) {
	if _, err := LoadSnapshotCSV(t.TempDir() + "/missing.csv"); err == nil || !strings.Contains(err.Error(), "open snapshot csv") {
		t.Errorf("err %v", err)
	}
}
