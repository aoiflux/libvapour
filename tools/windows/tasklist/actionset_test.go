package tasklist

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

var classID = [16]byte{0x4C, 0x4A, 0x9E, 0x0F, 0x2B, 0xC6, 0x4F, 0x48, 0x9A, 0x6E, 0x2A, 0x2B, 0x0B, 0x5B, 0x1C, 0x3D}

func TestActionRecordsOfBothMeasuredFormatsDecode(t *testing.T) {
	for _, format := range []uint16{actionFormatEarly, actionFormatLate} {
		v := actionsValue(format, "LocalSystem",
			execRecord(format, "", `%windir%\system32\devicecensus.exe`, "-x", `C:\w`),
			comRecord(classID, "timer"),
			execRecord(format, "second", `C:\a.exe`, "", ""))
		set, err := DecodeActions(v, 8)
		if err != nil {
			t.Fatal(err)
		}
		want := ActionSet{Context: "LocalSystem", Actions: []Action{
			{Kind: ActionExec, Record: recordExec, Command: `%windir%\system32\devicecensus.exe`, Arguments: "-x",
				WorkingDirectory: `C:\w`},
			{Kind: ActionComHandler, Record: recordComHandler, ClassID: "{0F9E4A4C-C62B-484F-9A6E-2A2B0B5B1C3D}",
				Data: "timer"},
			{Kind: ActionExec, Record: recordExec, ID: "second", Command: `C:\a.exe`},
		}}
		if !reflect.DeepEqual(set, want) {
			t.Errorf("format %d:\n got %+v\nwant %+v", format, set, want)
		}
	}
}

func TestActionValuesOutsideTheMeasuredLayoutAreRefused(t *testing.T) {
	cases := []struct {
		name    string
		value   []byte
		want    error
		partial bool
	}{
		{"another format", actionsValue(4, "A"), ErrFormat, false},
		{"a context cut short", actionsValue(actionFormatLate, "Author")[:8], ErrTruncated, false},
		{"an odd-length context", []byte{3, 0, 1, 0, 0, 0, 0x41}, ErrField, false},
		{"an unmeasured record kind", actionsValue(actionFormatLate, "A", []byte{0x88, 0x88, 0, 0, 0, 0}),
			ErrRecordKind, true},
		{"an exec record cut short", actionsValue(actionFormatLate, "A",
			execRecord(actionFormatLate, "", "c", "", "")[:10]), ErrTruncated, true},
		{"a class id cut short", actionsValue(actionFormatLate, "A", comRecord(classID, "")[:12]), ErrTruncated, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeActions(c.value, 8)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if got := decodeState(err) == StatePartial; got != c.partial {
				t.Errorf("partial %v, want %v", got, c.partial)
			}
		})
	}
	set, err := DecodeActions(actionsValue(actionFormatLate, "A", comRecord(classID, ""), comRecord(classID, "")), 1)
	if !errors.Is(err, ErrLimit) || len(set.Actions) != 1 {
		t.Errorf("limit: %d actions, %v", len(set.Actions), err)
	}
}

func TestDynamicInfoGivesTheLastRunAndItsResult(t *testing.T) {
	run := time.Date(2026, 1, 30, 8, 4, 6, 0, time.UTC)
	s, err := DecodeDynamicInfo(dynamicInfo(runStateFormat, filetime(run.Add(-time.Hour)), filetime(run),
		0x800710E0, filetime(run.Add(-24*time.Hour))))
	if err != nil || !s.LastRunTime.Equal(run) || s.LastTaskResult != 0x800710E0 {
		t.Fatalf("%+v %v", s, err)
	}
	s, err = DecodeDynamicInfo(dynamicInfo(runStateFormat, filetime(run), 0, 0, 0))
	if err != nil || !s.LastRunTime.IsZero() {
		t.Fatalf("never run: %+v %v", s, err)
	}
	for _, bad := range [][]byte{dynamicInfo(2, 0, 0, 0, 0), dynamicInfo(runStateFormat, 0, 0, 0, 0)[:32], nil} {
		if _, err := DecodeDynamicInfo(bad); !errors.Is(err, ErrFormat) {
			t.Errorf("%x: %v", bad, err)
		}
	}
}
