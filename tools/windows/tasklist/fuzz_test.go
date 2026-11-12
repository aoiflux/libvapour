package tasklist

import (
	"errors"
	"testing"
)

func FuzzDecodeTriggers(f *testing.F) {
	f.Add(fullTriggers())
	var w blob
	w.header(headerSpec{format: triggerSetFormat, id: "Users", sid: sidSystem, settings: settingsBlock(0, 7, 0, 0, true)})
	f.Add(w.b)
	f.Fuzz(func(t *testing.T, b []byte) {
		set, err := DecodeTriggers(b, 16)
		if len(set.Triggers) > 16 {
			t.Fatalf("%d records past the limit", len(set.Triggers))
		}
		for _, tr := range set.Triggers {
			if _, known := recordKinds[tr.Record]; !known {
				t.Fatalf("record kind 0x%x returned", tr.Record)
			}
			if tr.Kind == "" && tr.Record != recordTimed && tr.Record != recordUntiedA && tr.Record != recordUntiedB {
				t.Fatalf("tied record 0x%x without a kind", tr.Record)
			}
			if (tr.StartLocal && tr.Start.IsZero()) || (tr.EndLocal && tr.End.IsZero()) {
				t.Fatal("a local marker on an absent boundary")
			}
		}
		if err != nil && !anyOf(err, ErrTruncated, ErrFormat, ErrRecordKind, ErrField, ErrLimit) {
			t.Fatalf("unexpected error %v", err)
		}
	})
}

func FuzzDecodeActions(f *testing.F) {
	f.Add(actionsValue(actionFormatLate, "LocalSystem", execRecord(actionFormatLate, "", "c", "a", "d"),
		comRecord(classID, "x")))
	f.Add(actionsValue(actionFormatEarly, "Author", execRecord(actionFormatEarly, "", "c", "", "")))
	f.Fuzz(func(t *testing.T, b []byte) {
		set, err := DecodeActions(b, 16)
		if len(set.Actions) > 16 {
			t.Fatalf("%d records past the limit", len(set.Actions))
		}
		for _, a := range set.Actions {
			if a.Kind != ActionExec && a.Kind != ActionComHandler {
				t.Fatalf("kind %q", a.Kind)
			}
		}
		if err != nil && !anyOf(err, ErrTruncated, ErrFormat, ErrRecordKind, ErrField, ErrLimit) {
			t.Fatalf("unexpected error %v", err)
		}
	})
}

func FuzzDecodeDynamicInfo(f *testing.F) {
	f.Add(dynamicInfo(runStateFormat, 1, 2, 3, 4))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := DecodeDynamicInfo(b); err == nil && len(b) != runStateBytes {
			t.Fatalf("%d bytes accepted", len(b))
		}
	})
}

func anyOf(err error, targets ...error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}
