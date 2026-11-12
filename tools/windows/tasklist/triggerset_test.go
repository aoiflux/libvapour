package tasklist

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

var (
	startUTC   = time.Date(2026, 5, 24, 21, 11, 27, 0, time.UTC)
	startLocal = time.Date(2008, 9, 1, 3, 0, 0, 0, time.UTC)
)

func fullTriggers() []byte {
	var w blob
	w.header(headerSpec{format: triggerSetFormat, flags: taskEnabledBit | 0x42022148, id: "LocalSystem", sid: sidSystem,
		settings: settingsBlock(259200, 7, 600, 3, false)})
	w.timed(timedSpec{local: 0, start: filetime(startUTC), enabled: 1})
	w.timed(timedSpec{local: 1, start: filetime(startLocal), interval: 86400, schedule: 1, data: [8]byte{1},
		enabled: 1, random: 7200, id: "Daily"})
	w.timed(timedSpec{start: filetime(startUTC), schedule: 2, data: [8]byte{4, 0, 0x41, 0}, enabled: 0})
	w.eventDriven(recordLogon, 1, "79B8DA54")
	w.account(sidUser, `HOST\user`)
	w.eventDriven(recordSession, 0, "LocalConsoleConnectTrigger")
	w.raw(1, 0, 0, 0, 0x73, 0, 0, 0)
	w.account(nil, "")
	w.event(`<QueryList><Query Id="0"/></QueryList>`, 0)
	w.eventDriven(recordBoot, 1, "")
	w.eventDriven(recordUntiedA, 1, "")
	w.wnf([8]byte{0x75, 0x0C, 0xBC, 0xA3, 0x29, 0x0B, 0x96, 0x41}, []byte{1})
	w.wnf([8]byte{0x75, 0x10, 0xBC, 0xA3, 0x3A, 0x01, 0x95, 0x02}, nil)
	return w.b
}

func TestEveryMeasuredRecordDecodesToItsFields(t *testing.T) {
	set, err := DecodeTriggers(fullTriggers(), 64)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Enabled || set.Principal != (Principal{ID: "LocalSystem", UserID: "S-1-5-18"}) {
		t.Fatalf("header: %+v", set)
	}
	if set.Settings != (Settings{ExecutionTimeLimit: "P3D", Priority: 7, RestartInterval: "PT10M", RestartCount: 3}) {
		t.Fatalf("settings: %+v", set.Settings)
	}
	want := []Trigger{
		{Kind: KindTime, Record: recordTimed, Enabled: true, Start: startUTC},
		{Kind: KindDaily, Record: recordTimed, ID: "Daily", Enabled: true, Start: startLocal, StartLocal: true,
			RepetitionInterval: "P1D", RepetitionDuration: "PT0S", RandomDelay: "PT2H", DaysInterval: 1},
		{Kind: KindWeekly, Record: recordTimed, Start: startUTC, WeeksInterval: 4, DaysOfWeek: []string{"Sunday", "Saturday"}},
		{Kind: KindLogon, Record: recordLogon, ID: "79B8DA54", Enabled: true, UserID: "S-1-5-21-1-2-3-1001",
			UserName: `HOST\user`},
		{Kind: KindSessionStateChange, Record: recordSession, ID: "LocalConsoleConnectTrigger",
			StateChange: "ConsoleConnect"},
		{Kind: KindEvent, Record: recordEvent, Enabled: true, Subscription: `<QueryList><Query Id="0"/></QueryList>`},
		{Kind: KindBoot, Record: recordBoot, Enabled: true},
		{Kind: "", Record: recordUntiedA, Enabled: true},
		{Kind: KindWnfStateChange, Record: recordWnf, Enabled: true, StateName: "750CBCA3290B9641", StateData: "01"},
		{Kind: KindWnfStateChange, Record: recordWnf, Enabled: true, StateName: "7510BCA33A019502", StateData: ""},
	}
	if !reflect.DeepEqual(set.Triggers, want) {
		for i := range max(len(want), len(set.Triggers)) {
			if i >= len(want) || i >= len(set.Triggers) || !reflect.DeepEqual(set.Triggers[i], want[i]) {
				t.Errorf("trigger %d:\n got %+v\nwant %+v", i, at(set.Triggers, i), at(want, i))
			}
		}
	}
}

func at(ts []Trigger, i int) any {
	if i < len(ts) {
		return ts[i]
	}
	return nil
}

func TestASettingsBlockOfEitherMeasuredLengthDecodes(t *testing.T) {
	for _, long := range []bool{false, true} {
		var w blob
		w.header(headerSpec{format: triggerSetFormat, id: "Author", sid: sidSystem,
			settings: settingsBlock(unsetSeconds, 4, 0, 0, long)})
		set, err := DecodeTriggers(w.b, 8)
		if err != nil {
			t.Fatal(err)
		}
		if set.Enabled || set.Settings != (Settings{Priority: 4}) {
			t.Errorf("long %v: %+v", long, set)
		}
	}
}

func TestATaskWithNoTriggerRecordsAndNoSettingsDecodes(t *testing.T) {
	var w blob
	w.header(headerSpec{format: triggerSetFormat, id: "Users", sid: sidSystem})
	set, err := DecodeTriggers(w.b, 8)
	if err != nil || len(set.Triggers) != 0 || set.Settings != (Settings{}) {
		t.Fatalf("%+v %v", set, err)
	}
}

func TestTriggerValuesOutsideTheMeasuredLayoutAreRefused(t *testing.T) {
	header := func(h headerSpec) []byte {
		var w blob
		w.header(h)
		return w.b
	}
	good := headerSpec{format: triggerSetFormat, id: "Author", sid: sidSystem}
	withRecord := func(add func(*blob)) []byte {
		w := blob{b: header(good)}
		add(&w)
		return w.b
	}
	cases := []struct {
		name    string
		value   []byte
		want    error
		partial bool
	}{
		{"another format value", header(headerSpec{format: 24, id: "Author", sid: sidSystem}), ErrFormat, false},
		{"a settings block of another length", header(headerSpec{format: triggerSetFormat, id: "A",
			sid: sidSystem, settings: make([]byte, 12)}), ErrField, false},
		{"a malformed security identifier", header(headerSpec{format: triggerSetFormat, id: "A",
			sid: []byte{1, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}}), ErrField, false},
		{"an odd-length principal id", func() []byte {
			var w blob
			w.record()
			w.slotU32(triggerSetFormat)
			w.boundary(0, 0)
			w.boundary(0, 0)
			w.slotU32(0)
			w.slotU32(0)
			w.slotted([]byte{0x41})
			return w.b
		}(), ErrField, false},
		{"a value cut inside the header", header(good)[:0x30], ErrTruncated, false},
		{"an unmeasured record kind", withRecord(func(w *blob) { w.eventDriven(0x9999, 1, "") }), ErrRecordKind, true},
		{"a boundary marker other than 0 or 1", withRecord(func(w *blob) {
			w.timed(timedSpec{local: 2, start: 1, enabled: 1})
		}), ErrField, true},
		{"an enabled byte other than 0 or 1", withRecord(func(w *blob) { w.eventDriven(recordBoot, 2, "") }),
			ErrField, true},
		{"days of the week past Saturday", withRecord(func(w *blob) {
			w.timed(timedSpec{schedule: 2, data: [8]byte{1, 0, 0x80, 0}, enabled: 1})
		}), ErrField, true},
		{"an event record whose tail is not zero", withRecord(func(w *blob) { w.event("q", 1) }), ErrField, true},
		{"a record cut short", withRecord(func(w *blob) { w.eventDriven(recordBoot, 1, ""); w.b = w.b[:len(w.b)-9] }),
			ErrTruncated, true},
		{"a subscription longer than the value", withRecord(func(w *blob) {
			w.eventDriven(recordEvent, 1, "")
			w.le64(1 << 40)
		}), ErrTruncated, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeTriggers(c.value, 8)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if got := decodeState(err) == StatePartial; got != c.partial {
				t.Errorf("partial %v, want %v", got, c.partial)
			}
		})
	}
}

func TestRecordsPastTheLimitAreNotDecoded(t *testing.T) {
	set, err := DecodeTriggers(fullTriggers(), 3)
	if !errors.Is(err, ErrLimit) || len(set.Triggers) != 3 || decodeState(err) != StatePartial {
		t.Fatalf("%d triggers, %v", len(set.Triggers), err)
	}
}

func TestADurationIsWrittenInTheTaskDefinitionForm(t *testing.T) {
	for in, want := range map[uint32]string{0: "PT0S", 60: "PT1M", 600: "PT10M", 3600: "PT1H", 24960: "PT6H56M",
		86400: "P1D", 345600: "P4D", 90061: "P1DT1H1M1S", unsetSeconds: ""} {
		if got := duration(in); got != want {
			t.Errorf("%d: got %q, want %q", in, got, want)
		}
	}
}

func TestSecurityIdentifiersAreWrittenInTheirStringForm(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want string
	}{
		{sidSystem, "S-1-5-18"},
		{sidUser, "S-1-5-21-1-2-3-1001"},
		{[]byte{1, 0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, "S-1-0x123456789ABC"},
		{nil, ""},
	} {
		if got, err := sidString(c.in); err != nil || got != c.want {
			t.Errorf("%x: %q %v", c.in, got, err)
		}
	}
	for _, bad := range [][]byte{{1}, {2, 0, 0, 0, 0, 0, 0, 5}, {1, 1, 0, 0, 0, 0, 0, 5}} {
		if _, err := sidString(bad); !errors.Is(err, ErrField) {
			t.Errorf("%x: %v", bad, err)
		}
	}
}
