package tasklist

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/aoiflux/libvapour/util"
)

type TriggerKind string

const (
	KindEvent              TriggerKind = "Event"
	KindTime               TriggerKind = "Time"
	KindDaily              TriggerKind = "Daily"
	KindWeekly             TriggerKind = "Weekly"
	KindBoot               TriggerKind = "Boot"
	KindLogon              TriggerKind = "Logon"
	KindSessionStateChange TriggerKind = "SessionStateChange"
	KindWnfStateChange     TriggerKind = "WnfStateChange"
)

type Principal struct {
	ID       string
	UserID   string
	UserName string
}

type Settings struct {
	ExecutionTimeLimit string
	Priority           uint32
	RestartInterval    string
	RestartCount       uint32
}

type Trigger struct {
	Kind               TriggerKind
	Record             uint16
	ID                 string
	Enabled            bool
	Start              time.Time
	StartLocal         bool
	End                time.Time
	EndLocal           bool
	RepetitionInterval string
	RepetitionDuration string
	RandomDelay        string
	DaysInterval       uint16
	WeeksInterval      uint16
	DaysOfWeek         []string
	StateChange        string
	UserID             string
	UserName           string
	Subscription       string
	StateName          string
	StateData          string
}

type TriggerSet struct {
	Enabled   bool
	Principal Principal
	Settings  Settings
	Triggers  []Trigger
}

// S37 M3: the one format value every Triggers value carries.
const triggerSetFormat = 23

// S37 M7: bit 22 of the task flags follows the Enabled setting.
const taskEnabledBit = 1 << 22

// S37 M5: settings blocks are 0, 44 or 88 bytes; the first 44 share a layout.
const (
	settingsShort = 44
	settingsLong  = 88
)

const (
	recordWnf     = 0x6666
	recordSession = 0x7777
	recordUntiedA = 0x8888
	recordLogon   = 0xAAAA
	recordEvent   = 0xCCCC
	recordTimed   = 0xDDDD
	recordUntiedB = 0xEEEE
	recordBoot    = 0xFFFF
)

var recordKinds = map[uint16]TriggerKind{
	recordWnf:     KindWnfStateChange,
	recordSession: KindSessionStateChange,
	recordUntiedA: "",
	recordLogon:   KindLogon,
	recordEvent:   KindEvent,
	recordTimed:   "",
	recordUntiedB: "",
	recordBoot:    KindBoot,
}

// TASK_TRIGGER_TYPE (mstask.h) values of the schedule field (S37 D4, M8).
var scheduleKinds = map[uint32]TriggerKind{0: KindTime, 1: KindDaily, 2: KindWeekly}

// TASK_SESSION_STATE_CHANGE_TYPE (taskschd.h).
var stateChanges = map[uint32]string{
	1: "ConsoleConnect", 2: "ConsoleDisconnect", 3: "RemoteConnect", 4: "RemoteDisconnect",
	7: "SessionLock", 8: "SessionUnlock",
}

// MS-TSCH 2.4.2.11.3: bit 0 is Sunday through bit 6 Saturday.
var weekDays = [7]string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}

// DecodeTriggers returns what decoded before an error, so a caller can keep a
// partial result.
func DecodeTriggers(b []byte, maxRecords int) (TriggerSet, error) {
	var set TriggerSet
	c := &cursor{b: b}
	format, err := c.slotU32()
	if err != nil {
		return set, err
	}
	if format != triggerSetFormat {
		return set, fmt.Errorf("%w: Triggers format %d", ErrFormat, format)
	}
	for range 2 {
		if _, err := c.take(16); err != nil {
			return set, err
		}
	}
	flags, err := c.slotU32()
	if err != nil {
		return set, err
	}
	set.Enabled = flags&taskEnabledBit != 0
	if _, err := c.slotU32(); err != nil {
		return set, err
	}
	if set.Principal, err = decodePrincipal(c); err != nil {
		return set, err
	}
	if set.Settings, err = decodeSettings(c); err != nil {
		return set, err
	}
	for c.left() > 0 {
		if len(set.Triggers) >= maxRecords {
			err := fmt.Errorf("%w: more than %d records", ErrLimit, maxRecords)
			return set, &recordError{what: "trigger", at: c.at, err: err}
		}
		r := &cursor{b: b, at: c.at, base: c.at}
		t, err := decodeTrigger(r)
		if err != nil {
			return set, &recordError{what: "trigger", at: c.at, err: err}
		}
		set.Triggers = append(set.Triggers, t)
		c.at = r.at
	}
	return set, nil
}

func decodePrincipal(c *cursor) (Principal, error) {
	var p Principal
	id, err := c.slotted()
	if err != nil {
		return p, err
	}
	if p.ID, err = text(id); err != nil {
		return p, err
	}
	if _, err := c.slotted(); err != nil {
		return p, err
	}
	p.UserID, p.UserName, err = decodeAccount(c)
	return p, err
}

func decodeAccount(c *cursor) (sid, name string, err error) {
	absent, err := c.slotByte()
	switch {
	case err != nil:
		return "", "", err
	case absent == 1:
		return "", "", nil
	case absent != 0:
		return "", "", fmt.Errorf("%w: account marker %d", ErrField, absent)
	}
	if _, err := c.slotByte(); err != nil {
		return "", "", err
	}
	if _, err := c.slotU32(); err != nil {
		return "", "", err
	}
	raw, err := c.slotted()
	if err != nil {
		return "", "", err
	}
	if sid, err = sidString(raw); err != nil {
		return "", "", err
	}
	raw, err = c.slotted()
	if err != nil {
		return "", "", err
	}
	name, err = text(raw)
	return sid, name, err
}

func decodeSettings(c *cursor) (Settings, error) {
	var s Settings
	b, err := c.slotted()
	if err != nil {
		return s, err
	}
	switch len(b) {
	case 0:
		return s, nil
	case settingsShort, settingsLong:
	default:
		return s, fmt.Errorf("%w: settings block of %d bytes", ErrField, len(b))
	}
	r := &cursor{b: b}
	words := make([]uint32, 7)
	for i := range words {
		words[i], _ = r.u32()
	}
	s.ExecutionTimeLimit = duration(words[2])
	s.Priority = words[4]
	if words[6] != 0 {
		s.RestartInterval, s.RestartCount = duration(words[5]), words[6]
	}
	return s, nil
}

func decodeBoundary(c *cursor) (time.Time, bool, error) {
	b, err := c.take(16)
	if err != nil {
		return time.Time{}, false, err
	}
	if b[0] > 1 {
		return time.Time{}, false, fmt.Errorf("%w: boundary marker %d", ErrField, b[0])
	}
	t, _ := util.FiletimeToTime(binary.LittleEndian.Uint64(b[8:]))
	return t, b[0] == 1 && !t.IsZero(), nil
}

func decodeEnabled(b byte) (bool, error) {
	if b > 1 {
		return false, fmt.Errorf("%w: enabled byte %d", ErrField, b)
	}
	return b == 1, nil
}

func decodeTrigger(r *cursor) (Trigger, error) {
	var t Trigger
	tag, err := r.slotU16()
	if err != nil {
		return t, err
	}
	kind, known := recordKinds[tag]
	if !known {
		return t, fmt.Errorf("%w: 0x%04x", ErrRecordKind, tag)
	}
	t.Record, t.Kind = tag, kind
	if t.Start, t.StartLocal, err = decodeBoundary(r); err != nil {
		return t, err
	}
	if t.End, t.EndLocal, err = decodeBoundary(r); err != nil {
		return t, err
	}
	if tag == recordTimed {
		err = decodeTimed(r, &t)
	} else {
		err = decodeEventDriven(r, &t)
	}
	return t, err
}

func decodeTimed(r *cursor, t *Trigger) error {
	if _, err := r.take(16); err != nil {
		return err
	}
	var w [4]uint32
	for i := range w {
		v, err := r.u32()
		if err != nil {
			return err
		}
		w[i] = v
	}
	if w[0] != 0 {
		t.RepetitionInterval, t.RepetitionDuration = duration(w[0]), duration(w[1])
	}
	data, err := r.take(8)
	if err != nil {
		return err
	}
	t.Kind = scheduleKinds[w[3]]
	switch t.Kind {
	case KindDaily:
		t.DaysInterval = binary.LittleEndian.Uint16(data)
	case KindWeekly:
		t.WeeksInterval = binary.LittleEndian.Uint16(data)
		days := binary.LittleEndian.Uint16(data[2:])
		if days>>len(weekDays) != 0 {
			return fmt.Errorf("%w: days of week 0x%x", ErrField, days)
		}
		for i, name := range weekDays {
			if days&(1<<i) != 0 {
				t.DaysOfWeek = append(t.DaysOfWeek, name)
			}
		}
	}
	state, err := r.take(8)
	if err != nil {
		return err
	}
	if t.Enabled, err = decodeEnabled(state[1]); err != nil {
		return err
	}
	random, err := r.u32()
	if err != nil {
		return err
	}
	if random != 0 {
		t.RandomDelay = duration(random)
	}
	r.pad()
	return decodeID(r, t)
}

func decodeID(r *cursor, t *Trigger) error {
	id, err := r.packed()
	if err != nil {
		return err
	}
	t.ID, err = text(id)
	return err
}

func decodeEventDriven(r *cursor, t *Trigger) error {
	if _, err := r.take(24); err != nil {
		return err
	}
	state, err := r.take(16)
	if err != nil {
		return err
	}
	if t.Enabled, err = decodeEnabled(state[0]); err != nil {
		return err
	}
	if err := decodeID(r, t); err != nil {
		return err
	}
	switch t.Record {
	case recordWnf:
		return decodeWnf(r, t)
	case recordSession:
		change, err := r.take(8)
		if err != nil {
			return err
		}
		t.StateChange = stateChanges[binary.LittleEndian.Uint32(change)]
		t.UserID, t.UserName, err = decodeAccount(r)
		return err
	case recordLogon:
		var err error
		t.UserID, t.UserName, err = decodeAccount(r)
		return err
	case recordEvent:
		return decodeSubscription(r, t)
	}
	return nil
}

func decodeWnf(r *cursor, t *Trigger) error {
	name, err := r.take(8)
	if err != nil {
		return err
	}
	t.StateName = fmt.Sprintf("%X", name)
	n, err := r.u32()
	if err != nil {
		return err
	}
	if _, err := r.take(4); err != nil {
		return err
	}
	data, err := r.take(uint64(n))
	if err != nil {
		return err
	}
	t.StateData = fmt.Sprintf("%X", data)
	return nil
}

func decodeSubscription(r *cursor, t *Trigger) error {
	chars, err := r.u64()
	if err != nil {
		return err
	}
	if chars > uint64(r.left())/2 {
		return fmt.Errorf("%w: subscription of %d characters, %d bytes left", ErrTruncated, chars, r.left())
	}
	query, _ := r.take(2 * chars)
	if t.Subscription, err = text(query); err != nil {
		return err
	}
	end, err := r.take(2)
	if err != nil {
		return err
	}
	if end[0]|end[1] != 0 {
		return fmt.Errorf("%w: subscription not terminated", ErrField)
	}
	r.pad()
	tail, err := r.take(24)
	if err != nil {
		return err
	}
	for _, x := range tail {
		if x != 0 {
			return fmt.Errorf("%w: event record tail is not zero", ErrField)
		}
	}
	return nil
}
