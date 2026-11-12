package credentiallsasecrets

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

const madeUpFiletime = 133810000000000000

func addSecret(h *registrytest.FakeHive, name string, parts map[string][]byte) {
	k := h.Path(secretsPath + `\` + name)
	for sub, raw := range parts {
		c := h.Key(k, sub)
		if raw != nil {
			h.Values[c] = []registryhive.Value{defaultSecValue(raw)}
		}
	}
}

func fixtureKeys() KeyList {
	return KeyList{CurrentID: madeUpKeyID, Keys: map[[16]byte][]byte{madeUpKeyID: madeUpPolicyKey, madeUpOtherID: madeUpOlderKey}}
}

func TestSecretObjectsCarryBothValuesTheirTimesAndStates(t *testing.T) {
	h := securityHive(nil)
	current := bytes.Repeat([]byte{0x11}, 44)
	older := bytes.Repeat([]byte{0x22}, 44)
	addSecret(h, "NL$KM", map[string][]byte{
		currentValueKey:   seal(madeUpPolicyKey, madeUpKeyID, madeUpSalt, current),
		oldValueKey:       seal(madeUpOlderKey, madeUpOtherID, madeUpSalt, older),
		currentSetTimeKey: filetimeBytes(madeUpFiletime),
		oldSetTimeKey:     filetimeBytes(madeUpFiletime - 1),
	})
	addSecret(h, "DPAPI_SYSTEM", map[string][]byte{
		currentValueKey: seal(madeUpPolicyKey, [16]byte{0xcc}, madeUpSalt, current),
		oldValueKey:     seal(madeUpOlderKey, madeUpKeyID, madeUpSalt, older),
	})
	addSecret(h, "L$made-up", map[string][]byte{currentValueKey: nil})
	paged := h.Path(secretsPath + `\_SC_madeup\` + currentValueKey)
	h.Values[paged] = []registryhive.Value{{Name: defaultValueName, Length: 124}}

	d, sink := diagCtx()
	rows := secretObjects(d, h, fixtureKeys())
	if len(rows) != 4 {
		t.Fatalf("rows = %d", len(rows))
	}
	names := []string{rows[0].Name, rows[1].Name, rows[2].Name, rows[3].Name}
	if strings.Join(names, ",") != "DPAPI_SYSTEM,L$made-up,NL$KM,_SC_madeup" {
		t.Errorf("order = %v", names)
	}
	dp, local, nl, sc := rows[0], rows[1], rows[2], rows[3]
	if nl.Type != SystemSecret || dp.Type != UnlistedSecret || local.Type != LocalSecret || sc.Type != SystemSecret {
		t.Errorf("types = %s %s %s %s", nl.Type, dp.Type, local.Type, sc.Type)
	}
	if nl.CurrentValueState != ValuePresent || !bytes.Equal(nl.CurrentValue, current) {
		t.Errorf("NL$KM current = %s", nl.CurrentValueState)
	}
	if nl.OldValueState != ValuePresent || !bytes.Equal(nl.OldValue, older) {
		t.Errorf("NL$KM old = %s", nl.OldValueState)
	}
	want := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if nl.CurrentValueSetTime.Year() != want.Year() || nl.CurrentValueSetTime.Location() != time.UTC {
		t.Errorf("set time = %v", nl.CurrentValueSetTime)
	}
	if !nl.OldValueSetTime.Before(nl.CurrentValueSetTime) {
		t.Error("old set time not before the current one")
	}
	if dp.CurrentValueState != ValueUndecryptable || dp.CurrentValue != nil {
		t.Errorf("unknown key = %s", dp.CurrentValueState)
	}
	if dp.OldValueState != ValueUndecryptable {
		t.Errorf("wrong key = %s", dp.OldValueState)
	}
	if !dp.CurrentValueSetTime.IsZero() {
		t.Error("absent set time is not the zero time")
	}
	if local.CurrentValueState != ValueAbsent || local.OldValueState != ValueAbsent {
		t.Errorf("absent = %s %s", local.CurrentValueState, local.OldValueState)
	}
	if sc.CurrentValueState != ValueUnreadable {
		t.Errorf("unreadable = %s", sc.CurrentValueState)
	}
	if d.raised != 3 || len(*sink) != 3 {
		t.Errorf("diagnostics = %d: %v", d.raised, *sink)
	}
	for _, msg := range *sink {
		if !strings.HasPrefix(msg, Name+`: secret "`) {
			t.Errorf("diagnostic form: %q", msg)
		}
	}
}

func TestAnIncompleteSecretListKeepsWhatRead(t *testing.T) {
	h := securityHive(nil)
	addSecret(h, "NL$KM", map[string][]byte{currentValueKey: seal(madeUpPolicyKey, madeUpKeyID, madeUpSalt, []byte("x"))})
	h.SubkeysIncomplete[h.Path(secretsPath)] = true
	d, sink := diagCtx()
	rows := secretObjects(d, h, fixtureKeys())
	if len(rows) != 1 || rows[0].CurrentValueState != ValuePresent {
		t.Fatalf("rows = %+v", rows)
	}
	if len(*sink) != 1 || !strings.Contains((*sink)[0], "subkeys do not all read") {
		t.Errorf("diagnostics = %v", *sink)
	}
}

func TestNoSecretsKeyIsNoRowsAndNoDiagnostic(t *testing.T) {
	d, sink := diagCtx()
	if rows := secretObjects(d, securityHive(nil), fixtureKeys()); rows != nil || len(*sink) != 0 {
		t.Fatalf("rows = %v, diagnostics = %v", rows, *sink)
	}
}

func TestASetTimeOfAnotherLengthIsNoTime(t *testing.T) {
	h := securityHive(nil)
	addSecret(h, "NL$KM", map[string][]byte{currentSetTimeKey: {1, 2, 3}})
	d, _ := diagCtx()
	rows := secretObjects(d, h, fixtureKeys())
	if len(rows) != 1 || !rows[0].CurrentValueSetTime.IsZero() || d.raised != 1 {
		t.Fatalf("rows = %+v, raised %d", rows, d.raised)
	}
}

func TestReadSecretObjectReadsOneName(t *testing.T) {
	h := securityHive(nil)
	value := bytes.Repeat([]byte{0x31}, 64)
	addSecret(h, "NL$KM", map[string][]byte{currentValueKey: seal(madeUpPolicyKey, madeUpKeyID, madeUpSalt, value)})
	e, err := ReadSecretObject(h, fixtureKeys(), "NL$KM")
	if err != nil || !bytes.Equal(e.CurrentValue, value) {
		t.Fatalf("err %v, state %s", err, e.CurrentValueState)
	}
	if _, err := ReadSecretObject(h, fixtureKeys(), "absent"); !errors.Is(err, registryhive.ErrKeyNotFound) {
		t.Errorf("absent: err = %v", err)
	}
	for _, bad := range []string{"", `NL$KM\CurrVal`} {
		if _, err := ReadSecretObject(h, fixtureKeys(), bad); !errors.Is(err, ErrSecretName) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

func TestSecretTypesFollowTheNameTable(t *testing.T) {
	for name, want := range map[string]SecretType{
		"G$$trust":         TrustedDomainSecret,
		"G$shared":         GlobalSecret,
		"L$own":            LocalSecret,
		"M$machine":        SystemSecret,
		"_sc_service":      SystemSecret,
		"_SC_service":      SystemSecret,
		"NL$KM":            SystemSecret,
		"NL$1":             SystemSecret,
		"RasDialParams!x":  LocalSecret,
		"RasCredentials#0": LocalSecret,
		"$MACHINE.ACC":     SystemSecret,
		"SAC":              LocalSecret,
		"SAI":              LocalSecret,
		"SANSC":            LocalSecret,
		"DPAPI_SYSTEM":     UnlistedSecret,
		"DefaultPassword":  UnlistedSecret,
		"G$$":              UnlistedSecret,
		"G$":               UnlistedSecret,
		"L$":               UnlistedSecret,
		"NL$":              UnlistedSecret,
		"SACX":             UnlistedSecret,
		"$machine.acc":     UnlistedSecret,
		"l$lower":          UnlistedSecret,
	} {
		if got := secretTypeOf(name); got != want {
			t.Errorf("%q: %s, want %s", name, got, want)
		}
	}
}
