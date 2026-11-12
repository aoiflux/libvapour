package credentiallsasecrets

import (
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/util"
)

const secretsPath = `Policy\Secrets`

// Subkey names measured (S21 M7); each holds its data in the default value.
const (
	currentValueKey   = "CurrVal"
	oldValueKey       = "OldVal"
	currentSetTimeKey = "CupdTime"
	oldSetTimeKey     = "OupdTime"
	setTimeLen        = 8
)

var ErrSecretName = errors.New("credentiallsasecrets: secret name is empty or holds a backslash")

func ReadSecretObject(sec SecurityHive, keys KeyList, name string) (Entry, error) {
	if name == "" || strings.Contains(name, `\`) {
		return Entry{}, ErrSecretName
	}
	k, err := sec.OpenKey(secretsPath + `\` + name)
	if err != nil {
		return Entry{}, err
	}
	return secretObject(&diagnostics{}, sec, keys, k), nil
}

func secretObjects(d *diagnostics, sec SecurityHive, keys KeyList) []Entry {
	parent, err := sec.OpenKey(secretsPath)
	if err != nil {
		if !errors.Is(err, registryhive.ErrKeyNotFound) {
			d.add("%s: secret list: key does not read: %v", Name, err)
		}
		return nil
	}
	subkeys, complete := sec.SubkeysChecked(parent)
	if !complete || parent.SubkeysUnreadable {
		d.add("%s: secret list at 0x%x: subkeys do not all read", Name, parent.Address)
	}
	var rows []Entry
	for _, k := range subkeys {
		if k.NameUnreadable {
			d.add("%s: secret at 0x%x: name does not read", Name, k.Address)
			continue
		}
		rows = append(rows, secretObject(d, sec, keys, k))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

func secretObject(d *diagnostics, sec SecurityHive, keys KeyList, k *registryhive.KeyNode) Entry {
	e := Entry{Name: k.Name, Type: secretTypeOf(k.Name)}
	children, complete := sec.SubkeysChecked(k)
	e.CurrentValue, e.CurrentValueState = secretValue(d, sec, keys, k, children, complete, currentValueKey, "current")
	e.OldValue, e.OldValueState = secretValue(d, sec, keys, k, children, complete, oldValueKey, "old")
	e.CurrentValueSetTime = setTime(d, sec, k, children, complete, currentSetTimeKey)
	e.OldValueSetTime = setTime(d, sec, k, children, complete, oldSetTimeKey)
	return e
}

func childValue(sec SecurityHive, children []*registryhive.KeyNode, complete bool, name string) ([]byte, ValueState) {
	child, found, maybe := registryhive.FindSubkey(children, complete, name)
	switch {
	case found:
		return defaultValueOf(sec, child)
	case maybe:
		return nil, ValueUnreadable
	}
	return nil, ValueAbsent
}

func secretValue(d *diagnostics, sec SecurityHive, keys KeyList, k *registryhive.KeyNode, children []*registryhive.KeyNode, complete bool, sub, which string) ([]byte, ValueState) {
	raw, state := childValue(sec, children, complete, sub)
	switch state {
	case ValueUnreadable:
		d.add("%s: secret %q at 0x%x: %s value does not read", Name, k.Name, k.Address, which)
		return nil, ValueUnreadable
	case ValueAbsent:
		return nil, ValueAbsent
	}
	value, err := keys.open(raw)
	if err != nil {
		d.add("%s: secret %q at 0x%x: %s value does not decrypt: %v", Name, k.Name, k.Address, which, err)
		return nil, ValueUndecryptable
	}
	return value, ValuePresent
}

func setTime(d *diagnostics, sec SecurityHive, k *registryhive.KeyNode, children []*registryhive.KeyNode, complete bool, sub string) time.Time {
	raw, state := childValue(sec, children, complete, sub)
	switch {
	case state == ValueAbsent:
		return time.Time{}
	case state == ValueUnreadable || len(raw) != setTimeLen:
		d.add("%s: secret %q at 0x%x: %s is not an 8-byte time", Name, k.Name, k.Address, sub)
		return time.Time{}
	}
	t, _ := util.FiletimeToTime(binary.LittleEndian.Uint64(raw))
	return t
}

type namePattern struct {
	prefix string
	exact  bool
	fold   bool
	typ    SecretType
}

// The [MS-LSAD] "Secret Object Data Model" table, G$$ before G$. The table
// spells _sc_ in lower case only, so that one prefix is matched without case
// (S21 O7).
var secretNamePatterns = []namePattern{
	{prefix: "G$$", typ: TrustedDomainSecret},
	{prefix: "G$", typ: GlobalSecret},
	{prefix: "L$", typ: LocalSecret},
	{prefix: "M$", typ: SystemSecret},
	{prefix: "_sc_", fold: true, typ: SystemSecret},
	{prefix: "NL$", typ: SystemSecret},
	{prefix: "RasDialParams", typ: LocalSecret},
	{prefix: "RasCredentials", typ: LocalSecret},
	{prefix: "$MACHINE.ACC", exact: true, typ: SystemSecret},
	{prefix: "SAC", exact: true, typ: LocalSecret},
	{prefix: "SAI", exact: true, typ: LocalSecret},
	{prefix: "SANSC", exact: true, typ: LocalSecret},
}

func secretTypeOf(name string) SecretType {
	for _, p := range secretNamePatterns {
		if !p.exact && name == p.prefix {
			return UnlistedSecret
		}
	}
	for _, p := range secretNamePatterns {
		if p.exact {
			if name == p.prefix {
				return p.typ
			}
			continue
		}
		head := name
		if len(head) > len(p.prefix) {
			head = head[:len(p.prefix)]
		}
		match := head == p.prefix
		if p.fold {
			match = strings.EqualFold(head, p.prefix)
		}
		// "Starts with" needs at least one character after the prefix.
		if match && len(name) > len(p.prefix) {
			return p.typ
		}
	}
	return UnlistedSecret
}
