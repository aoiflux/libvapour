package credentiallsasecrets

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

var (
	ErrPolicyKeyAbsent     = errors.New("credentiallsasecrets: policy key list is absent")
	ErrPolicyKeyUnreadable = errors.New("credentiallsasecrets: policy key list does not read")
	ErrLegacyPolicyKey     = errors.New("credentiallsasecrets: policy holds only the older secret encryption key, which is not read")
	ErrPolicyKey           = errors.New("credentiallsasecrets: policy key list does not unwrap under the system key")
)

type SecurityHive interface {
	OpenKey(string) (*registryhive.KeyNode, error)
	SubkeysChecked(*registryhive.KeyNode) ([]*registryhive.KeyNode, bool)
	ValuesChecked(*registryhive.KeyNode) ([]registryhive.Value, bool)
}

type KeyList struct {
	CurrentID [16]byte
	Keys      map[[16]byte][]byte
}

const (
	keyListPath      = `Policy\PolEKList`
	legacyPolicyPath = `Policy\PolSecretEncryptionKey`
	defaultValueName = "(Default)"
)

// Key list layout measured (S21 M6); entries are {identifier, type, length, key}.
const (
	listCurrentIDOffset = 4
	listCountOffset     = 24
	listEntriesOffset   = 28
	entryHeaderLen      = 24
	entryLengthOffset   = 20
	policyKeyLen        = 32
)

func ReadKeyList(sec SecurityHive, systemKey []byte) (KeyList, error) {
	raw, state := defaultValue(sec, keyListPath)
	switch state {
	case ValueUnreadable:
		return KeyList{}, ErrPolicyKeyUnreadable
	case ValueAbsent:
		if _, legacy := defaultValue(sec, legacyPolicyPath); legacy != ValueAbsent {
			return KeyList{}, ErrLegacyPolicyKey
		}
		return KeyList{}, ErrPolicyKeyAbsent
	}
	plain, err := openProtected(raw, systemKey)
	if err != nil {
		return KeyList{}, fmt.Errorf("%w: %w", ErrPolicyKey, err)
	}
	return parseKeyList(plain)
}

func parseKeyList(list []byte) (KeyList, error) {
	if len(list) < listEntriesOffset {
		return KeyList{}, ErrPolicyKey
	}
	kl := KeyList{Keys: map[[16]byte][]byte{}}
	copy(kl.CurrentID[:], list[listCurrentIDOffset:])
	count := binary.LittleEndian.Uint32(list[listCountOffset:])
	at := listEntriesOffset
	for range count {
		if len(list)-at < entryHeaderLen {
			return KeyList{}, ErrPolicyKey
		}
		n := uint64(binary.LittleEndian.Uint32(list[at+entryLengthOffset:]))
		if n > uint64(len(list)-at-entryHeaderLen) {
			return KeyList{}, ErrPolicyKey
		}
		id := [16]byte(list[at : at+16])
		end := at + entryHeaderLen + int(n)
		kl.Keys[id] = append([]byte(nil), list[at+entryHeaderLen:end]...)
		at = end
	}
	if cur, ok := kl.Keys[kl.CurrentID]; !ok || len(cur) != policyKeyLen {
		return KeyList{}, ErrPolicyKey
	}
	return kl, nil
}

func (kl KeyList) open(raw []byte) ([]byte, error) {
	p, err := parseProtected(raw)
	if err != nil {
		return nil, err
	}
	k, ok := kl.Keys[p.keyID]
	if !ok {
		return nil, ErrUnknownPolicyKey
	}
	return p.open(k)
}

func defaultValue(sec SecurityHive, path string) ([]byte, ValueState) {
	k, err := sec.OpenKey(path)
	if err != nil {
		if errors.Is(err, registryhive.ErrKeyNotFound) {
			return nil, ValueAbsent
		}
		return nil, ValueUnreadable
	}
	return defaultValueOf(sec, k)
}

func defaultValueOf(sec SecurityHive, k *registryhive.KeyNode) ([]byte, ValueState) {
	values, complete := sec.ValuesChecked(k)
	v, found, maybe := registryhive.FindValue(values, complete && !k.ValuesUnreadable, defaultValueName)
	switch {
	case found && v.Unreadable():
		return nil, ValueUnreadable
	case found && len(v.Raw) > 0:
		return v.Raw, ValuePresent
	case maybe:
		return nil, ValueUnreadable
	}
	return nil, ValueAbsent
}
