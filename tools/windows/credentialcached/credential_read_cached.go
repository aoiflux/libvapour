// Decodes the cached domain logon slots NL$<n> of the SECURITY hive under the
// cache key carried by the NL$KM LSA secret (S22). The used-slot layout is a
// working layout no capture has confirmed (S22 O1).
package credentialcached

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/credentiallocal"
	"github.com/aoiflux/libvapour/tools/windows/credentiallsasecrets"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

const Name = "windows.credential.read_cached"

var (
	ErrNotWindows = errors.New("credentialcached: profile is not windows")
	ErrCacheKey   = errors.New("credentialcached: nl$km secret does not give a cache key")
)

type Entry struct {
	Slot               string
	EffectiveName      string
	LogonDomainName    string
	DNSLogonDomainName string
	UserID             uint32
	Verifier           []byte
	IterationCount     uint32
}

const (
	cachePath          = "Cache"
	cacheKeySecret     = "NL$KM"
	iterationValueName = "NL$IterationCount"
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Decode cached domain logons (NL$ slots: account, domain, verifier) from the SECURITY hive under the NL$KM cache key",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Entry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %w", Name, ErrNotWindows)
	}
	cr := registryhive.CellReader(ctx)
	sec, err := registryhive.OpenHive(ctx, "SECURITY", cr)
	if err != nil {
		return nil, fmt.Errorf("%s: SECURITY hive: %w", Name, err)
	}
	d := &diagnostics{ctx: ctx}
	key := func() ([]byte, error) {
		sys, err := registryhive.OpenHive(ctx, "SYSTEM", cr)
		if err != nil {
			return nil, fmt.Errorf("SYSTEM hive: %w", err)
		}
		systemKey, ok := credentiallocal.SystemKey(sys)
		if !ok {
			return nil, credentiallocal.ErrSystemKey
		}
		return cacheKey(sec, systemKey)
	}
	rows, err := cachedLogons(d, sec, key)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if ctx.StrictMode() && d.raised > 0 {
		return rows, fmt.Errorf("%s: %d cache slots did not decode; see diagnostics", Name, d.raised)
	}
	return rows, nil
}

func cacheKey(sec credentiallsasecrets.SecurityHive, systemKey []byte) ([]byte, error) {
	keys, err := credentiallsasecrets.ReadKeyList(sec, systemKey)
	if err != nil {
		return nil, err
	}
	nlkm, err := credentiallsasecrets.ReadSecretObject(sec, keys, cacheKeySecret)
	if err != nil {
		return nil, err
	}
	if nlkm.CurrentValueState != credentiallsasecrets.ValuePresent {
		return nil, fmt.Errorf("current value is %s", nlkm.CurrentValueState)
	}
	k, ok := cacheKeyFrom(nlkm.CurrentValue)
	if !ok {
		return nil, fmt.Errorf("current value is %d bytes", len(nlkm.CurrentValue))
	}
	return k, nil
}

type slotValue struct {
	number uint64
	value  registryhive.Value
}

func cachedLogons(d *diagnostics, sec credentiallsasecrets.SecurityHive, key func() ([]byte, error)) ([]Entry, error) {
	node, err := sec.OpenKey(cachePath)
	if err != nil {
		if errors.Is(err, registryhive.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, err
	}
	values, complete := sec.ValuesChecked(node)
	if !complete || node.ValuesUnreadable {
		d.add("%s: cache key at 0x%x: values do not all read", Name, node.Address)
	}
	var iterations uint32
	var used []slotValue
	for _, v := range values {
		if v.NameUnreadable {
			continue
		}
		if v.Name == iterationValueName {
			if !v.Unreadable() && len(v.Raw) == 4 {
				iterations = binary.LittleEndian.Uint32(v.Raw)
			}
			continue
		}
		n, ok := slotNumber(v.Name)
		if !ok {
			continue
		}
		if v.Unreadable() {
			d.add("%s: slot %s at 0x%x: data does not read", Name, v.Name, node.Address)
			continue
		}
		if !emptySlot(v.Raw) {
			used = append(used, slotValue{number: n, value: v})
		}
	}
	if len(used) == 0 {
		return nil, nil
	}
	sort.Slice(used, func(i, j int) bool { return used[i].number < used[j].number })
	k, err := key()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCacheKey, err)
	}
	var rows []Entry
	for _, s := range used {
		u, err := decodeSlot(s.value.Raw, k)
		if err != nil {
			d.add("%s: slot %s at 0x%x: slot does not decode: %v", Name, s.value.Name, node.Address, err)
			continue
		}
		rows = append(rows, Entry{
			Slot:               s.value.Name,
			EffectiveName:      u.effectiveName,
			LogonDomainName:    u.logonDomainName,
			DNSLogonDomainName: u.dnsLogonDomainName,
			UserID:             u.userID,
			Verifier:           u.verifier,
			IterationCount:     iterations,
		})
	}
	return rows, nil
}

type diagnostics struct {
	ctx    tools.Context
	raised int
}

func (d *diagnostics) add(format string, args ...any) {
	d.raised++
	d.ctx.AddDiagnostic(format, args...)
}
