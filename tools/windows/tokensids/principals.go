package tokensids

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

type PrincipalSource string

const (
	FromDocumentedSID PrincipalSource = "documented"
	FromServiceName   PrincipalSource = "service_name"
	FromSAMAccount    PrincipalSource = "sam_account"
	FromProfileFolder PrincipalSource = "profile_folder"
	FromDomainRID     PrincipalSource = "documented_rid"
)

const (
	logonSessionName   = "LOGON_ID"
	remoteMachineName  = `NT VIRTUAL MACHINE\Remote Virtual Machine`
	serviceDomain      = `NT SERVICE\`
	servicesKey        = `\Services`
	accountDomainKey   = `SAM\Domains\Account`
	accountDomainValue = "V"
	defaultValueName   = "(Default)"
	profileListKey     = `Microsoft\Windows NT\CurrentVersion\ProfileList`
	profilePathValue   = "ProfileImagePath"
	// S-1-5-21 and three sub-authorities: an 8-byte header and four words.
	accountDomainSIDSize = sidHeaderSize + 4*4
)

var accountNameKeys = []string{`SAM\Domains\Account\Users\Names`, `SAM\Domains\Account\Groups\Names`}

const builtinNameKey = `SAM\Domains\Builtin\Aliases\Names`

type nameSource struct {
	names    map[string]string
	complete bool
}

type principals struct {
	services, accounts, profiles nameSource
}

func sidOfServiceName(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	sum := sha1.Sum(b)
	s := sid{authority: ntAuthority, sub: []uint32{serviceRID}}
	for i := 0; i < len(sum)/4; i++ {
		s.sub = append(s.sub, binary.LittleEndian.Uint32(sum[4*i:]))
	}
	return s.String()
}

func loadPrincipals(ctx tools.Context, tool string) principals {
	ctx = ctx.WithoutPIDFilter()
	cells := registryhive.CellReader(ctx)
	return principals{
		services: loadServices(ctx, tool, cells),
		accounts: loadAccounts(ctx, tool, cells),
		profiles: loadProfiles(ctx, tool, cells),
	}
}

func incomplete(ctx tools.Context, tool, source string, err error) nameSource {
	ctx.AddDiagnostic("%s: %s names incomplete: %v", tool, source, err)
	return nameSource{names: map[string]string{}}
}

func loadServices(ctx tools.Context, tool string, cells memory.MemoryReader) nameSource {
	hive, err := registryhive.OpenHive(ctx, "SYSTEM", cells)
	if err != nil {
		return incomplete(ctx, tool, "service", err)
	}
	set, read := registryhive.CurrentControlSetChecked(hive)
	key, err := hive.OpenKey(set + servicesKey)
	if err != nil {
		return incomplete(ctx, tool, "service", err)
	}
	subkeys, whole := hive.SubkeysChecked(key)
	out := nameSource{names: make(map[string]string, len(subkeys)), complete: whole && read}
	for _, k := range subkeys {
		if k.NameUnreadable {
			out.complete = false
			continue
		}
		id := sidOfServiceName(k.Name)
		if _, seen := out.names[id]; !seen {
			out.names[id] = serviceDomain + k.Name
		}
	}
	if !out.complete {
		ctx.AddDiagnostic("%s: service names incomplete: control set %q, subkeys of %s not all read", tool, set, servicesKey)
	}
	return out
}

func loadAccounts(ctx tools.Context, tool string, cells memory.MemoryReader) nameSource {
	hive, err := registryhive.OpenHive(ctx, "SAM", cells)
	if err != nil {
		return incomplete(ctx, tool, "sam account", err)
	}
	out := nameSource{names: map[string]string{}, complete: true}
	add := func(keyPath, domain string) {
		key, err := hive.OpenKey(keyPath)
		if err != nil {
			out.complete = false
			ctx.AddDiagnostic("%s: sam account names incomplete: %v", tool, err)
			return
		}
		subkeys, whole := hive.SubkeysChecked(key)
		out.complete = out.complete && whole
		for _, k := range subkeys {
			v, found, unreadable := hive.ValueByNameChecked(k, defaultValueName)
			if k.NameUnreadable || !found || unreadable || v.TypeUnreadable {
				out.complete = false
				continue
			}
			out.names[domain+"-"+strconv.FormatUint(uint64(v.Type), 10)] = k.Name
		}
	}
	if domain, err := accountDomain(hive); err != nil {
		out.complete = false
		ctx.AddDiagnostic("%s: sam account names incomplete: %v", tool, err)
	} else {
		for _, k := range accountNameKeys {
			add(k, domain)
		}
	}
	add(builtinNameKey, sid{authority: ntAuthority, sub: []uint32{builtinDomainRID}}.String())
	return out
}

func accountDomain(hive *registryhive.HiveLayer) (string, error) {
	key, err := hive.OpenKey(accountDomainKey)
	if err != nil {
		return "", err
	}
	v, found, unreadable := hive.ValueByNameChecked(key, accountDomainValue)
	if !found || unreadable || v.Unreadable() || len(v.Raw) < accountDomainSIDSize {
		return "", fmt.Errorf("tokensids: account domain value %s\\%s does not read", accountDomainKey, accountDomainValue)
	}
	s, err := decodeSID(v.Raw[len(v.Raw)-accountDomainSIDSize:])
	if err != nil || !s.under(ntAuthority, ntNonUniqueRID, 4) {
		return "", fmt.Errorf("tokensids: account domain value %s\\%s does not end in an account domain sid", accountDomainKey, accountDomainValue)
	}
	return s.String(), nil
}

func loadProfiles(ctx tools.Context, tool string, cells memory.MemoryReader) nameSource {
	hive, err := registryhive.OpenHive(ctx, "SOFTWARE", cells)
	if err != nil {
		return incomplete(ctx, tool, "profile folder", err)
	}
	key, err := hive.OpenKey(profileListKey)
	if err != nil {
		return incomplete(ctx, tool, "profile folder", err)
	}
	subkeys, whole := hive.SubkeysChecked(key)
	out := nameSource{names: make(map[string]string, len(subkeys)), complete: whole}
	for _, k := range subkeys {
		v, found, unreadable := hive.ValueByNameChecked(k, profilePathValue)
		if k.NameUnreadable || unreadable || (found && v.Unreadable()) {
			out.complete = false
			continue
		}
		if !found {
			continue
		}
		path := strings.TrimRight(v.Data, `\`)
		if folder := path[strings.LastIndex(path, `\`)+1:]; folder != "" {
			out.names[k.Name] = folder
		}
	}
	if !out.complete {
		ctx.AddDiagnostic("%s: profile folder names incomplete: %s not all read", tool, profileListKey)
	}
	return out
}

type principal struct {
	name       string
	from       PrincipalSource
	incomplete bool
}

func (p principals) name(s sid) principal {
	id := s.String()
	if n, ok := documentedSIDs[id]; ok {
		return principal{n, FromDocumentedSID, false}
	}
	if n, ok := win32SIDs[id]; ok {
		return principal{n, FromDocumentedSID, false}
	}
	if s.under(ntAuthority, logonSessionRID, 3) {
		return principal{logonSessionName, FromDocumentedSID, false}
	}
	if s.under(ntAuthority, virtualMachineRID, 6) && s.sub[1] == 1 {
		return principal{remoteMachineName, FromDocumentedSID, false}
	}
	if n, ok := p.services.names[id]; ok {
		return principal{n, FromServiceName, false}
	}
	if n, ok := p.accounts.names[id]; ok {
		return principal{n, FromSAMAccount, false}
	}
	if n, ok := p.profiles.names[id]; ok {
		return principal{n, FromProfileFolder, false}
	}
	domainRelative := s.authority == ntAuthority && len(s.sub) == 5 && s.sub[0] == ntNonUniqueRID
	if domainRelative {
		if n, ok := documentedDomainRIDs[s.rid()]; ok {
			return principal{n, FromDomainRID, false}
		}
	}
	missed := !p.profiles.complete
	if s.authority == ntAuthority && len(s.sub) > 0 {
		switch s.sub[0] {
		case serviceRID:
			missed = missed || !p.services.complete
		case ntNonUniqueRID, builtinDomainRID:
			missed = missed || !p.accounts.complete
		}
	}
	return principal{incomplete: missed}
}
