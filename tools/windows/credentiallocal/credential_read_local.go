// Recovers each local account's NT and LM password verifiers from the SAM
// hive. The verifiers are wrapped under a hive-wide domain key, itself wrapped
// under a system key assembled from four SYSTEM-hive class names (S20).
package credentiallocal

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

const Name = "windows.credential.read_local"

var ErrNotWindows = errors.New("credentiallocal: profile is not windows")

type Entry struct {
	User         string
	RID          uint32
	LMHash       string
	NTHash       string
	LMUnreadable bool
	NTUnreadable bool
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Recover local account NT and LM password hashes from the SAM hive under the SYSTEM system key",
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
	sys, err := registryhive.OpenHive(ctx, "SYSTEM", cr)
	if err != nil {
		return nil, fmt.Errorf("%s: SYSTEM hive: %w", Name, err)
	}
	sam, err := registryhive.OpenHive(ctx, "SAM", cr)
	if err != nil {
		return nil, fmt.Errorf("%s: SAM hive: %w", Name, err)
	}
	systemKey, ok := SystemKey(sys)
	if !ok {
		return nil, fmt.Errorf("%s: %w", Name, ErrSystemKey)
	}
	key, err := samDomainKey(sam, systemKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	rows := accounts(ctx, sam, key)
	if ctx.StrictMode() && raisedDiagnostic(ctx) {
		return rows, fmt.Errorf("%s: a value did not read; see diagnostics", Name)
	}
	return rows, nil
}

func samDomainKey(sam *registryhive.HiveLayer, systemKey []byte) ([]byte, error) {
	acct, err := sam.OpenKey(`SAM\Domains\Account`)
	if err != nil {
		return nil, ErrDomainKey
	}
	f, found, _ := sam.ValueByNameChecked(acct, "F")
	if !found || f.Unreadable() {
		return nil, ErrDomainKey
	}
	return domainKey(f.Raw, systemKey)
}

type samHive interface {
	OpenKey(string) (*registryhive.KeyNode, error)
	SubkeysChecked(*registryhive.KeyNode) ([]*registryhive.KeyNode, bool)
	ValuesChecked(*registryhive.KeyNode) ([]registryhive.Value, bool)
}

func accounts(ctx tools.Context, sam samHive, domainKey []byte) []Entry {
	users, err := sam.OpenKey(`SAM\Domains\Account\Users`)
	if err != nil {
		ctx.AddDiagnostic("%s: Users key does not read: %v", Name, err)
		return nil
	}
	subkeys, _ := sam.SubkeysChecked(users)
	var rows []Entry
	for _, k := range subkeys {
		rid, err := strconv.ParseUint(k.Name, 16, 32)
		if err != nil {
			continue
		}
		rows = append(rows, account(ctx, sam, k, uint32(rid), domainKey))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].RID < rows[j].RID })
	return rows
}

func account(ctx tools.Context, sam samHive, node *registryhive.KeyNode, rid uint32, domainKey []byte) Entry {
	e := Entry{RID: rid}
	v, found, unreadable := valueFor(sam, node, "V")
	if !found || unreadable {
		ctx.AddDiagnostic("%s: account %d: V value does not read", Name, rid)
		e.LMUnreadable, e.NTUnreadable = true, true
		return e
	}
	e.User = accountName(v.Raw)
	e.LMHash, e.LMUnreadable = renderHash(ctx, v.Raw, domainKey, vLMHashEntry, rid, false)
	e.NTHash, e.NTUnreadable = renderHash(ctx, v.Raw, domainKey, vNTHashEntry, rid, true)
	return e
}

func renderHash(ctx tools.Context, v, domainKey []byte, entry int, rid uint32, nt bool) (string, bool) {
	hash, present, ok := hashFromRecord(v, domainKey, entry, rid, nt)
	if !ok {
		ctx.AddDiagnostic("%s: account %d: hash record at entry %d does not decrypt", Name, rid, entry)
		return "", true
	}
	if !present {
		return "", false
	}
	return hex.EncodeToString(hash[:]), false
}

func valueFor(sam samHive, node *registryhive.KeyNode, name string) (registryhive.Value, bool, bool) {
	values, _ := sam.ValuesChecked(node)
	v, found, _ := registryhive.FindValue(values, true, name)
	return v, found, v.Unreadable()
}

func raisedDiagnostic(ctx tools.Context) bool {
	v, ok := ctx.Options[diagnosticsKey]
	if !ok {
		return false
	}
	sink, ok := v.(*[]string)
	return ok && sink != nil && len(*sink) > 0
}

const diagnosticsKey = "diagnostics"
