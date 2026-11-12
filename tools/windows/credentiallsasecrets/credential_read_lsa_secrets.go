// Decrypts the LSA secret objects of the SECURITY hive. Each value is sealed
// under a policy key from Policy\PolEKList, itself sealed under the S20 system
// key (S21).
package credentiallsasecrets

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/credentiallocal"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

const Name = "windows.credential.read_lsa_secrets"

var ErrNotWindows = errors.New("credentiallsasecrets: profile is not windows")

type SecretType string

const (
	TrustedDomainSecret SecretType = "trusted_domain"
	GlobalSecret        SecretType = "global"
	LocalSecret         SecretType = "local"
	SystemSecret        SecretType = "system"
	UnlistedSecret      SecretType = "unlisted"
)

type ValueState string

const (
	ValuePresent       ValueState = "present"
	ValueAbsent        ValueState = "absent"
	ValueUnreadable    ValueState = "unreadable"
	ValueUndecryptable ValueState = "undecryptable"
)

type Entry struct {
	Name                string
	Type                SecretType
	CurrentValue        []byte
	CurrentValueState   ValueState
	CurrentValueSetTime time.Time
	OldValue            []byte
	OldValueState       ValueState
	OldValueSetTime     time.Time
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Decrypt the LSA secret objects (current and old values, set times) of the SECURITY hive under the policy key list and the SYSTEM system key",
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
	sec, err := registryhive.OpenHive(ctx, "SECURITY", cr)
	if err != nil {
		return nil, fmt.Errorf("%s: SECURITY hive: %w", Name, err)
	}
	systemKey, ok := credentiallocal.SystemKey(sys)
	if !ok {
		return nil, fmt.Errorf("%s: %w", Name, credentiallocal.ErrSystemKey)
	}
	keys, err := ReadKeyList(sec, systemKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	d := &diagnostics{ctx: ctx}
	rows := secretObjects(d, sec, keys)
	if ctx.StrictMode() && d.raised > 0 {
		return rows, fmt.Errorf("%s: %d secret reads failed; see diagnostics", Name, d.raised)
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
