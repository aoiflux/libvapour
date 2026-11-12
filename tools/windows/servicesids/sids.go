package servicesids

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

const Name = "windows.service.list_sids"

var (
	ErrServicesUnread = errors.New("servicesids: Services key not read")
	ErrIncomplete     = errors.New("servicesids: services not read in full")
)

type ServiceSID struct {
	Service string
	SID     string
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Derive the service SID (S-1-5-80-…) of every service key in the SYSTEM hive's current control set",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type serviceHive interface {
	OpenKey(path string) (*registryhive.KeyNode, error)
	SubkeysChecked(node *registryhive.KeyNode) ([]*registryhive.KeyNode, bool)
}

func Run(ctx tools.Context) ([]ServiceSID, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	hive, err := registryhive.OpenHive(ctx, "SYSTEM", nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", Name, ErrServicesUnread, err)
	}
	return derive(ctx, hive, registryhive.CurrentControlSet(hive)+`\Services`)
}

func derive(ctx tools.Context, h serviceHive, path string) ([]ServiceSID, error) {
	root, err := h.OpenKey(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w: %w", Name, path, ErrServicesUnread, err)
	}
	subs, complete := h.SubkeysChecked(root)
	var firstErr error
	if !complete {
		ctx.AddDiagnostic("%s: key at 0x%x: subkey list not read in full: %v", Name, root.Address, ErrIncomplete)
		firstErr = fmt.Errorf("%s: %s subkeys: %w", Name, path, ErrIncomplete)
	}
	out := make([]ServiceSID, 0, len(subs))
	unnamed := 0
	for _, sk := range subs {
		if sk.NameUnreadable {
			unnamed++
			continue
		}
		out = append(out, ServiceSID{Service: sk.Name, SID: SID(sk.Name)})
	}
	if unnamed > 0 {
		ctx.AddDiagnostic("%s: key at 0x%x: %d service names not read: %v", Name, root.Address, unnamed, ErrIncomplete)
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %s names: %w", Name, path, ErrIncomplete)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Service) < strings.ToLower(out[j].Service) })
	if firstErr != nil && ctx.StrictMode() {
		return out, firstErr
	}
	return out, nil
}

// [MS-LSAT] 3.1.1.1.2: the SHA-1 of the upper-cased UTF-16 name, read as five
// 32-bit words.
func SID(service string) string {
	units := utf16.Encode([]rune(service))
	buf := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[2*i:], upper(u))
	}
	sum := sha1.Sum(buf)
	var b strings.Builder
	b.WriteString("S-1-5-80")
	for i := 0; i < len(sum)/4; i++ {
		b.WriteByte('-')
		b.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(sum[4*i:])), 10))
	}
	return b.String()
}

// One UTF-16 unit maps to one, so a surrogate half, or a character whose
// upper case leaves the basic plane, is kept as it is.
func upper(u uint16) uint16 {
	r := rune(u)
	if utf16.IsSurrogate(r) {
		return u
	}
	up := unicode.ToUpper(r)
	if up > 0xffff || utf16.IsSurrogate(up) {
		return u
	}
	return uint16(up)
}
