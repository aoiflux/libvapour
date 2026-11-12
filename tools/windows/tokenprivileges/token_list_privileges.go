package tokenprivileges

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/tokensids"
)

const Name = "windows.token.list_privileges"

const maskBits = 64

var (
	ErrLayout           = errors.New("tokenprivileges: symbol table lacks a privilege member")
	ErrPrivilegesUnread = errors.New("tokenprivileges: privilege masks do not read")
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List each privilege set in a process token's present, enabled and enabled-by-default masks with its documented name and user right",
		},
		RunAny,
	)
}

type TokenPrivilege struct {
	PID              uint64
	Process          string
	ProcessAddress   uint64
	TokenAddress     uint64
	LUID             uint32
	Constant         string
	Privilege        string
	UserRight        string
	Present          bool
	Enabled          bool
	EnabledByDefault bool
	Failure          string
}

type masks struct {
	sepAt, present, enabled, byDefault uint64
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]TokenPrivilege, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	reader, err := tokensids.NewTokenReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	m, err := maskLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	pids := ctx.PIDs()
	var rows []TokenPrivilege
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		base := TokenPrivilege{PID: p.PID, Process: p.Name, ProcessAddress: p.EPROCESS}
		tok, err := reader.Token(p.EPROCESS)
		base.TokenAddress = tok.Address
		if err == nil {
			var bits []TokenPrivilege
			if bits, err = m.read(ctx.Memory, ctx.Symbols, base); err == nil {
				rows = append(rows, bits...)
				continue
			}
		}
		base.Failure = err.Error()
		rows = append(rows, base)
		if err := tokensids.TokenFailure(ctx, Name, p.EPROCESS, tok.Address, err); err != nil {
			return rows, err
		}
	}
	return rows, nil
}

func maskLayout(t symbols.SymbolTable) (masks, error) {
	var missing []string
	offset := func(typ, name string) uint64 {
		f, err := t.Field(typ, name)
		if err != nil {
			missing = append(missing, typ+"."+name)
			return 0
		}
		return f.Offset
	}
	m := masks{
		sepAt:     offset("_TOKEN", "Privileges"),
		present:   offset("_SEP_TOKEN_PRIVILEGES", "Present"),
		enabled:   offset("_SEP_TOKEN_PRIVILEGES", "Enabled"),
		byDefault: offset("_SEP_TOKEN_PRIVILEGES", "EnabledByDefault"),
	}
	if len(missing) > 0 {
		return masks{}, fmt.Errorf("%w: %s", ErrLayout, strings.Join(missing, ", "))
	}
	return m, nil
}

func (m masks) read(mem memory.MemoryReader, t symbols.SymbolTable, base TokenPrivilege) ([]TokenPrivilege, error) {
	at := base.TokenAddress + m.sepAt
	var v [3]uint64
	for i, off := range []uint64{m.present, m.enabled, m.byDefault} {
		x, err := t.ReadUint64(mem, at+off)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrPrivilegesUnread, err)
		}
		v[i] = x
	}
	return expand(base, v[0], v[1], v[2]), nil
}

func expand(base TokenPrivilege, present, enabled, byDefault uint64) []TokenPrivilege {
	var rows []TokenPrivilege
	for bit := uint32(0); bit < maskBits; bit++ {
		mask := uint64(1) << bit
		if (present|enabled|byDefault)&mask == 0 {
			continue
		}
		row := base
		row.LUID = bit
		row.Present, row.Enabled, row.EnabledByDefault = present&mask != 0, enabled&mask != 0, byDefault&mask != 0
		if d, ok := privilegeByLUID[bit]; ok {
			row.Constant, row.Privilege, row.UserRight = d.constant, d.privilege, d.userRight
		}
		rows = append(rows, row)
	}
	return rows
}
