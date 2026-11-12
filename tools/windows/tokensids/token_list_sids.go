package tokensids

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

const Name = "windows.token.list_sids"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the user, group, restricted and capability SIDs of each process token with their attributes and documented or registry names",
		},
		RunAny,
	)
}

type TokenSID struct {
	PID             uint64
	Process         string
	ProcessAddress  uint64
	TokenAddress    uint64
	Array           Array
	Index           int
	TokenUser       bool
	Identifier      string
	Attributes      uint32
	AttributeNames  []string
	Principal       string
	PrincipalFrom   PrincipalSource
	NamesIncomplete bool
	Failure         string
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]TokenSID, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	reader, err := NewTokenReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	pids := ctx.PIDs()
	names := loadPrincipals(ctx, Name)
	var rows []TokenSID
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		base := TokenSID{PID: p.PID, Process: p.Name, ProcessAddress: p.EPROCESS}
		tok, err := reader.Token(p.EPROCESS)
		base.TokenAddress = tok.Address
		if err != nil {
			base.Failure = err.Error()
			rows = append(rows, base)
			if err := TokenFailure(ctx, Name, p.EPROCESS, tok.Address, err); err != nil {
				return rows, err
			}
			continue
		}
		for _, a := range tok.Arrays {
			if a.Err != nil {
				if err := failure(ctx, fmt.Errorf("%s: token at 0x%x: %s not listed: %w", Name, tok.Address, a.Array, a.Err)); err != nil {
					return rows, err
				}
				continue
			}
			for i := uint32(0); i < a.Count; i++ {
				row := base
				row.Array, row.Index, row.TokenUser = a.Array, int(i), a.Array == UserAndGroups && i == 0
				e, err := reader.entryAt(a, i)
				row.Attributes, row.AttributeNames = e.attributes, attributeNames(e.attributes)
				if err != nil {
					row.Failure = err.Error()
					rows = append(rows, row)
					at := e.address
					if at == 0 {
						at = a.Address + uint64(i)*reader.entry
					}
					if err := failure(ctx, fmt.Errorf("%s: sid at 0x%x: not read: %w", Name, at, err)); err != nil {
						return rows, err
					}
					continue
				}
				row.Identifier = e.value.String()
				pr := names.name(e.value)
				row.Principal, row.PrincipalFrom, row.NamesIncomplete = pr.name, pr.from, pr.incomplete
				rows = append(rows, row)
			}
		}
	}
	return rows, nil
}

func TokenFailure(ctx tools.Context, tool string, eprocess, token uint64, err error) error {
	if token == 0 {
		return failure(ctx, fmt.Errorf("%s: process at 0x%x: token not listed: %w", tool, eprocess, err))
	}
	return failure(ctx, fmt.Errorf("%s: token at 0x%x: not listed: %w", tool, token, err))
}

func failure(ctx tools.Context, err error) error {
	if ctx.StrictMode() {
		return err
	}
	ctx.AddDiagnostic("%v", err)
	return nil
}
