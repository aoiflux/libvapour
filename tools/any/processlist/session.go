package processlist

import (
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

const (
	SessionIDNotApplicable = int64(-1)
	SessionIDUnreadable    = int64(-2)
)

// Build 26100 does not type the session space; the typed SessionId of 14393
// and 19045 sits here, and the value here equals the token's session on 26100
// (S25 T5, M5).
const untypedSessionIDOffset = uint64(8)

type SessionResolver struct {
	session  optionalField
	idOffset uint64
	untyped  bool
	reported bool
}

func NewSessionResolver(ctx tools.Context) *SessionResolver {
	r := &SessionResolver{session: lookupOptionalField(ctx, "_EPROCESS", "Session"), idOffset: untypedSessionIDOffset, untyped: true}
	for _, typeName := range []string{"_MM_SESSION_SPACE", "_PSP_SESSION_SPACE"} {
		if f := lookupOptionalField(ctx, typeName, "SessionId"); f.present {
			r.idOffset, r.untyped = f.offset, false
			break
		}
	}
	return r
}

func (r *SessionResolver) SessionID(ctx tools.Context, eprocess uint64) int64 {
	return r.SessionIDIn(ctx, ctx.Memory, eprocess)
}

// object holds the _EPROCESS; the session space is always read from kernel
// memory.
func (r *SessionResolver) SessionIDIn(ctx tools.Context, object memory.MemoryReader, eprocess uint64) int64 {
	if !r.session.present {
		return SessionIDUnreadable
	}
	space, err := ctx.Symbols.ReadPointer(object, eprocess+r.session.offset)
	if err != nil {
		return SessionIDUnreadable
	}
	if space == 0 {
		return SessionIDNotApplicable
	}
	if r.untyped && !r.reported {
		ctx.AddDiagnostic("processlist: session space has no typed SessionId, read at offset %d", untypedSessionIDOffset)
		r.reported = true
	}
	id, err := ctx.Symbols.ReadUint32(ctx.Memory, space+r.idOffset)
	if err != nil {
		return SessionIDUnreadable
	}
	return int64(id)
}
