package threaddebugregisters

type Condition string

const (
	ConditionExecute   Condition = "execute"
	ConditionWrite     Condition = "write"
	ConditionIO        Condition = "io"
	ConditionReadWrite Condition = "read_write"
)

// Intel SDM Vol. 3B, "Debug Control Register (DR7)": enable bits 0-7 (Ln at
// 2n, Gn at 2n+1), R/Wn at 16+4n and LENn at 18+4n.
const (
	breakpointSlots = 4
	controlShift    = 16
	controlStride   = 4
	reservedLow     = uint64(1)<<12 | 1<<14 | 1<<15
	reservedHigh    = uint64(0xffffffff) << 32
)

var conditions = [4]Condition{ConditionExecute, ConditionWrite, ConditionIO, ConditionReadWrite}

// LEN 10 is eight bytes on the processors that define it.
var lengths = [4]uint64{1, 2, 8, 4}

type slot struct {
	index     int
	local     bool
	global    bool
	condition Condition
	length    uint64
}

// A value with a reserved bit set was never loaded into DR7, since the
// processor faults on such a write; it is reported as not a saved register.
func decodeDebugControl(dr7, width uint64) ([]slot, bool) {
	reserved := reservedLow
	if width >= 8 {
		reserved |= reservedHigh
	}
	if dr7&reserved != 0 {
		return nil, false
	}
	var out []slot
	for i := range breakpointSlots {
		local := dr7>>(2*i)&1 != 0
		global := dr7>>(2*i+1)&1 != 0
		if !local && !global {
			continue
		}
		bits := dr7 >> (controlShift + controlStride*i)
		out = append(out, slot{index: i, local: local, global: global,
			condition: conditions[bits&3], length: lengths[bits>>2&3]})
	}
	return out, true
}
