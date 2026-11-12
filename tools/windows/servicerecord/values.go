package servicerecord

import (
	"fmt"
	"strings"
)

type (
	ServiceType  string
	CurrentState string
	StartType    string
	ErrorControl string
	Finding      string
)

const (
	FindingUnlinked      Finding = "unlinked"
	FindingNoRegistryKey Finding = "no registry key"
	FindingRegistryOnly  Finding = "registry only"
)

// S34 D1, D3 and D5; bit 0x80 is named from D5's wording (S34 O7).
var typeBits = []struct {
	bit  uint32
	name string
}{
	{0x1, "kernel driver"},
	{0x2, "file system driver"},
	{0x4, "adapter"},
	{0x8, "recognizer driver"},
	{0x10, "own process"},
	{0x20, "share process"},
	{0x40, "user service"},
	{0x80, "user service instance"},
	{0x100, "interactive"},
}

const (
	typeDriver    = 0x1 | 0x2
	typeWin32     = 0x10 | 0x20
	typeKind      = 0x3f
	typeKnownBits = 0x1ff
)

func serviceTypeOf(v uint32) ServiceType {
	var parts []string
	rest := v
	for _, b := range typeBits {
		if v&b.bit != 0 {
			parts = append(parts, b.name)
			rest &^= b.bit
		}
	}
	if rest != 0 {
		parts = append(parts, fmt.Sprintf("0x%x", rest))
	}
	return ServiceType(strings.Join(parts, "|"))
}

var stateNames = []CurrentState{"stopped", "start pending", "stop pending", "running", "continue pending", "pause pending", "paused"}

const (
	stateStopped = 1
	stateLast    = 7
)

func currentStateOf(v uint32) CurrentState {
	if v >= stateStopped && v <= stateLast {
		return stateNames[v-stateStopped]
	}
	return CurrentState(fmt.Sprintf("0x%x", v))
}

var startNames = []StartType{"boot", "system", "auto", "demand", "disabled"}

func startTypeOf(v uint32) StartType {
	if int(v) < len(startNames) {
		return startNames[v]
	}
	return StartType(fmt.Sprintf("0x%x", v))
}

var errorControlNames = []ErrorControl{"ignore", "normal", "severe", "critical"}

func errorControlOf(v uint32) ErrorControl {
	if int(v) < len(errorControlNames) {
		return errorControlNames[v]
	}
	return ErrorControl(fmt.Sprintf("0x%x", v))
}
