package callbacklist

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

var ErrUnsupportedVersion = errors.New("callbacklist: no measured callback layout for this windows build")

// Offsets into kernel records that no public kernel PDB describes (S27 M2 to
// M7). The three measured builds share one set.
type privateLayout struct {
	blockRoutine uint64

	registryRoutine  uint64
	registryAltitude uint64

	shutdownDevice uint64

	fsDriver  uint64
	fsRoutine uint64

	powerGUID    uint64
	powerRoutine uint64

	objectOperations   uint64
	objectRegistration uint64
	objectType         uint64
	objectPre          uint64
	objectPost         uint64
	registrationAlt    uint64
}

var measured64 = privateLayout{
	blockRoutine:       0x8,
	registryRoutine:    0x28,
	registryAltitude:   0x30,
	shutdownDevice:     0x10,
	fsDriver:           0x10,
	fsRoutine:          0x18,
	powerGUID:          0x24,
	powerRoutine:       0x50,
	objectOperations:   0x10,
	objectRegistration: 0x18,
	objectType:         0x20,
	objectPre:          0x28,
	objectPost:         0x30,
	registrationAlt:    0x10,
}

// Keyed by file-set build, so 19042 to 19045 use the 19041 entry (S03 4.9,
// S27 O2).
var measuredBuilds = map[uint32]privateLayout{
	14393: measured64,
	19041: measured64,
	26100: measured64,
}

func privateLayoutFor(kernelBuild uint32) (privateLayout, error) {
	l, ok := measuredBuilds[winkernel.FileSetBuild(kernelBuild)]
	if !ok {
		return privateLayout{}, fmt.Errorf("%w: build %d", ErrUnsupportedVersion, kernelBuild)
	}
	return l, nil
}

// x64 offsets of the WDK wdm.h records (S27 F5, F6).
type bugCheckLayout struct {
	routine, component, reason uint64
	hasReason                  bool
}

var (
	wdkBugCheck       = bugCheckLayout{routine: 0x10, component: 0x28}
	wdkBugCheckReason = bugCheckLayout{routine: 0x10, component: 0x18, reason: 0x28, hasReason: true}
)

// A table that does describe the record wins over the header-derived offsets.
func bugCheckLayoutOf(table symbols.SymbolTable, typeName string, fallback bugCheckLayout) bugCheckLayout {
	routine, err1 := table.Field(typeName, "CallbackRoutine")
	component, err2 := table.Field(typeName, "Component")
	if err1 != nil || err2 != nil {
		return fallback
	}
	out := bugCheckLayout{routine: routine.Offset, component: component.Offset}
	if fallback.hasReason {
		reason, err := table.Field(typeName, "Reason")
		if err != nil {
			return fallback
		}
		out.reason, out.hasReason = reason.Offset, true
	}
	return out
}

// The RefCnt bits of _EX_FAST_REF are not part of the object address.
func fastRefMask(table symbols.SymbolTable) (uint64, error) {
	f, err := table.Field("_EX_FAST_REF", "RefCnt")
	if err != nil {
		return 0, fmt.Errorf("callbacklist: _EX_FAST_REF.RefCnt: %w", err)
	}
	if f.Type.BitLength == 0 || f.Type.BitLength >= 64 || f.Type.BitOffset != 0 {
		return 0, fmt.Errorf("callbacklist: _EX_FAST_REF.RefCnt is not a low bit field (offset %d, length %d)",
			f.Type.BitOffset, f.Type.BitLength)
	}
	return ^(uint64(1)<<f.Type.BitLength - 1), nil
}
