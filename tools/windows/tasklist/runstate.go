package tasklist

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/aoiflux/libvapour/util"
)

type RunState struct {
	LastRunTime    time.Time
	LastTaskResult uint32
}

// S37 M11: every DynamicInfo value is 36 bytes of format 3.
const (
	runStateFormat = 3
	runStateBytes  = 36
)

func DecodeDynamicInfo(b []byte) (RunState, error) {
	var s RunState
	if len(b) != runStateBytes {
		return s, fmt.Errorf("%w: DynamicInfo of %d bytes", ErrFormat, len(b))
	}
	if f := binary.LittleEndian.Uint32(b); f != runStateFormat {
		return s, fmt.Errorf("%w: DynamicInfo format %d", ErrFormat, f)
	}
	s.LastRunTime, _ = util.FiletimeToTime(binary.LittleEndian.Uint64(b[12:]))
	s.LastTaskResult = binary.LittleEndian.Uint32(b[24:])
	return s, nil
}
