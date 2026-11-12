package logkernel

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/util"
)

type Level string

const (
	LevelEmerg   Level = "emerg"
	LevelAlert   Level = "alert"
	LevelCrit    Level = "crit"
	LevelErr     Level = "err"
	LevelWarning Level = "warning"
	LevelNotice  Level = "notice"
	LevelInfo    Level = "info"
	LevelDebug   Level = "debug"
)

var levelNames = [8]Level{LevelEmerg, LevelAlert, LevelCrit, LevelErr, LevelWarning, LevelNotice, LevelInfo, LevelDebug}

type Facility string

var facilityNames = map[uint8]Facility{
	0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
	16: "local0", 17: "local1", 18: "local2", 19: "local3", 20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

func facilityName(n uint8) Facility { return facilityNames[n] }

const (
	flagCont     = 8
	callerIsCPU  = 0x80000000
	callerNumber = 0x7fffffff
)

type record struct {
	seq       uint64
	hasSeq    bool
	ts        uint64
	hasTs     bool
	facility  uint8
	level     uint8
	hasLevel  bool
	flags     uint8
	caller    uint32
	hasCaller bool
	final     bool
	subsystem string
	device    string
	text      []byte
}

func callerText(id uint32) string {
	if id&callerIsCPU != 0 {
		return fmt.Sprintf("C%d", id&callerNumber)
	}
	return fmt.Sprintf("T%d", id)
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return util.DecodeUTF8Replace(b)
}

// The /dev/kmsg form: a byte outside 0x20 to 0x7e, or a backslash, becomes
// \xNN, so the line's own bytes can be read back from the text.
func escapeText(b []byte) string {
	const hexDigits = "0123456789abcdef"
	var out strings.Builder
	for _, c := range b {
		if c < ' ' || c >= 0x7f || c == '\\' {
			out.WriteString(`\x`)
			out.WriteByte(hexDigits[c>>4])
			out.WriteByte(hexDigits[c&0xf])
			continue
		}
		out.WriteByte(c)
	}
	return out.String()
}

func rowsOf(recs []record) []Row {
	var rows []Row
	for _, r := range recs {
		base := Row{Sequence: r.seq, HasSequence: r.hasSeq, TimestampNsec: r.ts, HasTimestamp: r.hasTs,
			Fragment: r.flags&flagCont != 0, Final: r.final, Subsystem: r.subsystem, Device: r.device}
		if r.hasLevel {
			base.Facility, base.FacilityNumber, base.HasFacility = facilityName(r.facility), r.facility, true
			base.Level = levelNames[r.level&7]
		}
		if r.hasCaller {
			base.Caller = callerText(r.caller)
		}
		for _, line := range bytes.Split(r.text, []byte{'\n'}) {
			row := base
			row.Line, row.LineEscaped = util.DecodeUTF8Replace(line), escapeText(line)
			rows = append(rows, row)
		}
	}
	return rows
}
