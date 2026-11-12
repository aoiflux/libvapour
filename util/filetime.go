package util

import "time"

const (
	ticksPerSecond = 10_000_000
	nanosPerTick   = 100

	// 1601-01-01 to 1970-01-01: 369 years, 89 of them leap years.
	secondsFrom1601To1970 = (369*365 + 89) * 86400

	// FileTimeToSystemTime fails on values at or above this.
	firstRejectedFiletime = uint64(1) << 63
)

const LastRFC3339Second = 253402300799

// Zero is the value of a time that was never set, so it is no time.
func FiletimeToTime(v uint64) (time.Time, bool) {
	if v == 0 || v >= firstRejectedFiletime {
		return time.Time{}, false
	}
	seconds := int64(v/ticksPerSecond) - secondsFrom1601To1970
	nanos := int64(v%ticksPerSecond) * nanosPerTick
	return time.Unix(seconds, nanos).UTC(), true
}

// RFC 3339 has a four-digit year, so a FILETIME past 9999 has no text form.
func FiletimeToRFC3339(v uint64) (string, bool) {
	t, ok := FiletimeToTime(v)
	if !ok || t.Unix() > LastRFC3339Second {
		return "", false
	}
	return t.Format(time.RFC3339), true
}
