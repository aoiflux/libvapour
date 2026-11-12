package servicerecord

import "testing"

func TestValueNames(t *testing.T) {
	types := map[uint32]ServiceType{
		0x1:   "kernel driver",
		0x2:   "file system driver",
		0x10:  "own process",
		0x20:  "share process",
		0x30:  "own process|share process",
		0x60:  "share process|user service",
		0xe0:  "share process|user service|user service instance",
		0x110: "own process|interactive",
		0x408: "recognizer driver|0x400",
	}
	for v, want := range types {
		if got := serviceTypeOf(v); got != want {
			t.Errorf("type 0x%x: %q, want %q", v, got, want)
		}
	}
	states := []CurrentState{"stopped", "start pending", "stop pending", "running", "continue pending", "pause pending", "paused"}
	for i, want := range states {
		if got := currentStateOf(uint32(i + 1)); got != want {
			t.Errorf("state %d: %q", i+1, got)
		}
	}
	if got := currentStateOf(9); got != "0x9" {
		t.Errorf("state 9: %q", got)
	}
	for i, want := range []StartType{"boot", "system", "auto", "demand", "disabled"} {
		if got := startTypeOf(uint32(i)); got != want {
			t.Errorf("start %d: %q", i, got)
		}
	}
	for i, want := range []ErrorControl{"ignore", "normal", "severe", "critical"} {
		if got := errorControlOf(uint32(i)); got != want {
			t.Errorf("error control %d: %q", i, got)
		}
	}
	if startTypeOf(5) != "0x5" || errorControlOf(4) != "0x4" {
		t.Error("an undocumented value is not shown in hexadecimal")
	}
}
