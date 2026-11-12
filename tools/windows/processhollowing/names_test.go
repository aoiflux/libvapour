package processhollowing

import "testing"

func TestTheLastComponentFollowsTheLastBackslash(t *testing.T) {
	for in, want := range map[string]string{
		`\Device\HarddiskVolume2\Windows\a.exe`: "a.exe",
		`a.exe`:                                 "a.exe",
		`\Windows\`:                             "",
	} {
		if got := lastComponent(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestOneNameDiffersFromNothing(t *testing.T) {
	if _, differ := lastComponentsDiffer([]namedPath{{"view file", `\a.exe`}}); differ {
		t.Error("a single name differed")
	}
}

func TestTheImageFileNameRule(t *testing.T) {
	for _, c := range []struct {
		name, component string
		match           bool
	}{
		{"app.exe", "APP.EXE", true},
		{"app.exe", "app.dll", false},
		{"VmComputeAgent", "VmComputeAgent.exe", true},
		{"VmComputeAgen", "VmComputeAgent.exe", false},
		{"caf\xe9.exe", "café.exe", true},
	} {
		if got := imageFileNameMatches(c.name, c.component, 14); got != c.match {
			t.Errorf("%q against %q: %v, want %v", c.name, c.component, got, c.match)
		}
	}
}
