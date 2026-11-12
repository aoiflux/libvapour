package servicesids

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

// [MS-LSAT] 3.1.1.1.2 gives the ALG example.
func TestTheMicrosoftExampleIsReproduced(t *testing.T) {
	if got := SID("ALG"); got != "S-1-5-80-2387347252-3645287876-2469496166-3824418187-3586569773" {
		t.Fatalf("SID(ALG) = %s", got)
	}
	if SID("alg") != SID("ALG") {
		t.Error("service names compare without case")
	}
}

func TestEveryNamedServiceKeyGetsItsSID(t *testing.T) {
	h := registrytest.NewFakeHive("ROOT")
	root := h.Path(`ControlSet001\Services`)
	h.Key(root, "zz")
	h.Key(root, "ALG")
	h.UnnamedKey(root)
	var diags []string
	out, err := derive(tools.Context{Options: map[string]any{"diagnostics": &diags, "strict": true}}, h, `ControlSet001\Services`)
	if !errors.Is(err, ErrIncomplete) || len(out) != 2 || out[0].Service != "ALG" || out[1].Service != "zz" {
		t.Fatalf("%v %+v", err, out)
	}
	if out[0].SID != SID("ALG") || len(diags) != 1 {
		t.Errorf("%+v %q", out, diags)
	}
	if _, err := derive(tools.Context{}, h, `x`); !errors.Is(err, ErrServicesUnread) {
		t.Errorf("err %v", err)
	}
}

func FuzzServiceSID(f *testing.F) {
	f.Add("ALG")
	f.Add("Dienst-ü")
	f.Fuzz(func(t *testing.T, name string) {
		sid := SID(name)
		parts := strings.Split(sid, "-")
		if len(parts) != 9 || !strings.HasPrefix(sid, "S-1-5-80-") {
			t.Fatalf("SID(%q) = %s", name, sid)
		}
	})
}
