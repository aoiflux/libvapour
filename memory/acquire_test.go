package memory

import (
	"errors"
	"strings"
	"testing"
)

func TestTheFileProviderOpensEachFormatAndSaysWhich(t *testing.T) {
	cases := map[string]image{
		"raw":       image(pattern(4096, 1)),
		"lime":      append(limeFile([]limeRange{{0x1000, pattern(64, 1)}}), 0, 0),
		"crashdump": crashFile([]run{{1, 1}}, nil),
	}
	for format, data := range cases {
		cfg := AcquisitionConfig{Source: tempFile(t, data)}
		if err := ValidateProviderContract(NewFileProvider(), cfg); err != nil {
			t.Errorf("%s contract: %v", format, err)
		}
		s, err := NewFileProvider().Open(cfg)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		diags := s.Diagnostics()
		if len(diags) == 0 || !strings.Contains(diags[0].Message, "opened as "+format) || diags[0].Category != DiagnosticProviderOpen {
			t.Errorf("%s diagnostics %+v", format, diags)
		}
		if format == "lime" && (len(diags) != 2 || diags[1].Category != DiagnosticProviderRead) {
			t.Errorf("lime padding not reported: %+v", diags)
		}
		if err := s.Close(); err != nil || s.Close() != nil {
			t.Errorf("%s close: %v", format, err)
		}
	}
}

func TestARefusedCaptureReachesTheCallerThroughTheSelector(t *testing.T) {
	core := elfSpec{wide: true, notes: []elfNoteSpec{{noteOwnerCore, noteAuxv, make([]byte, 16)}},
		loads: []elfLoadSpec{{phys: 0, data: pattern(64, 1)}}}.build()
	sel, err := NewProviderSelector(NewFileProvider())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = sel.Select([]string{"file"}, AcquisitionConfig{Source: tempFile(t, core)})
	if !errors.Is(err, ErrProcessCore) || !errors.Is(err, ErrNoProvider) {
		t.Errorf("err %v", err)
	}
	if _, err := NewFileProvider().Open(AcquisitionConfig{}); !errors.Is(err, ErrProviderConfig) {
		t.Errorf("no source: %v", err)
	}
}

func TestReaderAndLiveProvidersServeTheGivenReader(t *testing.T) {
	src := image(pattern(32, 1))
	if err := ValidateProviderContract(NewReaderProvider(src), AcquisitionConfig{}); err != nil {
		t.Error(err)
	}
	if _, err := NewReaderProvider(nil).Open(AcquisitionConfig{}); !errors.Is(err, ErrProviderConfig) {
		t.Errorf("nil reader: %v", err)
	}
	live := NewLiveProvider()
	if err := ValidateProviderContract(live, AcquisitionConfig{Options: map[string]any{optionLiveReader: src}}); err != nil {
		t.Error(err)
	}
	for _, opts := range []map[string]any{nil, {optionLiveReader: "not a reader"}} {
		if _, err := live.Open(AcquisitionConfig{Options: opts}); !errors.Is(err, ErrProviderConfig) {
			t.Errorf("options %v: %v", opts, err)
		}
	}
}

type fakeProvider struct {
	name string
	err  error
	log  *[]string
}

func (p fakeProvider) Name() string { return p.name }

func (p fakeProvider) Open(AcquisitionConfig) (AcquisitionSession, error) {
	*p.log = append(*p.log, p.name)
	if p.err != nil {
		return nil, p.err
	}
	return &providerSession{reader: image{1}, diagnostics: []AcquisitionDiagnostic{{Category: "made_up", Provider: "other"}}}, nil
}

func TestSelectionTriesPreferredThenTheRestByName(t *testing.T) {
	var log []string
	errC, errA := errors.New("c failed"), errors.New("a failed")
	sel, err := NewProviderSelector(fakeProvider{"c", errC, &log}, fakeProvider{"b", nil, &log}, fakeProvider{"a", errA, &log})
	if err != nil {
		t.Fatal(err)
	}
	_, name, err := sel.Select([]string{"c", "c"}, AcquisitionConfig{})
	if err != nil || name != "b" || strings.Join(log, ",") != "c,a,b" {
		t.Fatalf("chose %s after %v: %v", name, log, err)
	}
	sel, _ = NewProviderSelector(fakeProvider{"c", errC, &log}, fakeProvider{"a", errA, &log})
	_, _, err = sel.Select(nil, AcquisitionConfig{})
	if !errors.Is(err, errA) || !errors.Is(err, errC) || !strings.Contains(err.Error(), "provider c") {
		t.Errorf("all failed: %v", err)
	}
	if _, _, err := sel.Select([]string{"z"}, AcquisitionConfig{}); !errors.Is(err, ErrProviderConfig) {
		t.Errorf("unknown preference: %v", err)
	}
}

func TestSelectorsAndContractsRefuseBrokenProviders(t *testing.T) {
	var log []string
	for name, ps := range map[string][]AcquisitionProvider{
		"none":      nil,
		"nil":       {nil},
		"no name":   {fakeProvider{"", nil, &log}},
		"duplicate": {fakeProvider{"a", nil, &log}, fakeProvider{"a", nil, &log}},
	} {
		if _, err := NewProviderSelector(ps...); !errors.Is(err, ErrProviderConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	err := ValidateProviderContract(fakeProvider{"a", nil, &log}, AcquisitionConfig{})
	if !errors.Is(err, ErrProviderContract) || !strings.Contains(err.Error(), "made_up") {
		t.Errorf("bad diagnostics accepted: %v", err)
	}
	if err := ValidateProviderContract(nil, AcquisitionConfig{}); !errors.Is(err, ErrProviderContract) {
		t.Errorf("nil provider: %v", err)
	}
}

func TestStrictModeRefusesARepairedContainer(t *testing.T) {
	repaired := map[string]image{
		"crashdump": crashFile(manyRuns(crashOverwrittenRun+9), overwriteSlot(0x744f2000)),
		"lime":      append(limeFile([]limeRange{{0x1000, pattern(64, 1)}}), 0, 0),
	}
	for format, data := range repaired {
		path := tempFile(t, data)
		if _, err := NewFileProvider().Open(AcquisitionConfig{Source: path, Strict: true}); !errors.Is(err, ErrStrictRepair) {
			t.Errorf("%s strict: %v", format, err)
		}
		s, err := NewFileProvider().Open(AcquisitionConfig{Source: path})
		if err != nil {
			t.Fatalf("%s lenient: %v", format, err)
		}
		_ = s.Close()
	}
	whole := tempFile(t, limeFile([]limeRange{{0x1000, pattern(64, 1)}}))
	s, err := NewFileProvider().Open(AcquisitionConfig{Source: whole, Strict: true})
	if err != nil {
		t.Fatalf("strict clean lime: %v", err)
	}
	_ = s.Close()
}
