package limits

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestZeroFieldsTakeTheirDefaults(t *testing.T) {
	got, err := Limits{}.Resolved()
	if err != nil {
		t.Fatal(err)
	}
	want := Limits{
		MaxListEntries: DefaultMaxListEntries, MaxTableEntries: DefaultMaxTableEntries,
		MaxRowsPerObject: DefaultMaxRowsPerObject, MaxRecursionDepth: DefaultMaxRecursionDepth,
		MaxPathSteps: DefaultMaxPathSteps, MaxNameBytes: DefaultMaxNameBytes,
		MaxTextBytes: DefaultMaxTextBytes, MaxBufferBytes: DefaultMaxBufferBytes,
		MaxKernelImageBytes: DefaultMaxKernelImageBytes, MaxRegionScanBytes: DefaultMaxRegionScanBytes,
		MaxMatchesPerChunk: DefaultMaxMatchesPerChunk, PTECacheEntries: DefaultPTECacheEntries,
		Workers:          min(runtime.GOMAXPROCS(0), CeilingWorkers),
		MaxArtifactBytes: DefaultMaxArtifactBytes, MaxArchiveBytes: DefaultMaxArchiveBytes,
		MaxImageBytes:   DefaultMaxImageBytes,
		RowPreviewBytes: DefaultRowPreviewBytes, NameAttempts: DefaultNameAttempts,
	}
	if got != want || Default() != want {
		t.Errorf("resolved %+v\ndefault %+v\nwant %+v", got, Default(), want)
	}
}

func TestSetFieldsAreKept(t *testing.T) {
	got, err := Limits{MaxListEntries: 7, MaxNameBytes: 300, Workers: 1}.Resolved()
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxListEntries != 7 || got.MaxNameBytes != 300 || got.Workers != 1 || got.MaxTableEntries != DefaultMaxTableEntries {
		t.Errorf("%+v", got)
	}
}

func TestEveryCeilingIsAccepted(t *testing.T) {
	l := Limits{
		MaxListEntries: CeilingEntries, MaxTableEntries: CeilingEntries, MaxRowsPerObject: CeilingEntries,
		MaxRecursionDepth: CeilingRecursionDepth, MaxPathSteps: CeilingPathSteps,
		MaxNameBytes: CeilingBytes, MaxTextBytes: CeilingBytes, MaxBufferBytes: CeilingBytes,
		MaxKernelImageBytes: CeilingBytes, MaxRegionScanBytes: CeilingRegionScan,
		MaxMatchesPerChunk: CeilingMatches, PTECacheEntries: CeilingPTECache, Workers: CeilingWorkers,
		MaxArtifactBytes: CeilingImageBytes, MaxArchiveBytes: CeilingImageBytes, MaxImageBytes: CeilingImageBytes,
		RowPreviewBytes: CeilingImageBytes,
		NameAttempts:    CeilingNameAttempts,
	}
	if _, err := l.Resolved(); err != nil {
		t.Error(err)
	}
}

func TestRefusedValuesNameTheirField(t *testing.T) {
	for _, c := range []struct {
		l      Limits
		field  string
		reason string
	}{
		{Limits{MaxListEntries: -1}, "MaxListEntries", "negative"},
		{Limits{MaxRegionScanBytes: -5}, "MaxRegionScanBytes", "negative"},
		{Limits{Workers: CeilingWorkers + 1}, "Workers", "past its ceiling"},
		{Limits{MaxRecursionDepth: CeilingRecursionDepth + 1}, "MaxRecursionDepth", "past its ceiling"},
		{Limits{MaxImageBytes: CeilingImageBytes + 1}, "MaxImageBytes", "past its ceiling"},
		{Limits{MaxNameBytes: DefaultMaxTextBytes + 1}, "MaxNameBytes", "exceeds MaxTextBytes"},
		{Limits{MaxTextBytes: 10, MaxBufferBytes: 9, MaxNameBytes: 1}, "MaxTextBytes", "exceeds MaxBufferBytes"},
		{Limits{RowPreviewBytes: 2, MaxArtifactBytes: 1}, "RowPreviewBytes", "exceeds MaxArtifactBytes"},
		{Limits{MaxArtifactBytes: DefaultMaxImageBytes + 1}, "MaxArtifactBytes", "exceeds MaxImageBytes"},
	} {
		_, err := c.l.Resolved()
		var le *Error
		if !errors.As(err, &le) {
			t.Errorf("%s: %v, want *Error", c.field, err)
			continue
		}
		if le.Field != c.field || !strings.Contains(le.Error(), c.reason) || !strings.HasPrefix(le.Error(), "limits: "+c.field+" ") {
			t.Errorf("%s: %q", c.field, le.Error())
		}
	}
}

func TestEffectiveFallsBackWhole(t *testing.T) {
	if got := (Limits{MaxListEntries: 9}).Effective(); got.MaxListEntries != 9 || got.MaxTableEntries != DefaultMaxTableEntries {
		t.Errorf("%+v", got)
	}
	if got := (Limits{MaxListEntries: 9, Workers: -1}).Effective(); got != Default() {
		t.Errorf("%+v", got)
	}
}
