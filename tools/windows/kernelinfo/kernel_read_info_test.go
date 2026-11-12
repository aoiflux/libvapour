package kernelinfo

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/tools"
)

func setTime(k *testsupport.S64Kernel, member, v uint64, torn bool) {
	at := testsupport.S64SharedData + member
	k.U32(at, uint32(v))
	k.U32(at+4, uint32(v>>32))
	high := uint32(v >> 32)
	if torn {
		high++
	}
	k.U32(at+8, high)
}

func TestTheRowsComeFromTheSharedDataAndTheGlobals(t *testing.T) {
	k := testsupport.NewS64Kernel()
	when := time.Date(2026, 5, 6, 18, 24, 25, 0, time.UTC)
	setTime(k, testsupport.S64SystemTime, uint64(when.UnixNano()/100)+filetimeToUnix, false)
	setTime(k, testsupport.S64InterruptTime, 36_000_000_000, false)
	k.Write(testsupport.S64SharedData+testsupport.S64SystemRoot, append(testsupport.S64UTF16(`C:\Windows`), 0, 0))
	k.U32(testsupport.S64SharedData+testsupport.S64ProductType, 3)
	k.Write(k.Global("KeNumberProcessors", 4), []byte{8, 1})
	k.Write(k.Global("NtBuildLab", 64), []byte("26100.ge_release\x00junk"))
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.Variable] = r.Value
	}
	for name, want := range map[string]string{
		"NtMajorVersion": "10", "NtMinorVersion": "0", "NtBuildNumber": "26100", "KeNumberProcessors": "8",
		"NtProductType": "NtProductServer", "NtSystemRoot": `C:\Windows`, "NtBuildLab": "26100.ge_release",
		"SystemTime": when.Format(SystemTimeLayout), "InterruptTime": "1h0m0s", "PointerSize": "8",
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
	}
}

func TestTheKernelImageHeaderGivesItsFields(t *testing.T) {
	k := testsupport.NewS64Kernel()
	image := testsupport.BuildMappedPE(0)
	base := k.Alloc(uint64(len(image)))
	k.Write(base, image)
	ctx := k.Context()
	ctx.Options[tools.OptionKernelBase] = base
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	var order []string
	for _, r := range rows {
		got[r.Variable] = r.Value
		order = append(order, r.Variable)
	}
	stamp := time.Unix(int64(testsupport.MappedPETimeDateStamp), 0).UTC().Format(SystemTimeLayout)
	for name, want := range map[string]string{
		"Machine": fmt.Sprintf("0x%x", testsupport.MappedPEMachine), "TimeDateStamp": stamp,
		"MajorOperatingSystemVersion": fmt.Sprint(testsupport.MappedPEMajorOSVersion),
		"MinorOperatingSystemVersion": fmt.Sprint(testsupport.MappedPEMinorOSVersion),
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
	}
	if n := len(order); n < 4 || order[n-4] != "Machine" || order[n-1] != "MinorOperatingSystemVersion" {
		t.Errorf("the header rows are not last, in S64 4.10 order: %v", order)
	}
}

func TestAnUnreadKernelHeaderGivesADiagnosticAndNoRows(t *testing.T) {
	k := testsupport.NewS64Kernel()
	ctx := k.Context()
	var diagnostics []string
	ctx.Options["diagnostics"] = &diagnostics
	ctx.Options[tools.OptionKernelBase] = k.Skip()
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Variable == "Machine" || r.Variable == "TimeDateStamp" {
			t.Errorf("row %s = %q from a header that does not read", r.Variable, r.Value)
		}
	}
	found := false
	for _, d := range diagnostics {
		found = found || strings.Contains(d, "pe header does not read")
	}
	if !found {
		t.Errorf("no diagnostic names the unread header: %q", diagnostics)
	}
}

func TestATornTimeIsAnError(t *testing.T) {
	k := testsupport.NewS64Kernel()
	setTime(k, testsupport.S64SystemTime, 1<<40, true)
	if _, err := SharedTime(k.Context(), "SystemTime"); !errors.Is(err, ErrTimeTorn) {
		t.Errorf("err = %v", err)
	}
	if _, err := SharedTime(k.Context(), "Nothing"); !errors.Is(err, ErrNoSharedType) {
		t.Errorf("err = %v", err)
	}
}

func TestFiletimeRange(t *testing.T) {
	if _, ok := FiletimeUTC(filetimeToUnix - 1); ok {
		t.Error("a time before 1970 was placed")
	}
	if at, ok := FiletimeUTC(filetimeToUnix); !ok || !at.Equal(time.Unix(0, 0)) {
		t.Error("the epoch is not 1970")
	}
	if _, ok := FiletimeUTC(^uint64(0)); ok {
		t.Error("an overflowing time was placed")
	}
}

func FuzzSharedTime(f *testing.F) {
	f.Add(uint32(1), uint32(2), uint32(2))
	k := testsupport.NewS64Kernel()
	ctx := k.Context()
	f.Fuzz(func(t *testing.T, low, high1, high2 uint32) {
		at := testsupport.S64SharedData + testsupport.S64SystemTime
		k.U32(at, low)
		k.U32(at+4, high1)
		k.U32(at+8, high2)
		v, err := SharedTime(ctx, "SystemTime")
		if (err == nil) != (high1 == high2) {
			t.Errorf("err %v for high parts %d %d", err, high1, high2)
		}
		if err == nil && v != uint64(high1)<<32|uint64(low) {
			t.Errorf("value 0x%x", v)
		}
	})
}
