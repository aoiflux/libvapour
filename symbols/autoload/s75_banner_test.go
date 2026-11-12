package autoload

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

func banners(t *testing.T, buf []byte) []LinuxBanner {
	t.Helper()
	out, err := ScanLinuxBanners(&flatImage{buf: buf}, limits.Limits{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

func TestABannerIsTheKernelsWhenTheTemplateFollowsIt(t *testing.T) {
	buf := make([]byte, 0x4000)
	putBanner(buf, 0x100, "6.17.0-35-generic", true, 0)
	putBanner(buf, 0x1000, "6.14.5-100.fc40.x86_64", true, procBannerGap)
	putBanner(buf, 0x2000, "6.12.6-100.fc40.x86_64", true, procBannerGap+1)
	putBanner(buf, 0x3000, "6.8.0-31-generic", false, 0)
	got := banners(t, buf)
	want := []struct {
		release string
		at      uint64
		rodata  bool
	}{{"6.17.0-35-generic", 0x100, true}, {"6.14.5-100.fc40.x86_64", 0x1000, true}, {"6.12.6-100.fc40.x86_64", 0x2000, false}, {"6.8.0-31-generic", 0x3000, false}}
	if len(got) != len(want) {
		t.Fatalf("banners %+v", got)
	}
	for i, w := range want {
		if got[i].Release != w.release || got[i].Offset != w.at || got[i].InKernelRodata != w.rodata || got[i].Raw != kernelBanner(w.release) {
			t.Errorf("banner %d: %+v, want %+v", i, got[i], w)
		}
	}
}

func TestOnlyPrintableTextEndingInNewlineAndNULIsABanner(t *testing.T) {
	buf := make([]byte, 0x2000)
	copy(buf[0x100:], kernelBanner("6.17.0")+"\nx")
	copy(buf[0x300:], kernelBanner("6.17.0")+"\n\n")
	b := []byte(kernelBanner("6.17.0") + "\n\x00")
	b[40] = 0x01
	copy(buf[0x500:], b)
	copy(buf[0x700:], "Linux version (builder@host) #1\n\x00")
	copy(buf[0x900:], "Linux version 2024 (builder@host) #1\n\x00")
	if got := banners(t, buf); len(got) != 0 {
		t.Errorf("banners %+v, want none", got)
	}
}

func TestTheKernelBannerIsTheOneTheTemplateFollows(t *testing.T) {
	buf := make([]byte, 0x4000)
	putBanner(buf, 0x100, "6.14.5", false, 0)
	putBanner(buf, 0x1000, "6.14.6", true, 8)
	b, err := LinuxKernelBanner(&flatImage{buf: buf}, limits.Limits{})
	if err != nil || b.Release != "6.14.6" || b.Offset != 0x1000 {
		t.Errorf("LinuxKernelBanner = %+v (%v)", b, err)
	}
	putBanner(buf, 0x2000, "6.14.7", true, 8)
	if _, err := LinuxKernelBanner(&flatImage{buf: buf}, limits.Limits{}); !errors.Is(err, ErrLinuxBannerAmbiguous) {
		t.Errorf("two in read-only data: %v", err)
	}
	buf = make([]byte, 0x4000)
	putBanner(buf, 0x100, "6.14.5", false, 0)
	if _, err := LinuxKernelBanner(&flatImage{buf: buf}, limits.Limits{}); !errors.Is(err, ErrNoLinuxBanner) || !strings.Contains(err.Error(), "6.14.5 at 0x100") {
		t.Errorf("only a copy: %v", err)
	}
	if _, err := LinuxKernelBanner(&flatImage{buf: make([]byte, 0x4000)}, limits.Limits{}); !errors.Is(err, ErrNoLinuxBanner) {
		t.Errorf("no banner: %v", err)
	}
	if _, err := ScanLinuxBanners(unreadableImage{size: 8 << 20}, limits.Limits{}); !errors.Is(err, errCaptureGone) {
		t.Errorf("unreadable capture: %v", err)
	}
}

func TestTheBannerScanStepDoesNotChangeWhatItFinds(t *testing.T) {
	buf := make([]byte, 0x3000)
	putBanner(buf, 0xf80, "6.17.0", true, 16)
	putBanner(buf, 0x1fff, "6.14.0", true, 3)
	whole, _ := scanLinuxBanners(&flatImage{buf: buf}, len(buf)+1, limits.DefaultMaxNameBytes)
	if len(whole) != 2 || !whole[0].InKernelRodata || !whole[1].InKernelRodata {
		t.Fatalf("whole image: %+v", whole)
	}
	for _, step := range []int{0x10, 0xf90, 0x1000, 0x2000} {
		got, err := scanLinuxBanners(&flatImage{buf: buf}, step, limits.DefaultMaxNameBytes)
		if err != nil || !reflect.DeepEqual(got, whole) {
			t.Errorf("step 0x%x: %+v (%v)", step, got, err)
		}
	}
}

func TestReadLinuxBannerReadsThroughTheNUL(t *testing.T) {
	buf := make([]byte, 0x3000)
	putBanner(buf, 0xfc0, "6.17.0-35-generic", false, 0)
	got, release, err := ReadLinuxBanner(&flatImage{buf: buf}, 0xfc0, limits.Limits{})
	if err != nil || release != "6.17.0-35-generic" || string(got) != kernelBanner(release)+"\n\x00" {
		t.Fatalf("ReadLinuxBanner = %q %q (%v)", got, release, err)
	}
	for name, at := range map[string]uint64{"inside the text": 0xfc1, "past the image": 0x3000} {
		if _, _, err := ReadLinuxBanner(&flatImage{buf: buf}, at, limits.Limits{}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, _, err := ReadLinuxBanner(&flatImage{buf: buf}, 0xfc0, limits.Limits{MaxNameBytes: 40}); !errors.Is(err, ErrNoLinuxBanner) {
		t.Errorf("banner longer than MaxNameBytes: %v", err)
	}
	if _, _, err := ReadLinuxBanner(&flatImage{buf: buf}, ^uint64(0)-10, limits.Limits{}); err == nil {
		t.Error("an address at the top of the space read")
	}
}

func FuzzBannerScanWindows(f *testing.F) {
	img := make([]byte, 0x2000)
	end := putBanner(img, 0x100, "6.14.5-100.fc40.x86_64", true, 4)
	putBanner(img, end+0x40, "6.12.6-100.fc40.x86_64", false, 0)
	f.Add(img, uint16(0x140))
	f.Add(img, uint16(0x100))
	f.Fuzz(func(t *testing.T, data []byte, step uint16) {
		r := &flatImage{buf: data}
		whole, wholeErr := scanLinuxBanners(r, len(data)+1, limits.DefaultMaxNameBytes)
		windowed, err := scanLinuxBanners(r, 16+int(step)%0x1000, limits.DefaultMaxNameBytes)
		if (err == nil) != (wholeErr == nil) || !reflect.DeepEqual(windowed, whole) {
			t.Fatalf("step 0x%x found %+v (%v); one window found %+v (%v)", 16+int(step)%0x1000, windowed, err, whole, wholeErr)
		}
		for _, b := range windowed {
			if !bytes.HasPrefix(data[b.Offset:], []byte(b.Raw+"\n\x00")) || !strings.HasPrefix(b.Raw, bannerPrefix+b.Release) {
				t.Fatalf("banner at 0x%x differs from the bytes there", b.Offset)
			}
		}
	})
}

func FuzzReadLinuxBanner(f *testing.F) {
	img := make([]byte, 0x2000)
	putBanner(img, 0xfc0, "6.17.0-35-generic", true, 0)
	f.Add(img, uint16(0xfc0))
	f.Add(img, uint16(0xfc1))
	f.Fuzz(func(t *testing.T, data []byte, at uint16) {
		got, release, err := ReadLinuxBanner(&flatImage{buf: data}, uint64(at), limits.Limits{})
		if err != nil {
			return
		}
		if len(got) > limits.DefaultMaxNameBytes+1 || !bytes.HasSuffix(got, []byte("\n\x00")) ||
			!bytes.HasPrefix(got, []byte(bannerPrefix+release)) || !bytes.Equal(got, data[at:int(at)+len(got)]) {
			t.Fatalf("ReadLinuxBanner at 0x%x gave %q, release %q", at, got, release)
		}
	})
}
