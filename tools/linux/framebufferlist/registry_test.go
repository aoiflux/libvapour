package framebufferlist

import (
	"bytes"
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	kt "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const (
	registered = 0xffffffff82000000
	count      = 0xffffffff82000100
	infoSize   = 0x200
	offVar     = 0x10
	offFix     = 0xc0
	offBase    = 0x120
	offScreen  = 0x128
	offState   = 0x130
	offDev     = 0x138
	offNode    = 0x4
)

func fbTypes(t testing.TB, withDev bool) *kt.Table {
	i := kt.NewTypes(8)
	u32 := kt.Base("unsigned int")
	bf := map[string]kt.F{"offset": {Off: 0, Type: u32}, "length": {Off: 4, Type: u32}, "msb_right": {Off: 8, Type: u32}}
	i.Struct("fb_bitfield", 12, bf)
	i.Struct("fb_var_screeninfo", 0xa0, map[string]kt.F{
		"xres": {Off: 0, Type: u32}, "yres": {Off: 4, Type: u32}, "xres_virtual": {Off: 8, Type: u32},
		"yres_virtual": {Off: 0xc, Type: u32}, "xoffset": {Off: 0x10, Type: u32}, "yoffset": {Off: 0x14, Type: u32},
		"bits_per_pixel": {Off: 0x18, Type: u32}, "grayscale": {Off: 0x1c, Type: u32},
		"red": {Off: 0x20, Type: kt.Struct("fb_bitfield")}, "green": {Off: 0x2c, Type: kt.Struct("fb_bitfield")},
		"blue": {Off: 0x38, Type: kt.Struct("fb_bitfield")}, "transp": {Off: 0x44, Type: kt.Struct("fb_bitfield")},
	})
	i.Struct("fb_fix_screeninfo", 0x50, map[string]kt.F{
		"id": {Off: 0, Type: kt.Arr(16, kt.Base("char"))}, "smem_start": {Off: 0x10, Type: kt.Base("long unsigned int")},
		"smem_len": {Off: 0x18, Type: u32}, "type": {Off: 0x1c, Type: u32}, "visual": {Off: 0x24, Type: u32},
		"line_length": {Off: 0x30, Type: u32},
	})
	info := map[string]kt.F{
		"node": {Off: offNode, Type: kt.Base("int")}, "var": {Off: offVar, Type: kt.Struct("fb_var_screeninfo")},
		"fix": {Off: offFix, Type: kt.Struct("fb_fix_screeninfo")}, "screen_base": {Off: offBase, Type: kt.Ptr(kt.Base("char"))},
		"screen_size": {Off: offScreen, Type: kt.Base("long unsigned int")}, "state": {Off: offState, Type: u32},
	}
	if withDev {
		info["dev"] = kt.F{Off: offDev, Type: kt.Ptr(kt.Struct("device"))}
	}
	i.Struct("fb_info", infoSize, info)
	i.Struct("kobject", 0x40, map[string]kt.F{"name": {Off: 0, Type: kt.Ptr(kt.Base("char"))}})
	i.Struct("device", 0x80, map[string]kt.F{"kobj": {Off: 0x10, Type: kt.Struct("kobject")}})
	i.Symbol("registered_fb", registered, kt.Void())
	i.Symbol("num_registered_fb", count, kt.Void())
	return i.Table(t)
}

type fb struct {
	at, base, screen, smem uint64
	node                   int32
	id, device             string
	xres, yres, bpp, line  uint32
	gray, visual, state    uint32
	colors                 [4][3]uint32
}

var xrgb = [4][3]uint32{{16, 8, 0}, {8, 8, 0}, {0, 8, 0}, {0, 0, 0}}

func put(m *kt.Memory, slot int, f fb) {
	m.U64(registered+uint64(8*slot), f.at)
	m.Map(f.at, infoSize)
	m.U32(f.at+offNode, uint32(f.node))
	v := f.at + offVar
	m.U32(v, f.xres)
	m.U32(v+4, f.yres)
	m.U32(v+8, f.xres)
	m.U32(v+0xc, f.yres)
	m.U32(v+0x18, f.bpp)
	m.U32(v+0x1c, f.gray)
	for c, bits := range f.colors {
		for j, x := range bits {
			m.U32(v+0x20+uint64(12*c+4*j), x)
		}
	}
	x := f.at + offFix
	m.Str(x, f.id)
	m.U32(x+0x18, uint32(f.smem))
	m.U32(x+0x24, f.visual)
	m.U32(x+0x30, f.line)
	m.U64(f.at+offBase, f.base)
	m.U64(f.at+offScreen, f.screen)
	m.U32(f.at+offState, f.state)
	if f.device != "" {
		dev := f.at + 0x1000
		m.U64(dev+0x10, dev+0x100)
		m.Str(dev+0x100, f.device)
		m.U64(f.at+offDev, dev)
	}
}

const (
	info0 = 0xffff888000100000
	info2 = 0xffff888000200000
	pix0  = 0xffffc90000400000
)

func pixels() []byte {
	out := make([]byte, 4*2*4)
	for i := range 8 {
		copy(out[4*i:], []byte{byte(10 * i), byte(10*i + 1), byte(10*i + 2), 0})
	}
	return out
}

func fixture() *kt.Memory {
	m := kt.NewMemory()
	m.Map(registered, 0x200)
	put(m, 0, fb{at: info0, base: pix0, screen: 32, node: 0, id: "hyperv_drmdrmfb", device: "fb0", xres: 4, yres: 2,
		bpp: 32, line: 16, visual: visualTrueColor, colors: xrgb})
	m.Write(pix0, pixels())
	put(m, 2, fb{at: info2, base: pix0 + 0x10000, smem: 64, node: 1, id: "yuv", xres: 8, yres: 4, bpp: 16, line: 16,
		gray: 'Y' | 'U'<<8 | 'Y'<<16 | 'V'<<24, visual: 6, state: 1})
	m.Write(pix0+0x10000, make([]byte, 64))
	m.U32(count, 2)
	return m
}

func run(t *testing.T, m *kt.Memory, withDev bool, opts map[string]any) ([]Framebuffer, []string, error) {
	t.Helper()
	ctx, diags := kt.Context(m, fbTypes(t, withDev), opts)
	rows, err := Run(ctx)
	return rows, *diags, err
}

func TestRegisteredFramebuffersAreListed(t *testing.T) {
	rows, diags, err := run(t, fixture(), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Framebuffer{
		{Slot: 0, Address: info0, Node: 0, Device: "fb0", DeviceKnown: true, ID: "hyperv_drmdrmfb", ScreenAddress: pix0,
			ScreenSize: 32, XRes: 4, YRes: 2, VirtualXRes: 4, VirtualYRes: 2, BitsPerPixel: 32, LineLength: 16,
			Visual: "truecolor", State: "running"},
		{Slot: 2, Address: info2, Node: 1, DeviceKnown: true, ID: "yuv", ScreenAddress: pix0 + 0x10000, ScreenSize: 64,
			XRes: 8, YRes: 4, VirtualXRes: 8, VirtualYRes: 4, BitsPerPixel: 16, LineLength: 16, Visual: "fourcc",
			FourCC: "YUYV", State: "suspended"},
	}
	if len(rows) != 2 || rows[0] != want[0] || rows[1] != want[1] {
		t.Errorf("rows\n got %+v\nwant %+v", rows, want)
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "node 1, but it is in registered_fb[2]") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestWithoutTheDeviceMemberTheDeviceIsUnknown(t *testing.T) {
	rows, _, err := run(t, fixture(), false, nil)
	if err != nil || len(rows) != 2 || rows[0].DeviceKnown || rows[0].Device != "" {
		t.Fatalf("rows %+v, %v", rows, err)
	}
}

func TestTheCountIsChecked(t *testing.T) {
	m := fixture()
	m.U32(count, 3)
	_, diags, _ := run(t, m, true, nil)
	if !strings.Contains(strings.Join(diags, "\n"), "num_registered_fb is 3, but 2 slots") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestScreenMemoryIsSaved(t *testing.T) {
	dir := t.TempDir()
	rows, diags, err := run(t, fixture(), true, map[string]any{OptionDump: true, "output_dir": dir})
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].File != "framebuffer.kernel.0xffff888000100000.hyperv_drmdrmfb.png" ||
		rows[1].File != "framebuffer.kernel.0xffff888000200000.yuv.bin" {
		t.Fatalf("files %q %q, diagnostics %q", rows[0].File, rows[1].File, diags)
	}
	data, err := os.ReadFile(filepath.Join(dir, rows[0].File))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	r, g, b, a := img.At(1, 1).RGBA()
	if r>>8 != 52 || g>>8 != 51 || b>>8 != 50 || a>>8 != 255 {
		t.Errorf("pixel (1,1) = %d %d %d %d", r>>8, g>>8, b>>8, a>>8)
	}
	raw, err := os.ReadFile(filepath.Join(dir, rows[1].File))
	if err != nil || len(raw) != 64 {
		t.Errorf("raw file: %d bytes, %v", len(raw), err)
	}
	if _, _, err := run(t, fixture(), true, map[string]any{OptionDump: true, "output_dir": dir}); err != nil {
		t.Fatal(err)
	}
}

func TestSavingNeedsAnOutputDirectory(t *testing.T) {
	if _, _, err := run(t, fixture(), true, map[string]any{OptionDump: true}); !errors.Is(err, ErrNoOutputDir) {
		t.Errorf("%v", err)
	}
}

func TestAnUnreadableEntryIsSkippedOrInStrictModeAnError(t *testing.T) {
	m := fixture()
	m.U64(registered+8, 0xffff888000300000)
	rows, diags, err := run(t, m, true, nil)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "fb_info at 0xffff888000300000 (registered_fb[1])") {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := run(t, m, true, map[string]any{"strict": true}); err == nil {
		t.Error("strict mode accepted an unreadable fb_info")
	}
}

func TestTheRegistryAndTypeAreRequired(t *testing.T) {
	ctx, _ := kt.Context(fixture(), kt.NewTypes(8).Table(t), nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoRegistry) {
		t.Errorf("no registry: %v", err)
	}
	i := kt.NewTypes(8)
	i.Symbol("registered_fb", registered, kt.Void())
	ctx, _ = kt.Context(fixture(), i.Table(t), nil)
	if _, err := Run(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("no fb_info: %v", err)
	}
}

func TestNamesAndCodes(t *testing.T) {
	for v, want := range map[uint64]string{0: "mono01", 2: "truecolor", 6: "fourcc", 9: "visual=9"} {
		if got := VisualName(v); got != want {
			t.Errorf("visual %d: %q", v, got)
		}
	}
	for v, want := range map[uint64]string{0: "running", 1: "suspended", 7: "state=7"} {
		if got := StateName(v); got != want {
			t.Errorf("state %d: %q", v, got)
		}
	}
	if got := FourCCText('N' | 'V'<<8 | '1'<<16 | '2'<<24 | 1<<31); got != "NV12 be" {
		t.Errorf("big-endian code: %q", got)
	}
	if got := FourCCText(0x00010203); got != "0x00010203" {
		t.Errorf("unprintable code: %q", got)
	}
}

func TestPictureRefusesWhatDoesNotFit(t *testing.T) {
	l := Layout{XRes: 4, YRes: 2, BitsPerPixel: 32, LineLength: 16, Channels: [4][2]uint64{{16, 8}, {8, 8}, {0, 8}}}
	if _, err := Picture(make([]byte, 31), l, 1<<20); !errors.Is(err, ErrOutside) {
		t.Errorf("short memory: %v", err)
	}
	if _, err := Picture(make([]byte, 32), l, 16); !errors.Is(err, ErrTooLarge) {
		t.Errorf("image bound: %v", err)
	}
	l.Channels[0] = [2]uint64{30, 8}
	if _, err := Picture(make([]byte, 32), l, 1<<20); !errors.Is(err, ErrNotTrueColor) {
		t.Errorf("field past the pixel: %v", err)
	}
	l = Layout{XRes: 2, YRes: 1, BitsPerPixel: 16, LineLength: 4, Channels: [4][2]uint64{{11, 5}, {5, 6}, {0, 5}}}
	img, err := Picture([]byte{0x00, 0xf8, 0x1f, 0x00}, l, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if p := img.Pix; p[0] != 255 || p[1] != 0 || p[2] != 0 || p[4] != 0 || p[6] != 255 {
		t.Errorf("565 pixels %v", p)
	}
}

func FuzzPicture(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8}, uint8(2), uint8(1), uint8(32), uint8(8), uint8(16), uint8(8), uint8(4))
	f.Fuzz(func(t *testing.T, raw []byte, x, y, bpp, line, off, length, start uint8) {
		l := Layout{XRes: uint64(x), YRes: uint64(y), BitsPerPixel: uint64(bpp), LineLength: uint64(line),
			Start: uint64(start), Channels: [4][2]uint64{{uint64(off), uint64(length)}, {0, 1}, {0, 1}, {uint64(off), 0}}}
		img, err := Picture(raw, l, 1<<16)
		if err != nil {
			return
		}
		if b := img.Bounds(); uint64(b.Dx()) != l.XRes || uint64(b.Dy()) != l.YRes {
			t.Fatalf("bounds %v for %dx%d", b, x, y)
		}
	})
}
