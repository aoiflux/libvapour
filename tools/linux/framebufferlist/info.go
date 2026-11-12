package framebufferlist

import (
	"fmt"
)

type channel struct{ offset, length, msbRight uint64 }

type record struct {
	row              Framebuffer
	fbType           uint64
	visual           uint64
	grayscale        uint64
	xOffset, yOffset uint64
	channels         [4]channel
}

const (
	typePackedPixels = 0
	visualTrueColor  = 2
)

var visualNames = []string{"mono01", "mono10", "truecolor", "pseudocolor", "directcolor", "static_pseudocolor", "fourcc"}

func VisualName(v uint64) string {
	if v < uint64(len(visualNames)) {
		return visualNames[v]
	}
	return fmt.Sprintf("visual=%d", v)
}

func StateName(v uint64) string {
	switch v {
	case 0:
		return "running"
	case 1:
		return "suspended"
	}
	return fmt.Sprintf("state=%d", v)
}

// FourCCText reads a grayscale value above 1 as the four characters
// v4l2_fourcc packs from the low byte up, with bit 31 marking the
// big-endian variant.
func FourCCText(v uint64) string {
	be := v&(1<<31) != 0
	code := uint32(v) &^ (1 << 31)
	b := []byte{byte(code), byte(code >> 8), byte(code >> 16), byte(code >> 24)}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return fmt.Sprintf("0x%08x", uint32(v))
		}
	}
	if be {
		return string(b) + " be"
	}
	return string(b)
}

func (l *lister) read(slot int, p uint64) (record, error) {
	k := l.k
	rec := record{row: Framebuffer{Slot: slot, Address: k.Canonical(p)}}
	r := &rec.row
	var node int64
	var err error
	if node, err = k.Int(p, "fb_info", "node"); err != nil {
		return rec, fmt.Errorf("fb_info.node: %w", err)
	}
	r.Node = node
	var state, screenSize, smemLen uint64
	for _, m := range []struct {
		path string
		to   *uint64
	}{
		{"var.xres", &r.XRes}, {"var.yres", &r.YRes}, {"var.xres_virtual", &r.VirtualXRes},
		{"var.yres_virtual", &r.VirtualYRes}, {"var.bits_per_pixel", &r.BitsPerPixel},
		{"var.grayscale", &rec.grayscale}, {"fix.smem_start", &r.PhysicalStart}, {"fix.smem_len", &smemLen},
		{"fix.type", &rec.fbType}, {"fix.visual", &rec.visual}, {"fix.line_length", &r.LineLength},
		{"screen_size", &screenSize}, {"state", &state}, {"var.xoffset", &rec.xOffset}, {"var.yoffset", &rec.yOffset},
	} {
		if *m.to, err = k.Uint(p, "fb_info", m.path); err != nil {
			return rec, fmt.Errorf("fb_info.%s: %w", m.path, err)
		}
	}
	base, err := k.Ptr(p, "fb_info", "screen_base")
	if err != nil {
		return rec, fmt.Errorf("fb_info.screen_base: %w", err)
	}
	if base != 0 {
		r.ScreenAddress = k.Canonical(base)
	}
	if r.ID, err = k.MemberString(p, "fb_info", "fix.id"); err != nil {
		return rec, fmt.Errorf("fb_info.fix.id: %w", err)
	}
	// fb_read takes screen_size and falls back to smem_len when it is 0.
	r.ScreenSize = screenSize
	if r.ScreenSize == 0 {
		r.ScreenSize = smemLen
	}
	r.Visual = VisualName(rec.visual)
	if rec.grayscale > 1 {
		r.FourCC = FourCCText(rec.grayscale)
	}
	r.State = StateName(state)
	for i, c := range []string{"red", "green", "blue", "transp"} {
		ch := &rec.channels[i]
		for _, m := range []struct {
			name string
			to   *uint64
		}{{"offset", &ch.offset}, {"length", &ch.length}, {"msb_right", &ch.msbRight}} {
			if *m.to, err = k.Uint(p, "fb_info", "var."+c+"."+m.name); err != nil {
				return rec, fmt.Errorf("fb_info.var.%s.%s: %w", c, m.name, err)
			}
		}
	}
	if l.device {
		r.Device, r.DeviceKnown = l.deviceName(p)
	}
	return rec, nil
}

// fb_device_create names the device fb<node>, but the name is read from
// the device itself so a renamed or foreign device shows as it is.
func (l *lister) deviceName(p uint64) (string, bool) {
	dev, err := l.k.Ptr(p, "fb_info", "dev")
	if err != nil {
		l.diag("fb_info at 0x%x: fb_info.dev: %v", l.k.Canonical(p), err)
		return "", false
	}
	if dev == 0 {
		return "", true
	}
	name, err := l.k.Ptr(dev, "device", "kobj.name")
	if err == nil && name != 0 {
		var s string
		if s, err = l.k.StringAt(name, uint64(l.ctx.Bounds().MaxNameBytes)); err == nil {
			return s, true
		}
	}
	if err != nil {
		l.diag("fb_info at 0x%x: device at 0x%x: name: %v", l.k.Canonical(p), l.k.Canonical(dev), err)
	}
	return "", false
}
