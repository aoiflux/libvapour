package framebufferlist

import (
	"bytes"
	"errors"
	"image"
	"image/png"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
)

var (
	ErrNotTrueColor = errors.New("framebufferlist: not a packed true-colour layout")
	ErrOutside      = errors.New("framebufferlist: the visible area does not fit the screen memory")
	ErrTooLarge     = errors.New("framebufferlist: the picture is over Limits.MaxImageBytes")
)

// Layout is what a packed true-colour picture needs: the visible size, the
// pixel width, the byte step between lines, where the visible area starts,
// and the red, green, blue and transparency fields of a pixel.
type Layout struct {
	XRes, YRes   uint64
	BitsPerPixel uint64
	LineLength   uint64
	Start        uint64
	Channels     [4][2]uint64
}

func (r record) layout() (Layout, error) {
	if r.fbType != typePackedPixels || r.visual != visualTrueColor || r.grayscale != 0 {
		return Layout{}, ErrNotTrueColor
	}
	l := Layout{XRes: r.row.XRes, YRes: r.row.YRes, BitsPerPixel: r.row.BitsPerPixel, LineLength: r.row.LineLength}
	for i, c := range r.channels {
		if c.msbRight != 0 {
			return Layout{}, ErrNotTrueColor
		}
		l.Channels[i] = [2]uint64{c.offset, c.length}
	}
	if l.BitsPerPixel%8 != 0 {
		return Layout{}, ErrNotTrueColor
	}
	l.Start = r.yOffset*l.LineLength + r.xOffset*(l.BitsPerPixel/8)
	return l, nil
}

// Picture turns packed true-colour pixels into an image. Each field is a
// run of bits counted from the least significant bit of the little-endian
// pixel value, scaled to 8 bits; a transparency field of length 0 is opaque.
func Picture(raw []byte, l Layout, maxBytes uint64) (*image.NRGBA, error) {
	bpp := l.BitsPerPixel / 8
	if bpp == 0 || bpp > 4 || l.XRes == 0 || l.YRes == 0 {
		return nil, ErrNotTrueColor
	}
	for i, c := range l.Channels {
		if c[0]+c[1] > l.BitsPerPixel || (i < 3 && c[1] == 0) {
			return nil, ErrNotTrueColor
		}
	}
	if l.XRes > maxBytes/4/l.YRes || l.XRes > 1<<16 || l.YRes > 1<<16 {
		return nil, ErrTooLarge
	}
	row := l.XRes * bpp
	if l.LineLength < row {
		return nil, ErrOutside
	}
	size := uint64(len(raw))
	if l.Start > size || size-l.Start < row || (l.YRes-1) > (size-l.Start-row)/l.LineLength {
		return nil, ErrOutside
	}
	img := image.NewNRGBA(image.Rect(0, 0, int(l.XRes), int(l.YRes)))
	for y := range l.YRes {
		line := l.Start + y*l.LineLength
		for x := range l.XRes {
			at := line + x*bpp
			var v uint64
			for b := range bpp {
				v |= uint64(raw[at+b]) << (8 * b)
			}
			o := img.PixOffset(int(x), int(y))
			for i := range 3 {
				img.Pix[o+i] = scale(v, l.Channels[i])
			}
			img.Pix[o+3] = 0xff
			if l.Channels[3][1] != 0 {
				img.Pix[o+3] = scale(v, l.Channels[3])
			}
		}
	}
	return img, nil
}

func scale(v uint64, c [2]uint64) uint8 {
	top := uint64(1)<<c[1] - 1
	field := (v >> c[0]) & top
	return uint8((field*255 + top/2) / top)
}

type saver struct {
	k   *linuxkern.Kernel
	ctx tools.Context
	dir string
}

func (s *saver) diag(format string, args ...any) {
	s.ctx.AddDiagnostic("%s: "+format, append([]any{Name}, args...)...)
}

func (s *saver) save(rec record) string {
	fb := rec.row
	switch {
	case fb.ScreenAddress == 0:
		s.diag("fb_info at 0x%x: no screen memory; not saved", fb.Address)
		return ""
	case fb.ScreenSize == 0:
		s.diag("fb_info at 0x%x: screen memory of 0 bytes; not saved", fb.Address)
		return ""
	case fb.ScreenSize > s.ctx.DumpLimit():
		s.diag("fb_info at 0x%x: %d bytes of screen memory is over the dump limit of %d; not saved", fb.Address,
			fb.ScreenSize, s.ctx.DumpLimit())
		return ""
	}
	raw, gaps := extract.ReadPadded(s.k.Mem, fb.ScreenAddress, fb.ScreenSize)
	var missing uint64
	for _, g := range gaps {
		missing += g.Length
	}
	if missing == fb.ScreenSize {
		s.diag("fb_info at 0x%x: screen memory at 0x%x does not read; not saved", fb.Address, fb.ScreenAddress)
		return ""
	}
	if missing > 0 {
		s.diag("fb_info at 0x%x: %d of %d bytes of screen memory do not read and are saved as zeros", fb.Address,
			missing, fb.ScreenSize)
	}
	data, ext := raw, extract.ExtBytes
	if l, err := rec.layout(); err == nil {
		img, err := Picture(raw, l, uint64(s.ctx.Bounds().MaxImageBytes))
		if err == nil {
			var buf bytes.Buffer
			if err = png.Encode(&buf, img); err == nil {
				data, ext = buf.Bytes(), extract.ExtPNG
			}
		}
		if err != nil {
			s.diag("fb_info at 0x%x: saved as raw bytes: %v", fb.Address, err)
		}
	}
	name := extract.Name{Kind: extract.KindFramebuffer, Scope: extract.Kernel, Width: uint8(s.k.PtrSize),
		Addresses: []uint64{fb.Address}, Labels: []string{fb.ID}, Ext: ext}.String()
	f, err := extract.CreateNew(s.dir, name)
	if err != nil {
		s.diag("fb_info at 0x%x: %v", fb.Address, err)
		return ""
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		s.diag("fb_info at 0x%x: write %s: %v", fb.Address, name, err)
		_ = extract.RemoveArtifact(s.dir, name)
		return ""
	}
	return name
}
