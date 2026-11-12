package framebufferlist

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
)

const Name = "linux.framebuffer.list"

const OptionDump = "linux.framebuffer.list.dump"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the framebuffers registered with the Linux fbdev core, and save their screen memory",
		},
		RunAny,
	)
}

type Framebuffer struct {
	Slot          int
	Address       uint64
	Node          int64
	Device        string
	DeviceKnown   bool
	ID            string
	ScreenAddress uint64
	ScreenSize    uint64
	PhysicalStart uint64
	XRes          uint64
	YRes          uint64
	VirtualXRes   uint64
	VirtualYRes   uint64
	BitsPerPixel  uint64
	LineLength    uint64
	Visual        string
	FourCC        string
	State         string
	File          string
}

var (
	ErrNoRegistry  = errors.New("framebufferlist: registered_fb not in the symbol table")
	ErrUnsupported = errors.New("framebufferlist: struct fb_info is not in the symbol table")
	ErrNoOutputDir = errors.New("framebufferlist: " + OptionDump + " needs the " + tools.OptionOutputDir + " option")
)

// FB_MAX in include/uapi/linux/fb.h; the symbol table may give registered_fb
// no type, so its length cannot be taken from there.
const slots = 32

var requiredMembers = []string{"node", "var.xres", "var.yres", "var.xres_virtual", "var.yres_virtual",
	"var.bits_per_pixel", "var.grayscale", "fix.id", "fix.smem_start", "fix.smem_len", "fix.type", "fix.visual",
	"fix.line_length", "screen_base", "screen_size", "state", "var.xoffset", "var.yoffset"}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Framebuffer, error) {
	dump, err := ctx.BoolOption(OptionDump)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	dir, haveDir := ctx.OutputDir()
	if dump && !haveDir {
		return nil, ErrNoOutputDir
	}
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	table, err := k.Symbol("registered_fb")
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", Name, ErrNoRegistry, err)
	}
	for _, m := range requiredMembers {
		if _, err := k.Member("fb_info", m); err != nil {
			return nil, fmt.Errorf("%s: fb_info.%s: %w: %w", Name, m, ErrUnsupported, err)
		}
	}
	l := lister{k: k, ctx: ctx, device: k.HasMember("fb_info", "dev") && k.HasMember("device", "kobj.name")}
	if dump {
		l.saver = &saver{k: k, ctx: ctx, dir: dir}
	}
	rows := l.list(table)
	l.checkCount(len(rows))
	if l.lossy && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: the framebuffer registry was read in part", Name)
	}
	return rows, nil
}

type lister struct {
	k      *linuxkern.Kernel
	ctx    tools.Context
	device bool
	saver  *saver
	lossy  bool
}

func (l *lister) diag(format string, args ...any) {
	l.ctx.AddDiagnostic("%s: "+format, append([]any{Name}, args...)...)
}

func (l *lister) list(table uint64) []Framebuffer {
	var rows []Framebuffer
	for i := range slots {
		slot := table + uint64(i)*l.k.PtrSize
		p, err := l.k.ReadPointer(slot)
		if err != nil {
			l.lossy = true
			l.diag("registered_fb[%d] at 0x%x: %v", i, l.k.Canonical(slot), err)
			continue
		}
		if p == 0 {
			continue
		}
		rec, err := l.read(i, p)
		if err != nil {
			l.lossy = true
			l.diag("fb_info at 0x%x (registered_fb[%d]): %v", l.k.Canonical(p), i, err)
			continue
		}
		if rec.row.Node != int64(i) {
			l.diag("fb_info at 0x%x: node %d, but it is in registered_fb[%d]", rec.row.Address, rec.row.Node, i)
		}
		if l.saver != nil {
			rec.row.File = l.saver.save(rec)
		}
		rows = append(rows, rec.row)
	}
	return rows
}

func (l *lister) checkCount(found int) {
	at, err := l.k.Symbol("num_registered_fb")
	if err != nil {
		return
	}
	n, err := l.k.ReadUint(at, 4)
	if err != nil {
		l.diag("num_registered_fb at 0x%x: %v", l.k.Canonical(at), err)
		return
	}
	if int64(int32(n)) != int64(found) {
		l.diag("num_registered_fb is %d, but %d slots of registered_fb hold a framebuffer", int32(n), found)
	}
}
