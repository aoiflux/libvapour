package kernelinfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.kernel.read_info"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Kernel identity and state: base, page tables, version block, build strings, processor count and the shared data times",
		},
		RunAny,
	)
}

var (
	ErrTimeTorn     = errors.New("kernelinfo: KSYSTEM_TIME High1Time and High2Time differ")
	ErrTimeUnread   = errors.New("kernelinfo: KSYSTEM_TIME does not read")
	ErrNoSharedType = errors.New("kernelinfo: symbol table has no _KUSER_SHARED_DATA member")
)

const SystemTimeLayout = "2006-01-02 15:04:05-07:00"

// Learn, FILETIME: 100-nanosecond intervals since January 1, 1601 (UTC).
const filetimeToUnix = 116444736000000000

// A system-root path is at most the 260 WCHARs of NtSystemRoot (ntddk.h).
const systemRootBytes = 260 * 2

type Row struct {
	Variable string
	Value    string
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type rows struct {
	ctx tools.Context
	out []Row
}

func (r *rows) add(name, format string, args ...any) {
	r.out = append(r.out, Row{Variable: name, Value: fmt.Sprintf(format, args...)})
}

func (r *rows) unread(object string, at uint64, err error) {
	r.ctx.AddDiagnostic("%s: %s at 0x%x: does not read: %v", Name, object, at, err)
}

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	r := &rows{ctx: ctx}
	t := ctx.Symbols
	if base, ok := ctx.KernelBase(); ok {
		r.add("KernelBase", "0x%x", base)
	}
	if dtb, ok := ctx.KernelDTB(); ok {
		r.add("DirectoryTableBase", "0x%x", dtb)
	}
	if mode := ctx.PagingMode(); mode != "" {
		r.add("PagingMode", "%s", mode)
	}
	r.add("SymbolTable", "%s", t.Name())
	r.add("PointerSize", "%d", t.PointerSize())
	r.versionBlock()
	r.buildStrings()
	r.processors()
	r.shared()
	r.imageHeader()
	return r.out, nil
}

func (r *rows) imageHeader() {
	base, ok := r.ctx.KernelBase()
	if !ok {
		return
	}
	h, err := extract.ReadHeaders(r.ctx.Memory, base)
	if err != nil {
		r.ctx.AddDiagnostic("%s: kernel image at 0x%x: pe header does not read: %v", Name, base, err)
		return
	}
	r.add("Machine", "0x%x", h.File.Machine)
	r.add("TimeDateStamp", "%s", time.Unix(int64(h.File.TimeDateStamp), 0).UTC().Format(SystemTimeLayout))
	r.add("MajorOperatingSystemVersion", "%d", h.Optional.MajorOperatingSystemVersion)
	r.add("MinorOperatingSystemVersion", "%d", h.Optional.MinorOperatingSystemVersion)
}

// _DBGKD_GET_VERSION64 at KdVersionBlock names the kernel base and the loaded
// module list head; both equal the session's on every capture (S64 I3).
func (r *rows) versionBlock() {
	t := r.ctx.Symbols
	sym, err := t.LookupSymbol("KdVersionBlock")
	if err != nil {
		return
	}
	r.add("KdVersionBlock", "0x%x", sym.Address)
	read := func(member string, width uint64) (uint64, bool) {
		f, err := t.Field("_DBGKD_GET_VERSION64", member)
		if err != nil {
			return 0, false
		}
		v, err := readUint(r.ctx.Memory, sym.Address+f.Offset, width)
		if err != nil {
			r.unread("_DBGKD_GET_VERSION64."+member, sym.Address+f.Offset, err)
			return 0, false
		}
		return v, true
	}
	if v, ok := read("MajorVersion", 2); ok {
		r.add("MajorVersion", "%d", v)
	}
	if v, ok := read("MinorVersion", 2); ok {
		r.add("MinorVersion", "%d", v)
	}
	if v, ok := read("MachineType", 2); ok {
		r.add("MachineType", "0x%x", v)
	}
	if v, ok := read("KernBase", 8); ok {
		r.add("KernBase", "0x%x", v)
		if base, known := r.ctx.KernelBase(); known && base != v {
			r.ctx.AddDiagnostic("%s: _DBGKD_GET_VERSION64 at 0x%x: KernBase 0x%x is not the session's kernel base 0x%x",
				Name, sym.Address, v, base)
		}
	}
	if v, ok := read("PsLoadedModuleList", 8); ok {
		r.add("PsLoadedModuleList", "0x%x", v)
	}
}

func (r *rows) buildStrings() {
	for _, name := range []string{"NtBuildLab", "NtBuildLabEx"} {
		sym, err := r.ctx.Symbols.LookupSymbol(name)
		if err != nil {
			continue
		}
		s, err := readCString(r.ctx.Memory, sym.Address, 256)
		if err != nil {
			r.unread(name, sym.Address, err)
			continue
		}
		r.add(name, "%s", s)
	}
}

func readCString(m memory.MemoryReader, at, max uint64) (string, error) {
	var out []byte
	for len(out) < int(max) {
		n := uint64(0x1000) - at&0xFFF
		if rest := max - uint64(len(out)); n > rest {
			n = rest
		}
		b, err := m.ReadAt(at, n)
		if err != nil {
			if len(out) > 0 {
				break
			}
			return "", err
		}
		for _, c := range b {
			if c == 0 {
				return util.DecodeUTF8Replace(out), nil
			}
			out = append(out, c)
		}
		at += n
	}
	return util.DecodeUTF8Replace(out), nil
}

func (r *rows) processors() {
	sym, err := r.ctx.Symbols.LookupSymbol("KeNumberProcessors")
	if err != nil {
		return
	}
	// WDK wdm.h declares KeNumberProcessors as CCHAR.
	v, err := readUint(r.ctx.Memory, sym.Address, 1)
	if err != nil {
		r.unread("KeNumberProcessors", sym.Address, err)
		return
	}
	r.add("KeNumberProcessors", "%d", v)
}

func (r *rows) shared() {
	t := r.ctx.Symbols
	base := winkernel.SharedDataAddress(t)
	r.add("KUSER_SHARED_DATA", "0x%x", base)
	for _, m := range []string{"NtMajorVersion", "NtMinorVersion", "NtBuildNumber", "ActiveProcessorCount", "NumberOfPhysicalPages"} {
		f, err := t.Field("_KUSER_SHARED_DATA", m)
		if err != nil {
			continue
		}
		v, err := readUint(r.ctx.Memory, base+f.Offset, 4)
		if err != nil {
			r.unread("_KUSER_SHARED_DATA."+m, base+f.Offset, err)
			continue
		}
		r.add(m, "%d", v)
	}
	if f, err := t.Field("_KUSER_SHARED_DATA", "NtProductType"); err == nil {
		if v, err := readUint(r.ctx.Memory, base+f.Offset, 4); err != nil {
			r.unread("_KUSER_SHARED_DATA.NtProductType", base+f.Offset, err)
		} else {
			r.add("NtProductType", "%s", productType(t, int64(int32(v))))
		}
	}
	if f, err := t.Field("_KUSER_SHARED_DATA", "NtSystemRoot"); err == nil {
		if b, err := r.ctx.Memory.ReadAt(base+f.Offset, systemRootBytes); err != nil {
			r.unread("_KUSER_SHARED_DATA.NtSystemRoot", base+f.Offset, err)
		} else {
			r.add("NtSystemRoot", "%s", util.DecodeUTF16LEZ(b))
		}
	}
	now, err := SharedTime(r.ctx, "SystemTime")
	if err != nil {
		r.ctx.AddDiagnostic("%s: %v", Name, err)
	} else if at, ok := FiletimeUTC(now); ok {
		r.add("SystemTime", "%s", at.Format(SystemTimeLayout))
	}
	if up, err := SharedTime(r.ctx, "InterruptTime"); err != nil {
		r.ctx.AddDiagnostic("%s: %v", Name, err)
	} else {
		r.add("InterruptTime", "%s", time.Duration(up)*100)
	}
}

func productType(t symbols.SymbolTable, v int64) string {
	if det, ok := t.(symbols.DeterministicLookup); ok {
		if ty, err := det.LookupType("_NT_PRODUCT_TYPE"); err == nil {
			for _, e := range ty.Enum {
				if e.Value == v {
					return e.Name
				}
			}
		}
	}
	return fmt.Sprintf("%d", v)
}

// The WDK's KeQueryTickCount reads High1Time, LowPart, then High2Time and
// retries until the two high parts agree: unequal parts are a torn value.
func SharedTime(ctx tools.Context, member string) (uint64, error) {
	f, err := ctx.Symbols.Field("_KUSER_SHARED_DATA", member)
	if err != nil {
		return 0, fmt.Errorf("_KUSER_SHARED_DATA.%s: %w", member, ErrNoSharedType)
	}
	at := winkernel.SharedDataAddress(ctx.Symbols) + f.Offset
	b, err := ctx.Memory.ReadAt(at, 12)
	if err != nil || len(b) != 12 {
		return 0, fmt.Errorf("_KUSER_SHARED_DATA.%s at 0x%x: %w", member, at, ErrTimeUnread)
	}
	low := binary.LittleEndian.Uint32(b)
	high1 := binary.LittleEndian.Uint32(b[4:])
	high2 := binary.LittleEndian.Uint32(b[8:])
	if high1 != high2 {
		return 0, fmt.Errorf("_KUSER_SHARED_DATA.%s at 0x%x: %w", member, at, ErrTimeTorn)
	}
	return uint64(high1)<<32 | uint64(low), nil
}

func FiletimeUTC(v uint64) (time.Time, bool) {
	if v < filetimeToUnix || v-filetimeToUnix > uint64(1<<63-1)/100 {
		return time.Time{}, false
	}
	return time.Unix(0, int64(v-filetimeToUnix)*100).UTC(), true
}

func readUint(m memory.MemoryReader, at, width uint64) (uint64, error) {
	b, err := m.ReadAt(at, width)
	if err != nil {
		return 0, err
	}
	if uint64(len(b)) != width {
		return 0, fmt.Errorf("read 0x%x bytes of 0x%x", len(b), width)
	}
	var v uint64
	for i := int(width) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v, nil
}
