package cpulist

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const Name = "windows.cpu.list"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List each processor's control region and control block from KiProcessorBlock",
		},
		RunAny,
	)
}

var (
	ErrNoProcessorBlock = errors.New("cpulist: symbol table has no KiProcessorBlock or KeNumberProcessors")
	ErrNoPcrType        = errors.New("cpulist: symbol table has no _KPCR.Prcb")
	ErrCountUnread      = errors.New("cpulist: KeNumberProcessors does not read")
	ErrNoProcessors     = errors.New("cpulist: KeNumberProcessors is 0")
	ErrCountTooLarge    = errors.New("cpulist: KeNumberProcessors is above the processor capacity")
)

// The widest processor set the measured kernel tables describe: 32 words of
// 64 bits in _KAFFINITY_EX on 26100 (S64 C2).
const MaxProcessors = 2048

type Entry struct {
	Index      int
	Offset     uint64
	PRCB       uint64
	Number     uint32
	PointsBack bool
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]Entry, error) {
	return List(ctx)
}

func List(ctx tools.Context) ([]Entry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	t := ctx.Symbols
	block, err1 := t.LookupSymbol("KiProcessorBlock")
	number, err2 := t.LookupSymbol("KeNumberProcessors")
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoProcessorBlock)
	}
	prcbField, err := t.Field("_KPCR", "Prcb")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPcrType)
	}
	// WDK wdm.h declares KeNumberProcessors as CCHAR.
	raw, err := ctx.Memory.ReadAt(number.Address, 1)
	if err != nil || len(raw) != 1 {
		return nil, fmt.Errorf("%s: KeNumberProcessors at 0x%x: %w", Name, number.Address, ErrCountUnread)
	}
	count := int(raw[0])
	if count == 0 {
		return nil, fmt.Errorf("%s: KeNumberProcessors at 0x%x: %w", Name, number.Address, ErrNoProcessors)
	}
	if capacity := Capacity(t); count > capacity {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: KeNumberProcessors at 0x%x holds %d, capacity %d: %w", Name, number.Address, count,
				capacity, ErrCountTooLarge)
		}
		ctx.AddDiagnostic("%s: KeNumberProcessors at 0x%x holds %d, above the capacity of %d: %d processors read",
			Name, number.Address, count, capacity, capacity)
		count = capacity
	}
	self, selfErr := t.Field("_KPCR", "Self")
	current, currentErr := t.Field("_KPCR", "CurrentPrcb")
	numberField, numberErr := t.Field("_KPRCB", "Number")
	width := uint64(t.PointerSize())
	var out []Entry
	for i := 0; i < count; i++ {
		slot := block.Address + uint64(i)*width
		prcb, err := t.ReadPointer(ctx.Memory, slot)
		if err != nil {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: KiProcessorBlock slot %d at 0x%x: %w", Name, i, slot, err)
			}
			ctx.AddDiagnostic("%s: KiProcessorBlock slot %d at 0x%x: does not read: %v", Name, i, slot, err)
			continue
		}
		if prcb == 0 || prcb < prcbField.Offset {
			ctx.AddDiagnostic("%s: KiProcessorBlock slot %d at 0x%x: holds 0x%x, no processor control block", Name, i, slot, prcb)
			continue
		}
		e := Entry{Index: i, Offset: prcb - prcbField.Offset, PRCB: prcb}
		if numberErr == nil {
			if n, err := t.ReadUint32(ctx.Memory, prcb+numberField.Offset); err == nil {
				e.Number = n
			}
		}
		if selfErr == nil && currentErr == nil {
			s, err1 := t.ReadPointer(ctx.Memory, e.Offset+self.Offset)
			c, err2 := t.ReadPointer(ctx.Memory, e.Offset+current.Offset)
			e.PointsBack = err1 == nil && err2 == nil && s == e.Offset && c == prcb
		}
		if !e.PointsBack {
			ctx.AddDiagnostic("%s: _KPCR at 0x%x: Self and CurrentPrcb do not point back to it and to 0x%x", Name, e.Offset, prcb)
		}
		out = append(out, e)
	}
	return out, nil
}

func Capacity(t symbols.SymbolTable) int {
	st, err := t.Struct("_KAFFINITY_EX")
	if err != nil {
		return MaxProcessors
	}
	words := uint64(0)
	for _, f := range st.Fields {
		if (f.Name == "StaticBitmap" || f.Name == "Bitmap") && f.Type.IsArray && f.Type.ArrayLength > words {
			words = f.Type.ArrayLength
		}
	}
	if words == 0 || words*64 > MaxProcessors {
		return MaxProcessors
	}
	return int(words * 64)
}
