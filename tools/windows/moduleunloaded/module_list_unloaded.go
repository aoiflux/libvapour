package moduleunloaded

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/kernelinfo"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.module.list_unloaded"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the kernel modules the system unloaded, from the MmUnloadedDrivers record",
		},
		RunAny,
	)
}

var (
	ErrNoSymbols         = errors.New("moduleunloaded: symbol table has no MmUnloadedDrivers or MmLastUnloadedDriver")
	ErrUnsupportedLayout = errors.New("moduleunloaded: no measured record layout for a 4-byte kernel")
	ErrRecordUnread      = errors.New("moduleunloaded: unloaded driver record does not read")
	ErrIndexTooLarge     = errors.New("moduleunloaded: MmLastUnloadedDriver is above the record capacity")
)

// The record has no type in the kernel tables. Its 64-bit layout is
// measured (S64 U1-U3): a UNICODE_STRING name, the start and end
// addresses, and a 100-ns time, 0x28 bytes, in an array of 50.
const (
	recordBytes  = 0x28
	nameOffset   = 0x00
	startOffset  = 0x10
	endOffset    = 0x18
	timeOffset   = 0x20
	capacity     = 50
	nameMaxBytes = util.MaxUnicodeStringBytes
)

type Clock string

const (
	ClockSystem    Clock = "system"
	ClockInterrupt Clock = "interrupt"
	ClockUnknown   Clock = "unknown"
)

type Module struct {
	Name                     string
	NameUnreadable           bool
	StartAddress, EndAddress uint64
	CurrentTime              uint64
	Clock                    Clock
	Time                     time.Time
	SinceBoot                time.Duration
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Module, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	t := ctx.Symbols
	arraySym, err1 := t.LookupSymbol("MmUnloadedDrivers")
	lastSym, err2 := t.LookupSymbol("MmLastUnloadedDriver")
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoSymbols)
	}
	if t.PointerSize() != 8 {
		return nil, fmt.Errorf("%s: %w", Name, ErrUnsupportedLayout)
	}
	array, err := t.ReadPointer(ctx.Memory, arraySym.Address)
	if err != nil {
		return nil, fmt.Errorf("%s: MmUnloadedDrivers at 0x%x: %w: %w", Name, arraySym.Address, ErrRecordUnread, err)
	}
	last, err := t.ReadUint32(ctx.Memory, lastSym.Address)
	if err != nil {
		return nil, fmt.Errorf("%s: MmLastUnloadedDriver at 0x%x: %w: %w", Name, lastSym.Address, ErrRecordUnread, err)
	}
	if array == 0 {
		ctx.AddDiagnostic("%s: MmUnloadedDrivers at 0x%x is null: no driver has been unloaded", Name, arraySym.Address)
		return nil, nil
	}
	if last > capacity {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: MmLastUnloadedDriver at 0x%x holds %d: %w", Name, lastSym.Address, last, ErrIndexTooLarge)
		}
		ctx.AddDiagnostic("%s: MmLastUnloadedDriver at 0x%x holds %d, above the %d records: %d read", Name,
			lastSym.Address, last, capacity, capacity)
		last = capacity
	}
	clock := readClock(ctx)
	order := slotOrder(ctx.Memory, array, uint64(last))
	us := util.ResolveUnicodeStringLayout(t)
	out := make([]Module, 0, len(order))
	for _, slot := range order {
		at := array + slot*recordBytes
		raw, err := ctx.Memory.ReadAt(at, recordBytes)
		if err != nil || len(raw) != recordBytes {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: unloaded driver record at 0x%x: %w", Name, at, ErrRecordUnread)
			}
			ctx.AddDiagnostic("%s: unloaded driver record at 0x%x: does not read: %v", Name, at, err)
			continue
		}
		m := Module{
			StartAddress: binary.LittleEndian.Uint64(raw[startOffset:]),
			EndAddress:   binary.LittleEndian.Uint64(raw[endOffset:]),
			CurrentTime:  binary.LittleEndian.Uint64(raw[timeOffset:]),
		}
		name, err := util.ReadUnicodeString(ctx.Memory, at+nameOffset, us, nameMaxBytes)
		if err != nil {
			m.NameUnreadable = true
			ctx.AddDiagnostic("%s: unloaded driver record at 0x%x: name does not read: %v", Name, at, err)
		} else {
			m.Name = name.Text()
		}
		if m.EndAddress < m.StartAddress {
			ctx.AddDiagnostic("%s: unloaded driver record at 0x%x: end 0x%x lies below start 0x%x", Name, at,
				m.EndAddress, m.StartAddress)
		}
		clock.stamp(&m)
		out = append(out, m)
	}
	return out, nil
}

// MmLastUnloadedDriver is the next slot to fill. Past it the slots are empty
// until the array has wrapped; a used next slot means it has, and the oldest
// record is the next slot (S64 4.8 step 5).
func slotOrder(m memory.MemoryReader, array, last uint64) []uint64 {
	wrapped := false
	if last < capacity {
		if b, err := m.ReadAt(array+last*recordBytes+nameOffset, 2); err == nil && len(b) == 2 {
			wrapped = binary.LittleEndian.Uint16(b) != 0
		}
	}
	var out []uint64
	if wrapped {
		for i := last; i < capacity; i++ {
			out = append(out, i)
		}
	}
	for i := uint64(0); i < last; i++ {
		out = append(out, i)
	}
	return out
}

type clock struct {
	system, interrupt uint64
	known             bool
}

func readClock(ctx tools.Context) clock {
	now, err1 := kernelinfo.SharedTime(ctx, "SystemTime")
	up, err2 := kernelinfo.SharedTime(ctx, "InterruptTime")
	if err1 != nil || err2 != nil || up > now {
		ctx.AddDiagnostic("%s: shared data times do not read: unload times are not placed on a clock", Name)
		return clock{}
	}
	return clock{system: now, interrupt: up, known: true}
}

// The record's time is interrupt time on 26100 and system time on 19045 and
// 14393 (S64 U3). The two ranges cannot meet: interrupt time counts from
// boot, system time from 1601, so a value is placed by the range it lies in.
func (c clock) stamp(m *Module) {
	m.Clock = ClockUnknown
	if !c.known {
		return
	}
	boot := c.system - c.interrupt
	switch v := m.CurrentTime; {
	case v <= c.interrupt:
		m.Clock = ClockInterrupt
		m.SinceBoot = time.Duration(v) * 100
		m.Time, _ = kernelinfo.FiletimeUTC(boot + v)
	case v <= c.system:
		m.Clock = ClockSystem
		m.Time, _ = kernelinfo.FiletimeUTC(v)
		if v >= boot {
			m.SinceBoot = time.Duration(v-boot) * 100
		}
	}
}
