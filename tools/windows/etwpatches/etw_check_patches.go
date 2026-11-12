package etwpatches

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/windows/pesymbols"
)

const Name = "windows.etw.check_patches"

const Module = "ntdll.dll"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Report ntdll ETW functions whose first instruction returns at once or jumps out of ntdll",
		},
		RunAny,
	)
}

// The user-mode ETW entry points ntdll exports: the Etw functions and the
// trace system-service stubs (S64 E1).
func IsETWFunction(name string) bool {
	return strings.HasPrefix(name, "Etw") || strings.HasPrefix(name, "NtTrace") || strings.HasPrefix(name, "ZwTrace")
}

// First bytes of the returns and jumps of the Intel SDM, Vol. 2: RET (C3),
// RET imm16 (C2 iw), JMP rel8 (EB cb), JMP rel32 (E9 cd) and JMP r/m (FF /4).
var Opcodes = map[byte]string{
	0xC3: "RET",
	0xC2: "RET imm16",
	0xEB: "JMP rel8",
	0xE9: "JMP rel32",
	0xFF: "JMP m",
}

type Row struct {
	PID         uint64
	Process     string
	Module      string
	Path        string
	Function    string
	Offset      uint64
	Opcode      byte
	Instruction string
	Target      uint64
}

func (r Row) OpcodeString() string {
	return fmt.Sprintf("%02x (%s)", r.Opcode, r.Instruction)
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type tally struct {
	mappings, exportsUnread, noSpace, checked, unread int
}

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	maps, err := memoryranges.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process memory ranges: %w", Name, err)
	}
	var c tally
	var out []Row
	for _, m := range maps {
		if m.Type != memoryranges.KindImage || m.End < m.Start || !strings.EqualFold(fileName(m.Path), Module) {
			continue
		}
		c.mappings++
		exports, err := pesymbols.Exports(ctx, pesymbols.Module{PID: m.PID, ProcessName: m.Process,
			DirectoryTableBase: m.DirectoryTableBase, Name: m.Path, Base: m.Start, Size: m.End - m.Start + 1})
		if err != nil {
			c.exportsUnread++
			ctx.AddDiagnostic("%s: %s (%d): %s at 0x%x: export table does not read: %v", Name, m.Process, m.PID, m.Path,
				m.Start, err)
			continue
		}
		space, err := ctx.ProcessSpace(m.DirectoryTableBase)
		if err != nil {
			c.noSpace++
			ctx.AddDiagnostic("%s: %s (%d): process space: %v", Name, m.Process, m.PID, err)
			continue
		}
		out = append(out, check(space, m, exports, &c)...)
	}
	ctx.AddDiagnostic("%s: %d ntdll mappings, %d export tables unread, %d spaces unavailable; %d ETW entry points "+
		"read, %d unread; %d patched", Name, c.mappings, c.exportsUnread, c.noSpace, c.checked, c.unread, len(out))
	return out, nil
}

func fileName(path string) string {
	return path[strings.LastIndexAny(path, `\/`)+1:]
}

func check(space memory.MemoryReader, m memoryranges.Mapping, exports []pe.Export, c *tally) []Row {
	var funcs []pe.Export
	for _, e := range exports {
		if IsETWFunction(e.Name) && e.Forwarder == "" && !e.ForwarderUnreadable {
			funcs = append(funcs, e)
		}
	}
	sort.SliceStable(funcs, func(i, j int) bool { return funcs[i].RVA < funcs[j].RVA })
	wide := !strings.Contains(strings.ToLower(m.Path), `\syswow64\`)
	var out []Row
	for _, e := range funcs {
		at := e.Address(m.Start)
		code, err := space.ReadAt(at, 6)
		if err != nil || len(code) < 1 {
			c.unread++
			continue
		}
		c.checked++
		r, patched := classify(space, at, code, m, wide)
		if !patched {
			continue
		}
		r.PID, r.Process, r.Module, r.Path, r.Function, r.Offset = m.PID, m.Process, fileName(m.Path), m.Path, e.Name, at
		out = append(out, r)
	}
	return out
}

// A return as the first instruction ends the function before it logs. A
// jump is a patch only when it leaves the ntdll mapping: EtwpGetCpuSpeed
// begins with a jump inside ntdll in every process on every capture (S64 E3).
// An indirect jump whose slot does not read is reported with no target.
func classify(space memory.MemoryReader, at uint64, code []byte, m memoryranges.Mapping, wide bool) (Row, bool) {
	r := Row{Opcode: code[0], Instruction: Opcodes[code[0]]}
	inside := func(target uint64) bool { return target >= m.Start && target <= m.End }
	switch code[0] {
	case 0xC3, 0xC2:
		return r, true
	case 0xEB:
		if len(code) < 2 {
			return r, true
		}
		r.Target = at + 2 + uint64(int64(int8(code[1])))
	case 0xE9:
		if len(code) < 5 {
			return r, true
		}
		r.Target = at + 5 + uint64(int64(int32(binary.LittleEndian.Uint32(code[1:]))))
	case 0xFF:
		if len(code) < 6 || code[1] != 0x25 {
			return r, false
		}
		disp := uint64(int64(int32(binary.LittleEndian.Uint32(code[2:]))))
		slot, width := at+6+disp, uint64(8)
		if !wide {
			slot, width = uint64(uint32(disp)), 4
		}
		b, err := space.ReadAt(slot, width)
		if err != nil || uint64(len(b)) != width {
			return r, true
		}
		if width == 8 {
			r.Target = binary.LittleEndian.Uint64(b)
		} else {
			r.Target = uint64(binary.LittleEndian.Uint32(b))
		}
	default:
		return r, false
	}
	if !wide {
		r.Target = uint64(uint32(r.Target))
	}
	return r, !inside(r.Target)
}
