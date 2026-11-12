package syscallstub

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/disasm"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
)

type Finding struct {
	Process      string
	PID          uint64
	Path         string
	Address      uint64
	Number       uint32
	SyscallAt    uint64
	Instructions string
	Defender     bool
}

type Coverage struct {
	Processes  int
	Skipped    int
	Mappings   int
	Shared     int
	Bytes      uint64
	Unread     uint64
	Candidates int
	Blocks     int
}

// SYSCALL saves the return address in RCX (Intel SDM Vol. 3A, 6.8.8), so a stub
// moves the first argument to R10 before it: the anchor of every block.
var movR10RCX = []byte{0x4C, 0x8B, 0xD1}

const (
	movEAXImm32 = 0xB8
	movEAXLen   = 5
	page        = 0x1000
)

type blockKind int

const (
	direct blockKind = iota
	indirect
)

func (k blockKind) tool() string {
	if k == indirect {
		return IndirectName
	}
	return DirectName
}

type process struct {
	pid      uint64
	name     string
	dtb      uint64
	exe      string
	scan     []memoryranges.Mapping
	stubs    []memoryranges.Mapping
	sequence int
}

func scanBlocks(ctx tools.Context, kind blockKind) ([]Finding, Coverage, error) {
	var cov Coverage
	if err := ctx.Validate(); err != nil {
		return nil, cov, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, cov, fmt.Errorf("%s: unsupported profile os %q", kind.tool(), ctx.Profile.OS())
	}
	mappings, err := memoryranges.Run(ctx)
	if err != nil {
		return nil, cov, fmt.Errorf("%s: process memory ranges: %w", kind.tool(), err)
	}
	out, cov := scanProcesses(ctx, kind, mappings)
	return out, cov, nil
}

func scanProcesses(ctx tools.Context, kind blockKind, mappings []memoryranges.Mapping) ([]Finding, Coverage) {
	var cov Coverage
	limit := uint64(ctx.Bounds().MaxRegionScanBytes)
	var out []Finding
	scannedImages := map[string]bool{}
	for _, p := range groupProcesses(mappings) {
		space, err := ctx.ProcessSpace(p.dtb)
		if err != nil {
			cov.Skipped++
			ctx.AddDiagnostic("%s: %s (%d): process space: %v", kind.tool(), p.name, p.pid, err)
			continue
		}
		cov.Processes++
		s := scanner{kind: kind, mem: space, proc: p, defender: isDefenderPath(p.exe)}
		for _, m := range p.scan {
			// Views of one image at one base share its file pages, so the
			// first process's scan stands for every later one (S29 4.4 step 2).
			if m.Type == memoryranges.KindImage {
				key := fmt.Sprintf("%s@%x", strings.ToLower(m.Path), m.Start)
				if scannedImages[key] {
					cov.Shared++
					continue
				}
				scannedImages[key] = true
			}
			cov.Mappings++
			s.mapping(m, limit, &cov)
		}
		out = append(out, s.found...)
	}
	cov.Blocks = len(out)
	return out, cov
}

func executable(protection string) bool {
	return strings.Contains(strings.ToUpper(protection), "EXECUTE")
}

// The executable is the image mapping whose file name starts with the
// kernel's 15-byte image name, which the kernel cuts from that file name.
func groupProcesses(mappings []memoryranges.Mapping) []*process {
	byPID := map[uint64]*process{}
	var order []*process
	for _, m := range mappings {
		p := byPID[m.PID]
		if p == nil {
			p = &process{pid: m.PID, name: m.Process, dtb: m.DirectoryTableBase, sequence: len(order)}
			byPID[m.PID] = p
			order = append(order, p)
		}
		if m.End < m.Start {
			continue
		}
		if m.Type == memoryranges.KindImage && m.Path != "" {
			if stubModule(m.Path) {
				p.stubs = append(p.stubs, m)
				continue
			}
			file := strings.ToLower(m.Path[strings.LastIndexAny(m.Path, `\/`)+1:])
			if p.exe == "" && p.name != "" && strings.HasPrefix(file, strings.ToLower(p.name)) {
				p.exe = m.Path
			}
		}
		if executable(m.Protection) {
			p.scan = append(p.scan, m)
		}
	}
	return order
}

type scanner struct {
	kind     blockKind
	mem      memory.MemoryReader
	proc     *process
	defender bool
	found    []Finding
	last     uint64
}

func (s *scanner) mapping(m memoryranges.Mapping, limit uint64, cov *Coverage) {
	size := m.End - m.Start + 1
	if limit > 0 && size > limit {
		size = limit
	}
	s.last = 0
	for at := m.Start; at < m.Start+size; at += page {
		b, err := s.mem.ReadAt(at, page)
		if err != nil || len(b) < page {
			cov.Unread += page
			continue
		}
		cov.Bytes += page
		for i := 0; i < page; i++ {
			if b[i] != movR10RCX[0] {
				continue
			}
			if i+len(movR10RCX) > page {
				if tail, err := s.read(at+uint64(i), uint64(len(movR10RCX))); err != nil || !bytes.Equal(tail, movR10RCX) {
					continue
				}
			} else if !bytes.HasPrefix(b[i:], movR10RCX) {
				continue
			}
			cov.Candidates++
			s.candidate(m, at+uint64(i))
		}
	}
}

func (s *scanner) candidate(m memoryranges.Mapping, anchor uint64) {
	start := anchor
	window, err := s.read(anchor, stubWindow)
	if err != nil {
		return
	}
	// The two preamble moves are independent, so either order sets up the
	// same call; mov eax first puts the anchor five bytes in.
	if before, err := s.read(anchor-movEAXLen, movEAXLen); anchor >= movEAXLen && err == nil && before[0] == movEAXImm32 {
		start = anchor - movEAXLen
		window = append(before, window[:stubWindow-movEAXLen]...)
	} else if len(window) < len(movR10RCX)+movEAXLen || window[len(movR10RCX)] != movEAXImm32 {
		return
	}
	if start < s.last {
		return
	}
	f, ok := s.decode(start, window)
	if !ok {
		return
	}
	f.Process, f.PID, f.Path, f.Defender = s.proc.name, s.proc.pid, m.Path, s.defender
	s.found = append(s.found, f)
	s.last = start + stubWindow
}

func (s *scanner) read(at, n uint64) ([]byte, error) {
	b, err := s.mem.ReadAt(at, n)
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) < n {
		return nil, fmt.Errorf("short read")
	}
	return b, nil
}

// A block is straight-line code from the preamble to its end instruction:
// SYSCALL then RET for a direct block, a JMP to a SYSCALL in ntdll or win32u
// for an indirect one. A conditional jump may sit between them, as in the
// system's own stubs (S29 M3).
func (s *scanner) decode(start uint64, window []byte) (Finding, bool) {
	var f Finding
	var text []string
	var regImm = map[byte]uint64{}
	for off := 0; off < len(window); {
		inst, ok := disasm.Decode(window[off:], start+uint64(off), disasm.Mode64)
		if !ok || off+inst.Len > len(window) {
			return f, false
		}
		raw := window[off : off+inst.Len]
		text = append(text, inst.Text)
		if raw[0] == movEAXImm32 && inst.Len == movEAXLen {
			f.Number = binary.LittleEndian.Uint32(raw[1:])
		}
		if r, v, ok := movRegImm64(raw); ok {
			regImm[r] = v
		}
		switch {
		case inst.IsSyscall():
			if s.kind != direct {
				return f, false
			}
			next := off + inst.Len
			if next >= len(window) || window[next] != 0xC3 {
				return f, false
			}
			f.Address, f.SyscallAt, f.Instructions = start, inst.Address, strings.Join(append(text, "ret"), "; ")
			return f, true
		case inst.IsJmp():
			if s.kind != indirect {
				return f, false
			}
			target, ok := s.jumpTarget(inst, raw, regImm)
			if !ok || !s.syscallIn(target) {
				return f, false
			}
			f.Address, f.SyscallAt, f.Instructions = start, target, strings.Join(text, "; ")
			return f, true
		case inst.IsCall(), inst.IsRet(), inst.IsInt3(), inst.IsLeave():
			return f, false
		}
		off += inst.Len
	}
	return f, false
}

// `mov r64, imm64` is REX.W B8+r io (Intel SDM, MOV); the register number
// joins REX.B to the low opcode bits.
func movRegImm64(raw []byte) (byte, uint64, bool) {
	if len(raw) != 10 || raw[0]&0xF8 != 0x48 || raw[1]&0xF8 != 0xB8 {
		return 0, 0, false
	}
	return (raw[0]&1)<<3 | raw[1]&7, binary.LittleEndian.Uint64(raw[2:]), true
}

// The three encodings of an absolute JMP that a stub can carry: JMP rel8 and
// rel32 (EB, E9), JMP [RIP+disp32] (FF /4 with ModRM 25), and JMP r64 (FF /4
// with a register ModRM) after a `mov r64, imm64` (Intel SDM, JMP).
func (s *scanner) jumpTarget(inst disasm.Inst, raw []byte, regImm map[byte]uint64) (uint64, bool) {
	next := inst.Address + uint64(inst.Len)
	switch {
	case len(raw) == 2 && raw[0] == 0xEB:
		return next + uint64(int64(int8(raw[1]))), true
	case len(raw) == 5 && raw[0] == 0xE9:
		return next + uint64(int64(int32(binary.LittleEndian.Uint32(raw[1:])))), true
	case len(raw) == 6 && raw[0] == 0xFF && raw[1] == 0x25:
		slot := next + uint64(int64(int32(binary.LittleEndian.Uint32(raw[2:]))))
		b, err := s.read(slot, 8)
		if err != nil {
			return 0, false
		}
		return binary.LittleEndian.Uint64(b), true
	}
	rex, op := byte(0), raw
	if len(op) == 3 && op[0]&0xF0 == 0x40 {
		rex, op = op[0], op[1:]
	}
	if len(op) == 2 && op[0] == 0xFF && op[1]&0xF8 == 0xE0 {
		v, ok := regImm[(rex&1)<<3|op[1]&7]
		return v, ok
	}
	return 0, false
}

func (s *scanner) syscallIn(target uint64) bool {
	inside := false
	for _, m := range s.proc.stubs {
		if target >= m.Start && target < m.End {
			inside = true
			break
		}
	}
	if !inside {
		return false
	}
	b, err := s.read(target, 2)
	return err == nil && b[0] == 0x0F && b[1] == 0x05
}

func scanWithSummary(ctx tools.Context, kind blockKind) ([]Finding, Coverage, error) {
	findings, cov, err := scanBlocks(ctx, kind)
	if err == nil {
		ctx.AddDiagnostic("%s", summary(kind, cov))
	}
	return findings, cov, err
}

func summary(kind blockKind, c Coverage) string {
	return fmt.Sprintf("%s: %d processes scanned (%d skipped), %d mappings (%d shared image views not rescanned), "+
		"0x%x bytes read, 0x%x unread, %d anchors, %d blocks", kind.tool(), c.Processes, c.Skipped, c.Mappings, c.Shared,
		c.Bytes, c.Unread, c.Candidates, c.Blocks)
}
