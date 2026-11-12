package autoload

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// Symbol record kinds from cvinfo.h.
const (
	sPub32    = 0x110e
	sLData32  = 0x110c
	sGData32  = 0x110d
	sLProc32  = 0x110f
	sGProc32  = 0x1110
	sProcRef  = 0x1125
	sLProcRef = 0x1127

	moduleSignatureBytes = 4
	procAddressAt        = 28
)

type placedSymbol struct {
	address uint64
	public  bool
}

// Publics are the linker's names for the image and are taken first; data and
// procedure records place only names no public gave. Within one kind, the
// first record of a name is kept.
func collectAddresses(c *msfContainer, info debugInfo, decorated bool) map[string]uint64 {
	placed := map[string]placedSymbol{}
	place := func(name string, address uint64, public bool) {
		if name == "" {
			return
		}
		if held, seen := placed[name]; !seen || public && !held.public {
			placed[name] = placedSymbol{address, public}
		}
	}
	records := c.stream(int(info.symbolRecords))
	if info.symbolRecords == noStreamIndex {
		records = nil
	}
	modules := map[int][]byte{}
	for at := 0; at+4 <= len(records); {
		n := int(binary.LittleEndian.Uint16(records[at:]))
		if n < 2 || at+2+n > len(records) {
			break
		}
		kind := binary.LittleEndian.Uint16(records[at+2:])
		body := records[at+4 : at+2+n]
		at += 2 + n
		switch kind {
		case sPub32, sLData32:
			if len(body) < 10 {
				continue
			}
			name, _, ok := readName(body[10:])
			if !ok {
				continue
			}
			address, ok := info.address(binary.LittleEndian.Uint16(body[8:]), binary.LittleEndian.Uint32(body[4:]))
			if !ok {
				continue
			}
			if kind == sPub32 {
				if decorated {
					name = undecorateC(name)
				}
				place(name, address, true)
			} else {
				place(name, address, false)
			}
		case sLProcRef:
			if len(body) < 10 {
				continue
			}
			name, _, ok := readName(body[10:])
			if !ok {
				continue
			}
			if address, ok := procedureAddress(c, info, modules, binary.LittleEndian.Uint16(body[8:]), binary.LittleEndian.Uint32(body[4:]), name); ok {
				place(name, address, false)
			}
		}
	}
	out := make(map[string]uint64, len(placed))
	for name, p := range placed {
		out[name] = p.address
	}
	return out
}

// A procedure reference names its module (from 1) and the byte offset of the
// procedure record in that module's stream, whose symbol bytes begin with a
// four-byte signature. The record there must be a procedure of the same name.
func procedureAddress(c *msfContainer, info debugInfo, modules map[int][]byte, module uint16, offset uint32, name string) (uint64, bool) {
	if module == 0 || int(module) > len(info.modules) {
		return 0, false
	}
	m := info.modules[module-1]
	if m.symbolStream == noStreamIndex {
		return 0, false
	}
	s, loaded := modules[int(m.symbolStream)]
	if !loaded {
		s = c.stream(int(m.symbolStream))
		if uint64(m.symbolBytes) < uint64(len(s)) {
			s = s[:m.symbolBytes]
		}
		modules[int(m.symbolStream)] = s
	}
	at := uint64(offset)
	if at < moduleSignatureBytes || at+4 > uint64(len(s)) {
		return 0, false
	}
	n := uint64(binary.LittleEndian.Uint16(s[at:]))
	kind := binary.LittleEndian.Uint16(s[at+2:])
	if (kind != sLProc32 && kind != sGProc32) || at+2+n > uint64(len(s)) || n < 2+procAddressAt+7 {
		return 0, false
	}
	body := s[at+4 : at+2+n]
	own, _, ok := readName(body[procAddressAt+7:])
	if !ok || own != name {
		return 0, false
	}
	return info.address(binary.LittleEndian.Uint16(body[procAddressAt+4:]), binary.LittleEndian.Uint32(body[procAddressAt:]))
}

// x86 C names carry their calling convention: __cdecl a leading underscore,
// __stdcall that and @<bytes>, __fastcall a leading @ and @<bytes>, and
// __vectorcall @@<bytes>, the parameter bytes in decimal. A C++ name starts
// with ?, and a name with an @ in no such form is not a C name: both are kept
// whole.
func undecorateC(name string) string {
	if strings.HasPrefix(name, "?") {
		return name
	}
	if !strings.Contains(name, "@") {
		return strings.TrimPrefix(name, "_")
	}
	if base, bytes, ok := strings.Cut(name, "@@"); ok && parameterBytes(bytes) && plainName(base) {
		return base
	}
	at := strings.LastIndexByte(name, '@')
	base, bytes := name[:at], name[at+1:]
	if !parameterBytes(bytes) {
		return name
	}
	switch {
	case strings.HasPrefix(base, "@") && plainName(base[1:]):
		return base[1:]
	case strings.HasPrefix(base, "_") && plainName(base[1:]):
		return base[1:]
	}
	return name
}

func plainName(s string) bool { return s != "" && !strings.Contains(s, "@") }

// A parameter list on a 32-bit machine is fewer than 2^32 bytes, and a decimal
// count has no leading zero; constants named after their hexadecimal value are
// neither.
func parameterBytes(s string) bool {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return err == nil && n <= 0xffffffff
}
