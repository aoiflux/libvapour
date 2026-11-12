package processenvironment

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/aoiflux/libvapour/util"
)

type variable struct{ name, value string }

type windowsBlock struct {
	vars       []variable
	unnamed    int
	terminated bool
}

// The first empty string ends the block; what follows can be the stale tail
// of a longer block written earlier in the same allocation (S65 M2).
func splitWindowsBlock(raw []byte) windowsBlock {
	var out windowsBlock
	start := 0
	for i := 0; i+1 < len(raw); i += 2 {
		if binary.LittleEndian.Uint16(raw[i:]) != 0 {
			continue
		}
		if i == start {
			out.terminated = true
			return out
		}
		text := util.DecodeUTF16LE(raw[start:i])
		start = i + 2
		// "=C:" and its kind begin with the separator (S65 D2).
		at := strings.IndexByte(text[1:], '=')
		if at < 0 {
			out.unnamed++
			continue
		}
		out.vars = append(out.vars, variable{name: text[:at+1], value: text[at+2:]})
	}
	return out
}

type linuxArea struct {
	vars    []variable
	unnamed int
}

func splitLinuxArea(raw []byte) linuxArea {
	var out linuxArea
	end := bytes.LastIndexByte(raw, 0)
	if end < 0 {
		return out
	}
	for _, s := range bytes.Split(raw[:end], []byte{0}) {
		if len(s) == 0 {
			continue
		}
		name, value, ok := bytes.Cut(s, []byte{'='})
		if !ok || len(name) == 0 {
			out.unnamed++
			continue
		}
		out.vars = append(out.vars, variable{name: util.DecodeUTF8Replace(name), value: util.DecodeUTF8Replace(value)})
	}
	return out
}
