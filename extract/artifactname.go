package extract

import (
	"math"
	"strconv"
	"strings"
)

type Kind string

const (
	KindRegion      Kind = "region"
	KindModule      Kind = "module"
	KindImage       Kind = "image"
	KindProcess     Kind = "process"
	KindFile        Kind = "file"
	KindHive        Kind = "hive"
	KindInode       Kind = "inode"
	KindPageCache   Kind = "pagecache"
	KindFramebuffer Kind = "framebuffer"
)

const (
	ExtBytes    = "bin"
	ExtPE       = "pe"
	ExtELF      = "elf"
	ExtMinidump = "dmp"
	ExtHive     = "regf"
	ExtPNG      = "png"
	ExtTarGzip  = "tar.gz"
)

const (
	ViewData  = "data"
	ViewImage = "image"
	ViewCache = "cache"
)

type Scope struct {
	pid   uint64
	space string
}

func Process(pid uint64) Scope { return Scope{pid: pid} }

var (
	Kernel   = Scope{space: "kernel"}
	Physical = Scope{space: "phys"}
)

func (s Scope) String() string {
	if s.space != "" {
		return s.space
	}
	return "pid" + strconv.FormatUint(s.pid, 10)
}

type Name struct {
	Kind      Kind
	Scope     Scope
	Width     uint8
	Addresses []uint64
	Labels    []string
	Ext       string
}

const (
	maxLabelBytes = 64
	truncatedMark = '~'
	width32       = 4
)

func (n Name) String() string {
	parts := []string{string(n.Kind), n.Scope.String()}
	for _, a := range n.Addresses {
		parts = append(parts, n.address(a))
	}
	for _, l := range n.Labels {
		if l = Label(l); l != "" {
			parts = append(parts, l)
		}
	}
	parts = append(parts, n.Ext)
	return strings.Join(parts, ".")
}

func (n Name) address(a uint64) string {
	digits := 16
	if n.Width == width32 {
		a &= math.MaxUint32
		digits = 8
	}
	s := strconv.FormatUint(a, 16)
	return "0x" + strings.Repeat("0", digits-len(s)) + s
}

// A label can come from the image, so it is cut to its last path component
// and mapped to the portable set before it is joined: a hostile module path
// must not carry a separator into the name.
func Label(s string) string {
	if i := strings.LastIndexAny(s, `\/`); i >= 0 {
		s = s[i+1:]
	}
	out := portable(s)
	if len(out) > maxLabelBytes {
		out = out[:maxLabelBytes-1] + string(truncatedMark)
	}
	return out
}

func portable(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isPortable(r) {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	return b.String()
}

func isPortable(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return r == '.' || r == '_' || r == '-' || r == truncatedMark
}
