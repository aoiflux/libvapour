package limits

import (
	"fmt"
	"runtime"
)

// Every count, size and depth read from an image is untrusted. Each field
// bounds one kind of loop or allocation; the zero value of a field means its
// default.
type Limits struct {
	MaxListEntries      int
	MaxTableEntries     int
	MaxRowsPerObject    int
	MaxRecursionDepth   int
	MaxPathSteps        int
	MaxNameBytes        int64
	MaxTextBytes        int64
	MaxBufferBytes      int64
	MaxKernelImageBytes int64
	MaxRegionScanBytes  int64
	MaxMatchesPerChunk  int
	PTECacheEntries     int
	Workers             int
	MaxArtifactBytes    int64
	MaxArchiveBytes     int64
	MaxImageBytes       int64
	RowPreviewBytes     int64
	NameAttempts        int
}

const (
	DefaultMaxListEntries      = 1 << 20
	DefaultMaxTableEntries     = 1 << 22
	DefaultMaxRowsPerObject    = 1 << 20
	DefaultMaxRecursionDepth   = 1024
	DefaultMaxPathSteps        = 4096
	DefaultMaxNameBytes        = 4096
	DefaultMaxTextBytes        = 1 << 20
	DefaultMaxBufferBytes      = 64 << 20
	DefaultMaxKernelImageBytes = 64 << 20
	DefaultMaxRegionScanBytes  = 1 << 30
	DefaultMaxMatchesPerChunk  = 1_000_000
	DefaultPTECacheEntries     = 8192
	DefaultMaxArtifactBytes    = 1 << 30
	DefaultMaxArchiveBytes     = 16 << 30
	DefaultMaxImageBytes       = 1 << 40
	DefaultRowPreviewBytes     = 128
	DefaultNameAttempts        = 65536
)

const (
	CeilingEntries        = 1<<31 - 1
	CeilingRecursionDepth = 1 << 16
	CeilingPathSteps      = 1 << 20
	CeilingBytes          = 1 << 32
	CeilingRegionScan     = 1 << 57
	CeilingMatches        = 1 << 24
	CeilingPTECache       = 1 << 22
	CeilingWorkers        = 1024
	CeilingImageBytes     = 1 << 52
	CeilingNameAttempts   = 1 << 20
)

type Error struct {
	Field  string
	Value  int64
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("limits: %s %d: %s", e.Field, e.Value, e.Reason)
}

func Default() Limits {
	l, err := Limits{}.Resolved()
	if err != nil {
		panic(err)
	}
	return l
}

// A Limits that cannot be taken falls back whole to the defaults, never field
// by field: a mix would break the ordering between related fields.
func (l Limits) Effective() Limits {
	if r, err := l.Resolved(); err == nil {
		return r
	}
	return Default()
}

type bound struct {
	name           string
	int            *int
	size           *int64
	fallback, ceil int64
}

func (l *Limits) bounds() []bound {
	workers := int64(min(runtime.GOMAXPROCS(0), CeilingWorkers))
	return []bound{
		{name: "MaxListEntries", int: &l.MaxListEntries, fallback: DefaultMaxListEntries, ceil: CeilingEntries},
		{name: "MaxTableEntries", int: &l.MaxTableEntries, fallback: DefaultMaxTableEntries, ceil: CeilingEntries},
		{name: "MaxRowsPerObject", int: &l.MaxRowsPerObject, fallback: DefaultMaxRowsPerObject, ceil: CeilingEntries},
		{name: "MaxRecursionDepth", int: &l.MaxRecursionDepth, fallback: DefaultMaxRecursionDepth, ceil: CeilingRecursionDepth},
		{name: "MaxPathSteps", int: &l.MaxPathSteps, fallback: DefaultMaxPathSteps, ceil: CeilingPathSteps},
		{name: "MaxNameBytes", size: &l.MaxNameBytes, fallback: DefaultMaxNameBytes, ceil: CeilingBytes},
		{name: "MaxTextBytes", size: &l.MaxTextBytes, fallback: DefaultMaxTextBytes, ceil: CeilingBytes},
		{name: "MaxBufferBytes", size: &l.MaxBufferBytes, fallback: DefaultMaxBufferBytes, ceil: CeilingBytes},
		{name: "MaxKernelImageBytes", size: &l.MaxKernelImageBytes, fallback: DefaultMaxKernelImageBytes, ceil: CeilingBytes},
		{name: "MaxRegionScanBytes", size: &l.MaxRegionScanBytes, fallback: DefaultMaxRegionScanBytes, ceil: CeilingRegionScan},
		{name: "MaxMatchesPerChunk", int: &l.MaxMatchesPerChunk, fallback: DefaultMaxMatchesPerChunk, ceil: CeilingMatches},
		{name: "PTECacheEntries", int: &l.PTECacheEntries, fallback: DefaultPTECacheEntries, ceil: CeilingPTECache},
		{name: "Workers", int: &l.Workers, fallback: workers, ceil: CeilingWorkers},
		{name: "MaxArtifactBytes", size: &l.MaxArtifactBytes, fallback: DefaultMaxArtifactBytes, ceil: CeilingImageBytes},
		{name: "MaxArchiveBytes", size: &l.MaxArchiveBytes, fallback: DefaultMaxArchiveBytes, ceil: CeilingImageBytes},
		{name: "MaxImageBytes", size: &l.MaxImageBytes, fallback: DefaultMaxImageBytes, ceil: CeilingImageBytes},
		{name: "RowPreviewBytes", size: &l.RowPreviewBytes, fallback: DefaultRowPreviewBytes, ceil: CeilingImageBytes},
		{name: "NameAttempts", int: &l.NameAttempts, fallback: DefaultNameAttempts, ceil: CeilingNameAttempts},
	}
}

func (b bound) get() int64 {
	if b.int != nil {
		return int64(*b.int)
	}
	return *b.size
}

func (b bound) set(v int64) {
	if b.int != nil {
		*b.int = int(v)
		return
	}
	*b.size = v
}

// A smaller bound that exceeds the larger one it nests in could never be
// reached.
var nested = [][2]string{
	{"MaxNameBytes", "MaxTextBytes"},
	{"MaxTextBytes", "MaxBufferBytes"},
	{"RowPreviewBytes", "MaxArtifactBytes"},
	{"MaxArtifactBytes", "MaxImageBytes"},
}

func (l Limits) Resolved() (Limits, error) {
	values := map[string]int64{}
	for _, b := range l.bounds() {
		v := b.get()
		switch {
		case v < 0:
			return Limits{}, &Error{Field: b.name, Value: v, Reason: "negative"}
		case v > b.ceil:
			return Limits{}, &Error{Field: b.name, Value: v, Reason: fmt.Sprintf("past its ceiling %d", b.ceil)}
		case v == 0:
			v = b.fallback
			b.set(v)
		}
		values[b.name] = v
	}
	for _, pair := range nested {
		if small, large := values[pair[0]], values[pair[1]]; small > large {
			return Limits{}, &Error{Field: pair[0], Value: small, Reason: fmt.Sprintf("exceeds %s %d", pair[1], large)}
		}
	}
	return l, nil
}
