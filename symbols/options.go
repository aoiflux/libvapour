package symbols

import (
	"fmt"

	"github.com/aoiflux/libvapour/limits"
)

const FormatVersion = 1

// The largest measured table is about 5 MB. The bound keeps a hostile file
// from exhausting the reader's memory.
const MaxTableFile = 512 << 20

// A table file is read whole into memory; past 4 GiB that is no longer a
// symbol table but a mistake.
const ceilingTableFile = 1 << 32

type ReadOptions struct {
	MaxTableFile    int64
	MaxTableEntries int
}

func (o ReadOptions) Resolved() (ReadOptions, error) {
	switch {
	case o.MaxTableFile < 0:
		return ReadOptions{}, fmt.Errorf("symbols: MaxTableFile %d is negative", o.MaxTableFile)
	case o.MaxTableFile == 0:
		o.MaxTableFile = MaxTableFile
	case o.MaxTableFile > ceilingTableFile:
		return ReadOptions{}, fmt.Errorf("symbols: MaxTableFile %d is past its ceiling %d", o.MaxTableFile, int64(ceilingTableFile))
	}
	switch {
	case o.MaxTableEntries < 0:
		return ReadOptions{}, fmt.Errorf("symbols: MaxTableEntries %d is negative", o.MaxTableEntries)
	case o.MaxTableEntries == 0:
		o.MaxTableEntries = limits.DefaultMaxTableEntries
	case o.MaxTableEntries > limits.CeilingEntries:
		return ReadOptions{}, fmt.Errorf("symbols: MaxTableEntries %d is past its ceiling %d", o.MaxTableEntries, limits.CeilingEntries)
	}
	return o, nil
}
