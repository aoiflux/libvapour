package linuxobj

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
)

// Absent and empty differ: absent means no such field or it did not read,
// empty means the kernel holds nothing there.
type NetText struct {
	Value     string
	Available bool
}

func NetTextOf(s string) NetText { return NetText{Value: s, Available: true} }

var ErrNotInTable = errors.New("linuxobj: not in the symbol table")

func NotInTable(name string) error { return fmt.Errorf("%w: %s", ErrNotInTable, name) }

// A gap in the table holds for every object of the kind, so callers stop
// instead of counting one failure per object.
func TableGap(err error) bool {
	if err == nil {
		return false
	}
	var noType symbols.UnknownTypeError
	var noField symbols.UnknownFieldError
	var unusable symbols.UnusableTypeError
	return errors.As(err, &noType) || errors.As(err, &noField) || errors.As(err, &unusable) ||
		errors.Is(err, ErrNotInTable) || errors.Is(err, ErrUnsupported)
}
