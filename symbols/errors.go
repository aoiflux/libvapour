package symbols

import (
	"errors"
	"fmt"
)

var (
	ErrNotVsym       = errors.New("symbols: not a vsym symbol table")
	ErrTableTooLarge = errors.New("symbols: symbol table file is past the size limit")
)

type UnknownTypeError struct {
	TypeName string
}

func (e UnknownTypeError) Error() string {
	return fmt.Sprintf("symbols: no type %q", e.TypeName)
}

type UnknownFieldError struct {
	TypeName  string
	FieldName string
}

func (e UnknownFieldError) Error() string {
	return fmt.Sprintf("symbols: type %q has no field %q", e.TypeName, e.FieldName)
}

// The type is in the table but its embedded members cannot be brought up. It
// is kept apart from UnknownTypeError so that a caller's fallback for a type
// the build lacks does not fire on a table that is broken.
type UnusableTypeError struct {
	TypeName string
	Reason   string
}

func (e UnusableTypeError) Error() string {
	return fmt.Sprintf("symbols: type %q is unreadable: %s", e.TypeName, e.Reason)
}
