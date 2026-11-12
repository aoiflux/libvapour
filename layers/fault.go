package layers

import (
	"errors"
	"fmt"
)

type PageErrorKind int

const (
	PageInvalid PageErrorKind = iota
	PageDemandZero
	PageInPagefile
	PageNotCaptured
	PagePrototype
)

var (
	ErrPageInvalid     = errors.New("layers: page not mapped")
	ErrPageDemandZero  = errors.New("layers: page is demand-zero and was never written")
	ErrPageInPagefile  = errors.New("layers: page is in a pagefile that was not supplied")
	ErrPageNotCaptured = errors.New("layers: page table not in the capture")
	ErrPagePrototype   = errors.New("layers: page is reached through a prototype entry")
)

var pageErrorKinds = [...]struct {
	name string
	err  error
}{
	PageInvalid:     {"not mapped", ErrPageInvalid},
	PageDemandZero:  {"demand-zero", ErrPageDemandZero},
	PageInPagefile:  {"in pagefile", ErrPageInPagefile},
	PageNotCaptured: {"table not captured", ErrPageNotCaptured},
	PagePrototype:   {"prototype", ErrPagePrototype},
}

func (k PageErrorKind) String() string {
	if k < 0 || int(k) >= len(pageErrorKinds) {
		return pageErrorKinds[PageInvalid].name
	}
	return pageErrorKinds[k].name
}

type UnmappedPageError struct {
	VirtualAddress uint64
	Kind           PageErrorKind
	PageFileNumber int
	PageFileOffset uint64
	// Above the leaf, the bytes the faulting entry covers, so a caller can
	// step past all of them; zero at the leaf.
	Span uint64
}

func (e UnmappedPageError) Error() string {
	return fmt.Sprintf("layers: virtual address 0x%x: %s", e.VirtualAddress, e.Kind)
}

func (e UnmappedPageError) Unwrap() error {
	if e.Kind < 0 || int(e.Kind) >= len(pageErrorKinds) {
		return ErrPageInvalid
	}
	return pageErrorKinds[e.Kind].err
}
