package memoryranges

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

const OptionMemoryListAddress = "any.memory.list.address"

var ErrAddressUnsupported = errors.New("memoryranges: address filter needs a windows profile")

type AddressFilter struct {
	key     string
	address uint64
	set     bool
}

func ReadAddressFilter(ctx tools.Context, key string) (AddressFilter, error) {
	address, set, err := ctx.UintOption(key)
	if err != nil {
		return AddressFilter{}, err
	}
	return AddressFilter{key: key, address: address, set: set}, nil
}

func (f AddressFilter) Active() bool { return f.set }

func (f AddressFilter) Keeps(start, end uint64) bool {
	return !f.set || (start <= f.address && f.address <= end)
}

func (f AddressFilter) Apply(ctx tools.Context, tool string, rows []Mapping) []Mapping {
	if !f.set {
		return rows
	}
	kept := make([]Mapping, 0, min(len(rows), 64))
	for _, m := range rows {
		if f.Keeps(m.Start, m.End) {
			kept = append(kept, m)
		}
	}
	ctx.AddDiagnostic("%s: %s 0x%x falls in %d of %d ranges", tool, f.key, f.address, len(kept), len(rows))
	return kept
}

func RunMemoryList(ctx tools.Context) (any, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	filter, err := ReadAddressFilter(ctx, OptionMemoryListAddress)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", MemoryListName, err)
	}
	if filter.Active() && !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %s: %w", MemoryListName, OptionMemoryListAddress, ErrAddressUnsupported)
	}
	rows, err := Run(ctx)
	if err != nil {
		return nil, err
	}
	return filter.Apply(ctx, MemoryListName, rows), nil
}
