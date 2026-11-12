package servicerecord

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

func TestTheThreeToolsAreRegistered(t *testing.T) {
	for _, name := range []string{Name, ListName, CompareName} {
		if _, err := tools.Get(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAContextWithoutMemoryIsRefused(t *testing.T) {
	for name, run := range map[string]func(tools.Context) ([]Service, error){Name: Run, ListName: List, CompareName: Compare} {
		if _, err := run(tools.Context{}); !errors.Is(err, tools.ErrMissingMemoryReader) {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestA32BitTableIsRefused(t *testing.T) {
	ctx := tools.Context{Memory: newSparse(), Symbols: symbols.NewTable("nt", 4)}
	if _, err := findTargets(ctx, Name); !errors.Is(err, ErrPointerSize) {
		t.Errorf("err %v, want %v", err, ErrPointerSize)
	}
}
