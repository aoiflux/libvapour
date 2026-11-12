package tools

import (
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestRegisterRefusesBadNames(t *testing.T) {
	run := func(Context) (any, error) { return nil, nil }
	for _, name := range []string{"", "windows", "windows.process", "Windows.process.list", "windows.process.list.all",
		"windows..list", "windows.process.list ", "1any.process.list", "windows.process-tree.list"} {
		if err := Register(Spec{Name: name}, run); err == nil {
			t.Errorf("%q registered", name)
		}
	}
	if err := Register(Spec{Name: "test.registry.nil_run"}, nil); err == nil {
		t.Error("nil run registered")
	}
}

func TestRegistryFindsListsAndRuns(t *testing.T) {
	var seen string
	run := func(ctx Context) (any, error) {
		seen = ctx.Running()
		return 7, nil
	}
	for _, name := range []string{"test.registry.zeta", "test.registry.alpha"} {
		MustRegister(Spec{Name: name, Description: "d"}, run)
	}
	err := Register(Spec{Name: "test.registry.alpha"}, run)
	if !errors.Is(err, ErrToolAlreadyRegistered) || !strings.Contains(err.Error(), "test.registry.alpha") {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := Get("test.registry.missing"); !errors.Is(err, ErrToolNotFound) {
		t.Errorf("missing: %v", err)
	}
	if _, err := Execute(Context{}, "test.registry.missing"); !errors.Is(err, ErrToolNotFound) {
		t.Errorf("execute missing: %v", err)
	}
	got, err := Execute(Context{}, "test.registry.zeta")
	if got != 7 || err != nil || seen != "test.registry.zeta" {
		t.Errorf("execute: %v %v, running %q", got, err, seen)
	}
	names := []string{}
	for _, s := range List() {
		names = append(names, s.Name)
	}
	if !slices.IsSorted(names) || !slices.Contains(names, "test.registry.alpha") {
		t.Errorf("list %q", names)
	}
	defer func() {
		if recover() == nil {
			t.Error("MustRegister of a duplicate did not panic")
		}
	}()
	MustRegister(Spec{Name: "test.registry.zeta"}, run)
}

func TestExecuteRecoversToolPanic(t *testing.T) {
	MustRegister(Spec{Name: "test.registry.panic_text"}, func(Context) (any, error) { panic("bad record") })
	MustRegister(Spec{Name: "test.registry.panic_index"}, func(Context) (any, error) {
		var s []int
		return s[3], nil
	})
	got, err := Execute(Context{}, "test.registry.panic_text")
	if got != nil || !errors.Is(err, ErrToolPanicked) || err.Error() != `tools: tool panicked: "test.registry.panic_text": bad record` {
		t.Errorf("text panic: %v %v", got, err)
	}
	_, err = Execute(Context{}, "test.registry.panic_index")
	var rerr runtime.Error
	if !errors.Is(err, ErrToolPanicked) || !errors.As(err, &rerr) || !strings.Contains(err.Error(), "test.registry.panic_index") {
		t.Errorf("runtime panic: %v", err)
	}
	if strings.Contains(err.Error(), "goroutine") || strings.Contains(err.Error(), ".go:") {
		t.Errorf("stack in message: %v", err)
	}
}
