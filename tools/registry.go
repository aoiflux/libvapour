package tools

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

var (
	ErrToolAlreadyRegistered = errors.New("tools: tool name already registered")
	ErrToolNotFound          = errors.New("tools: tool not registered")
	ErrToolPanicked          = errors.New("tools: tool panicked")
)

type RunFunc func(Context) (any, error)

type Spec struct {
	Name        string
	Description string
}

type RegisteredTool struct {
	Spec Spec
	run  RunFunc
}

func (t RegisteredTool) Run(ctx Context) (any, error) { return t.run(ctx) }

var toolName = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// Registration happens in init functions; lookups may come from any goroutine.
var registry struct {
	sync.RWMutex
	byName map[string]RegisteredTool
}

func Register(spec Spec, run RunFunc) error {
	if !toolName.MatchString(spec.Name) {
		return fmt.Errorf("tools: tool name %q is not platform.subject.verb in lowercase", spec.Name)
	}
	if run == nil {
		return fmt.Errorf("tools: tool %q has no run function", spec.Name)
	}
	registry.Lock()
	defer registry.Unlock()
	if _, taken := registry.byName[spec.Name]; taken {
		return fmt.Errorf("%w: %q", ErrToolAlreadyRegistered, spec.Name)
	}
	if registry.byName == nil {
		registry.byName = map[string]RegisteredTool{}
	}
	registry.byName[spec.Name] = RegisteredTool{Spec: spec, run: run}
	return nil
}

func MustRegister(spec Spec, run RunFunc) {
	if err := Register(spec, run); err != nil {
		panic(err)
	}
}

func Get(name string) (RegisteredTool, error) {
	registry.RLock()
	defer registry.RUnlock()
	t, ok := registry.byName[name]
	if !ok {
		return RegisteredTool{}, fmt.Errorf("%w: %q", ErrToolNotFound, name)
	}
	return t, nil
}

// Name order gives every listing and every run of all tools one order.
func List() []Spec {
	registry.RLock()
	defer registry.RUnlock()
	specs := make([]Spec, 0, len(registry.byName))
	for _, t := range registry.byName {
		specs = append(specs, t.Spec)
	}
	slices.SortFunc(specs, func(a, b Spec) int { return strings.Compare(a.Name, b.Name) })
	return specs
}

// A panic on hostile data would otherwise end the caller's whole run, not just this tool.
func Execute(ctx Context, name string) (result any, err error) {
	t, err := Get(name)
	if err != nil {
		return nil, err
	}
	ctx.running = name
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		result = nil
		if cause, ok := r.(error); ok {
			err = fmt.Errorf("%w: %q: %w", ErrToolPanicked, name, cause)
			return
		}
		err = fmt.Errorf("%w: %q: %v", ErrToolPanicked, name, r)
	}()
	return t.Run(ctx)
}
