package processenvironment

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

const Name = "any.process.read_environment"

var ErrNoEnvironmentMember = errors.New("processenvironment: symbol table lacks a member the environment needs")

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Read each process's environment variables",
		},
		RunAny,
	)
}

type EnvVar struct {
	PID      uint64
	Process  string
	EPROCESS uint64
	Block    uint64
	Variable string
	Value    string
}

type LinuxEnvVar struct {
	PID, PPID  int64
	Comm       string
	Key, Value string
}

func RunAny(ctx tools.Context) (any, error) {
	if ctx.Profile != nil && strings.EqualFold(ctx.Profile.OS(), "linux") {
		return RunLinux(ctx)
	}
	return Run(ctx)
}

func Run(ctx tools.Context) ([]EnvVar, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q (linux has RunLinux)", Name, ctx.Profile.OS())
	}
	return runWindows(ctx)
}

const pageSize = uint64(0x1000)

// Stops at the first page that does not read, so the caller keeps what lies
// before a hole.
func readPages(r memory.MemoryReader, at, n uint64) []byte {
	out := make([]byte, 0, min(n, 1<<16))
	for uint64(len(out)) < n {
		pos := at + uint64(len(out))
		step := min(pageSize-pos%pageSize, n-uint64(len(out)))
		b, err := r.ReadAt(pos, step)
		if err != nil || uint64(len(b)) != step {
			return out
		}
		out = append(out, b...)
	}
	return out
}
