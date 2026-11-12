package memorycode

import (
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

const Name = "any.memory.find_code"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List process memory that holds executable code with no image file behind it (Windows VADs, Linux VMAs)",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) {
	if ctx.Profile != nil && strings.EqualFold(ctx.Profile.OS(), "linux") {
		return RunLinux(ctx)
	}
	return Run(ctx)
}
