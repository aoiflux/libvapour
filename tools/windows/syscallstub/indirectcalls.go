package syscallstub

import "github.com/aoiflux/libvapour/tools"

const IndirectName = "windows.syscall.find_indirect"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        IndirectName,
			Description: "Find system-call stubs outside ntdll and win32u that jump to a SYSCALL inside them",
		},
		RunIndirectAny,
	)
}

func RunIndirectAny(ctx tools.Context) (any, error) {
	return RunIndirect(ctx)
}

func RunIndirect(ctx tools.Context) ([]Finding, error) {
	findings, _, err := ScanIndirect(ctx)
	return findings, err
}

func ScanIndirect(ctx tools.Context) ([]Finding, Coverage, error) {
	return scanWithSummary(ctx, indirect)
}
