package syscallstub

import "github.com/aoiflux/libvapour/tools"

const DirectName = "windows.syscall.find_direct"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        DirectName,
			Description: "Find system-call stubs that issue SYSCALL outside ntdll and win32u",
		},
		RunDirectAny,
	)
}

func RunDirectAny(ctx tools.Context) (any, error) {
	return RunDirect(ctx)
}

func RunDirect(ctx tools.Context) ([]Finding, error) {
	findings, _, err := ScanDirect(ctx)
	return findings, err
}

func ScanDirect(ctx tools.Context) ([]Finding, Coverage, error) {
	return scanWithSummary(ctx, direct)
}
