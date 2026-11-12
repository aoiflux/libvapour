package profiles

type Profile interface {
	Name() string
	OS() string
	PointerSize() uint8
}

// Both supported targets run the kernel in 64-bit mode, where a pointer is
// eight bytes (S77 P1 to P3).
const x64PointerSize = 8

type WindowsX64Profile struct{}

func (WindowsX64Profile) Name() string       { return "windows-x64" }
func (WindowsX64Profile) OS() string         { return "windows" }
func (WindowsX64Profile) PointerSize() uint8 { return x64PointerSize }

type LinuxX64Profile struct{}

func (LinuxX64Profile) Name() string       { return "linux-x64" }
func (LinuxX64Profile) OS() string         { return "linux" }
func (LinuxX64Profile) PointerSize() uint8 { return x64PointerSize }
