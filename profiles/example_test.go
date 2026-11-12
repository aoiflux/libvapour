package profiles_test

import (
	"fmt"

	"github.com/aoiflux/libvapour/profiles"
)

func ExampleProfile() {
	for _, p := range []profiles.Profile{profiles.WindowsX64Profile{}, profiles.LinuxX64Profile{}} {
		fmt.Printf("%s runs %s with %d-byte pointers\n", p.Name(), p.OS(), p.PointerSize())
	}
	// Output:
	// windows-x64 runs windows with 8-byte pointers
	// linux-x64 runs linux with 8-byte pointers
}
