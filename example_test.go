package libvapour_test

import (
	"fmt"
	"log"

	"github.com/aoiflux/libvapour"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

// The session finds the kernel and its symbols in the capture; a tool then
// reads through the context it hands out.
func Example() {
	session, err := libvapour.OpenMemory("memory.raw", "windows", libvapour.OpenConfig{
		OfflineOnly:        true,
		CollectDiagnostics: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	processes, err := processlist.Run(session.Context())
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range processes {
		fmt.Println(p.PID, p.Name)
	}
	for _, line := range session.Diagnostics() {
		fmt.Println(line)
	}
}
