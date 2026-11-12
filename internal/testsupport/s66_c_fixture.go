package testsupport

import (
	"slices"

	"github.com/aoiflux/libvapour/symbols"
)

// S66CProcess joins the S43 VAD views of a process to the S56 loader lists in
// its PEB, so one image carries both views of the same modules.
type S66CProcess struct {
	S43Process
	Libraries []S56Library
	Wow64     []S56Library
}

func s66cPeb(i int) uint64 { return uint64(0x7ff6_0001_0000) + uint64(i)<<20 }

func S66CTable() *symbols.Table {
	t := S43Table()
	loader := S56Table()
	for _, name := range []string{"LIST_ENTRY32", "_STRING32", "_LARGE_INTEGER", "_EWOW64PROCESS", "_PEB32", "_PEB_LDR_DATA",
		"_LDR_DATA_TABLE_ENTRY", "_LDR_DDAG_NODE", "_UNICODE_STRING"} {
		st, err := loader.Struct(name)
		if err == nil {
			t.AddStruct(st)
		}
	}
	extend := func(name string, members ...string) {
		st, err := t.Struct(name)
		if err != nil {
			return
		}
		st.Fields = slices.Clone(st.Fields)
		for _, m := range members {
			if f, err := loader.Field(name, m); err == nil {
				st.Fields = append(st.Fields, f)
			}
		}
		t.AddStruct(st)
	}
	extend("_EPROCESS", "WoW64Process")
	extend("_PEB", "Ldr")
	return t
}

func BuildS66CImage(procs []S66CProcess) *S43Image {
	views := make([]S43Process, len(procs))
	for i, p := range procs {
		views[i] = p.S43Process
	}
	img := BuildS43Image(views)
	img.Table = S66CTable()
	for i, p := range procs {
		placed := img.Procs[i]
		user := img.User[placed.DirectoryTableBase]
		if !p.NoPeb {
			user.WriteU64(s66cPeb(i)+S56PebLdr, S56LdrVA)
			s56Native.place(user, p.Libraries)
		}
		if p.Wow64 != nil {
			ew := placed.EPROCESS + s56EwowInEprocess
			img.Kernel.WriteU64(placed.EPROCESS+S56Wow64Process, ew)
			img.Kernel.WriteU64(ew, S56Peb32VA)
			user.WriteU32(S56Peb32VA+S56Peb32Ldr, uint32(S56Ldr32VA))
			s56Wow.place(user, p.Wow64)
		}
	}
	return img
}
