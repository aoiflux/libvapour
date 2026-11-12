package testsupport

import (
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// One world for windows.pe.dump (S55 4.6) and windows.library.list (S56): the
// shared process fixture with a loaded-module list and session spaces added,
// so both tools read the same loader data.
const (
	S55ModuleListHead = uint64(0xfffff80000c00000)
	S55ModuleEntries  = uint64(0xfffff80000c10000)
	s55SessionSpaces  = uint64(0xfffff80000d00000)

	S55UserBase   = uint64(0x7ff600000000)
	S55KernelBase = uint64(0xfffff80001000000)
	S55DriverBase = uint64(0xfffff80002000000)
	S55Unmapped   = uint64(0xfffff80003000000)

	S55SessionOffset   = uint64(0xB0)
	S55SessionIDOffset = uint64(0x8)

	S55ExplorerPID = uint64(1200)
)

type S55KernelModule struct {
	Name, Path string
	Base       uint64
	Image      []byte
	InKernel   bool
	InSession  []uint64
}

type S55World struct {
	*ProcessFixture
	Ctx   tools.Context
	Diags *[]string
}

func S55Explorer() []FixtureProcess {
	return []FixtureProcess{
		{PID: 4, Name: "System", NoPeb: true},
		{PID: S55ExplorerPID, Name: "explorer.exe", Parent: 4, Modules: []FixtureModule{
			{Name: "explorer.exe", FullPath: `C:\Windows\explorer.exe`, Base: S55UserBase, Image: BuildMappedPE(0x140000000)},
		}},
	}
}

func S55StandardModules() []S55KernelModule {
	return []S55KernelModule{
		{Name: "ntoskrnl.exe", Path: `\SystemRoot\system32\ntoskrnl.exe`, Base: S55KernelBase, Image: BuildMappedPE(0x140000000), InKernel: true},
		{Name: "kdcom.dll", Path: `\SystemRoot\system32\kd.dll`, Base: S55DriverBase, Image: BuildMappedPE(0x180000000), InKernel: true},
	}
}

// Sessions follow _EPROCESS.Session to _MM_SESSION_SPACE.SessionId, where the
// S25 session reader resolves them from the table.
func BuildS55World(procs []FixtureProcess, sessions map[uint64]uint32, mods []S55KernelModule) (*S55World, error) {
	f := BuildProcessFixture(procs)
	ep, err := f.Table.Struct("_EPROCESS")
	if err != nil {
		return nil, err
	}
	ep.Fields = append(ep.Fields, symbols.Field{Name: "Session", Offset: S55SessionOffset})
	f.Table.AddStruct(ep)
	f.Table.AddStruct(symbols.StructType{Name: "_MM_SESSION_SPACE", Size: 0x100, Fields: []symbols.Field{
		{Name: "SessionId", Offset: S55SessionIDOffset, Type: symbols.TypeRef{Name: "unsigned long"}},
	}})
	for i, p := range procs {
		id, ok := sessions[p.PID]
		if !ok {
			continue
		}
		va := s55SessionSpaces + uint64(i)*0x1000
		pa := f.Kernel.MapPage(va)
		f.Memory.WriteU32(pa+S55SessionIDOffset, id)
		_, epPA := f.EPROCESS(p.PID)
		f.Memory.WriteU64(epPA+S55SessionOffset, va)
	}

	headPA := f.Kernel.MapPage(S55ModuleListHead)
	f.Table.AddSymbol(symbols.Symbol{Name: "PsLoadedModuleList", Address: S55ModuleListHead})
	prevPA, prevVA := headPA, S55ModuleListHead
	for i, m := range mods {
		va := S55ModuleEntries + uint64(i)*0x1000
		pa := f.Kernel.MapPage(va)
		f.Memory.WriteU64(prevPA+FixtureFlinkOffset, va)
		f.Memory.WriteU64(pa+FixtureBlinkOffset, prevVA)
		prevPA, prevVA = pa, va
		f.Memory.WriteU64(pa+FixtureDllBaseOffset, m.Base)
		f.Memory.WriteU32(pa+FixtureSizeOfImageOffset, uint32(len(m.Image)))
		for _, s := range []struct {
			member uint64
			text   string
		}{{FixtureBaseDllNameOffset, m.Name}, {FixtureFullDllNameOffset, m.Path}} {
			raw := utf16LE(s.text)
			buf := va + 0x400 + s.member*0x10
			f.Memory.WriteU16(pa+s.member, uint16(len(raw)))
			f.Memory.WriteU16(pa+s.member+2, uint16(len(raw)))
			f.Memory.WriteU64(pa+s.member+FixtureUnicodeBufferOffset, buf)
			f.Memory.WriteAt(pa+(buf-va), raw)
		}
		if m.InKernel {
			f.Kernel.MapImage(m.Base, m.Image)
		}
		for _, pid := range m.InSession {
			f.Space(pid).MapImage(m.Base, m.Image)
		}
	}
	f.Memory.WriteU64(prevPA+FixtureFlinkOffset, S55ModuleListHead)
	f.Memory.WriteU64(headPA+FixtureBlinkOffset, prevVA)

	ctx := f.Context()
	diags := []string{}
	ctx.Options["diagnostics"] = &diags
	return &S55World{ProcessFixture: f, Ctx: ctx, Diags: &diags}, nil
}
