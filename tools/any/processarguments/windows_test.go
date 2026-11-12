package processarguments

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// Peb, ProcessParameters and CommandLine sit where build 26100 has them
// (S61 M24).
const (
	winHead       = uint64(0xfffff80000001000)
	winProcess    = uint64(0xfffff80000002000)
	winPEB        = uint64(0x00007ff600010000)
	winParameters = uint64(0x00007ff600020000)
	winBuffer     = uint64(0x00007ff600030000)

	offLinks      = uint64(0x1d8)
	offPID        = uint64(0x1d0)
	offImage      = uint64(0x338)
	offDTB        = uint64(0x28)
	offPEB        = uint64(0x2e0)
	offParameters = uint64(0x20)
	offCommand    = uint64(0x70)
)

type table struct{ fields map[string]uint64 }

func (t table) Name() string       { return "windows-fixture" }
func (t table) PointerSize() uint8 { return 8 }
func (t table) Struct(name string) (symbols.StructType, error) {
	return symbols.StructType{}, errors.New("no struct")
}
func (t table) Field(typ, name string) (symbols.Field, error) {
	off, ok := t.fields[typ+"."+name]
	if !ok {
		return symbols.Field{}, fmt.Errorf("no %s.%s", typ, name)
	}
	return symbols.Field{Name: name, Offset: off}, nil
}
func (t table) LookupSymbol(name string) (symbols.Symbol, error) {
	if name == "PsActiveProcessHead" {
		return symbols.Symbol{Name: name, Address: winHead}, nil
	}
	return symbols.Symbol{}, fmt.Errorf("no %s", name)
}
func (t table) ReadUint32(r memory.MemoryReader, at uint64) (uint32, error) {
	b, err := r.ReadAt(at, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}
func (t table) ReadUint64(r memory.MemoryReader, at uint64) (uint64, error) {
	b, err := r.ReadAt(at, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}
func (t table) ReadPointer(r memory.MemoryReader, at uint64) (uint64, error) {
	return t.ReadUint64(r, at)
}
func (t table) ReadStruct(memory.MemoryReader, string, uint64) (symbols.StructInstance, error) {
	return symbols.StructInstance{}, errors.New("no struct")
}

type windowsCase struct {
	pm             *testsupport.PagedMemory
	kernel, user   *testsupport.AddressSpace
	processPage    uint64
	pebPage        uint64
	parametersPage uint64
}

func newWindowsCase(command string) *windowsCase {
	c := &windowsCase{pm: testsupport.NewPagedMemory(8 << 20)}
	c.kernel = c.pm.NewAddressSpace()
	c.user = c.pm.NewAddressSpace()
	c.pm.WriteU64(c.kernel.MapPage(winHead), winProcess+offLinks)
	c.processPage = c.kernel.MapPage(winProcess)
	c.pm.WriteU64(c.processPage+offLinks, winHead)
	c.pm.WriteU64(c.processPage+offPID, 1234)
	c.pm.WriteAt(c.processPage+offImage, []byte("tool.exe\x00"))
	c.pm.WriteU64(c.processPage+offPEB, winPEB)
	c.pm.WriteU64(c.processPage+offDTB, c.user.DTB)
	c.pebPage = c.user.MapPage(winPEB)
	c.pm.WriteU64(c.pebPage+offParameters, winParameters)
	c.parametersPage = c.user.MapPage(winParameters)
	units := utf16.Encode([]rune(command))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	c.pm.WriteAt(c.user.MapPage(winBuffer), raw)
	c.pm.WriteU16(c.parametersPage+offCommand, uint16(len(raw)))
	c.pm.WriteU16(c.parametersPage+offCommand+2, uint16(len(raw)+2))
	c.pm.WriteU64(c.parametersPage+offCommand+8, winBuffer)
	return c
}

func (c *windowsCase) context() (tools.Context, *[]string) {
	diags := &[]string{}
	return tools.Context{
		Memory: layers.NewProcessLayer(c.pm, c.kernel.DTB, 0),
		Symbols: table{fields: map[string]uint64{
			"_EPROCESS.ActiveProcessLinks": offLinks, "_EPROCESS.UniqueProcessId": offPID,
			"_EPROCESS.ImageFileName": offImage, "_EPROCESS.Peb": offPEB, "_EPROCESS.DirectoryTableBase": offDTB,
			"_PEB.ProcessParameters": offParameters, "_RTL_USER_PROCESS_PARAMETERS.CommandLine": offCommand,
			"_LIST_ENTRY.Flink": 0,
		}},
		Profile: profiles.WindowsX64Profile{},
		Options: map[string]any{"diagnostics": diags},
		ProcessMemory: func(dtb uint64) (memory.MemoryReader, error) {
			return layers.NewProcessLayer(c.pm, dtb, 0), nil
		},
	}, diags
}

func TestAWindowsCommandLineIsTheParametersCommandLine(t *testing.T) {
	const command = `C:\tool.exe --flag "a b"`
	c := newWindowsCase(command)
	ctx, diags := c.context()
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if r := rows[0]; r.PID != 1234 || r.Cmdline != command || r.CmdlineUnreadable || r.Arguments != nil ||
		r.Address != winProcess {
		t.Errorf("row %+v", r)
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestAProcessWithoutAPEBOrParametersHasAnEmptyCommandLine(t *testing.T) {
	c := newWindowsCase("x")
	c.pm.WriteU64(c.processPage+offPEB, 0)
	ctx, _ := c.context()
	if rows, err := Run(ctx); err != nil || len(rows) != 1 || rows[0].Cmdline != "" || rows[0].CmdlineUnreadable {
		t.Errorf("no PEB: %+v err %v", rows, err)
	}
	c = newWindowsCase("x")
	c.pm.WriteU64(c.pebPage+offParameters, 0)
	ctx, _ = c.context()
	if rows, err := Run(ctx); err != nil || len(rows) != 1 || rows[0].Cmdline != "" || rows[0].CmdlineUnreadable {
		t.Errorf("no parameters: %+v err %v", rows, err)
	}
}

func TestAWindowsCommandLineIsNeverReadThroughAnotherSpace(t *testing.T) {
	c := newWindowsCase("own")
	ctx, _ := c.context()
	ctx, kernelReads := testsupport.RefuseProcessSpace(ctx, c.user.DTB)
	diags := &[]string{}
	ctx.Options["diagnostics"] = diags
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].Cmdline != "" || !rows[0].CmdlineUnreadable {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if got := kernelReads.Addresses(); len(got) != 0 {
		t.Errorf("user addresses %#x read through the kernel layer", got)
	}
	if len(*diags) != 1 || !strings.HasPrefix((*diags)[0], Name+": 1 command lines not read, first: _EPROCESS at 0x") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestACommandLineBufferThatDoesNotReadIsSaidToBeUnread(t *testing.T) {
	c := newWindowsCase("lost")
	c.pm.WriteU64(c.parametersPage+offCommand+8, 0x00007ff600900000)
	ctx, _ := c.context()
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || !rows[0].CmdlineUnreadable {
		t.Errorf("rows %+v err %v", rows, err)
	}
	strict, _ := c.context()
	strict.Options["strict"] = true
	if _, err := Run(strict); err == nil {
		t.Error("strict mode passed an unread command line")
	}
}
