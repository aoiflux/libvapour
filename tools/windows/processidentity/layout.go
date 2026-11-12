package processidentity

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/util"
)

var (
	ErrLayout          = errors.New("processidentity: symbol table lacks a member the check needs")
	ErrNoProcessString = errors.New("processidentity: _RTL_USER_PROCESS_PARAMETERS has neither ImagePathName nor CommandLine")
)

type member struct {
	at uint64
	ok bool
}

type layout struct {
	peb, parameters member
	blockLength     member
	imagePath       member
	commandLine     member
	audit           member
	auditName       member
	strings         util.UnicodeStringLayout
	pointer         uint64
}

func field(t symbols.SymbolTable, typ, name string) member {
	f, err := t.Field(typ, name)
	if err != nil {
		return member{}
	}
	return member{at: f.Offset, ok: true}
}

func resolveLayout(t symbols.SymbolTable) (layout, []string, error) {
	l := layout{
		peb:         field(t, "_EPROCESS", "Peb"),
		parameters:  field(t, "_PEB", "ProcessParameters"),
		blockLength: field(t, "_RTL_USER_PROCESS_PARAMETERS", "Length"),
		imagePath:   field(t, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName"),
		commandLine: field(t, "_RTL_USER_PROCESS_PARAMETERS", "CommandLine"),
		strings:     util.ResolveUnicodeStringLayout(t),
		pointer:     uint64(t.PointerSize()),
	}
	if !l.peb.ok || !l.parameters.ok {
		return layout{}, nil, fmt.Errorf("%w: _EPROCESS.Peb or _PEB.ProcessParameters", ErrLayout)
	}
	if !l.imagePath.ok && !l.commandLine.ok {
		return layout{}, nil, ErrNoProcessString
	}
	var absent []string
	if !l.imagePath.ok {
		absent = append(absent, "_RTL_USER_PROCESS_PARAMETERS.ImagePathName")
	}
	if !l.commandLine.ok {
		absent = append(absent, "_RTL_USER_PROCESS_PARAMETERS.CommandLine")
	}
	if !l.blockLength.ok {
		absent = append(absent, "_RTL_USER_PROCESS_PARAMETERS.Length")
	}
	creation := field(t, "_EPROCESS", "SeAuditProcessCreationInfo")
	info := field(t, "_SE_AUDIT_PROCESS_CREATION_INFO", "ImageFileName")
	name := field(t, "_OBJECT_NAME_INFORMATION", "Name")
	if creation.ok && info.ok && name.ok {
		l.audit = member{at: creation.at + info.at, ok: true}
		l.auditName = name
	} else {
		absent = append(absent, "_EPROCESS.SeAuditProcessCreationInfo.ImageFileName.Name")
	}
	return l, absent, nil
}

type counted struct {
	util.UnicodeString
	units []uint16
}

// The raw units are kept as well as the text: a NUL inside Length and the unit
// just past Length are part of the layout rule (S68 4.5 step 6).
func readString(r memory.MemoryReader, l layout, at uint64) (counted, error) {
	s, err := util.ReadUnicodeString(r, at, l.strings, util.MaxUnicodeStringBytes)
	if err != nil {
		return counted{}, err
	}
	c := counted{UnicodeString: s}
	span := uint64(max(s.Length, s.MaximumLength)) &^ 1
	if s.Buffer == 0 || span == 0 {
		return c, nil
	}
	data, err := r.ReadAt(s.Buffer, span)
	if err != nil || uint64(len(data)) < span {
		data, err = r.ReadAt(s.Buffer, uint64(s.Length)&^1)
		if err != nil {
			return c, nil
		}
	}
	c.units = make([]uint16, len(data)/2)
	for i := range c.units {
		c.units[i] = uint16(data[2*i]) | uint16(data[2*i+1])<<8
	}
	return c, nil
}
