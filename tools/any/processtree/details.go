package processtree

import (
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

type offset struct {
	at uint64
	ok bool
}

func offsetOf(ctx tools.Context, steps ...string) offset {
	var at uint64
	for i := 0; i+1 < len(steps); i += 2 {
		f, err := ctx.Symbols.Field(steps[i], steps[i+1])
		if err != nil {
			return offset{}
		}
		at += f.Offset
	}
	return offset{at: at, ok: true}
}

type detailReader struct {
	ctx        tools.Context
	auditInfo  offset
	objectName offset
	peb        offset
	parameters offset
	imagePath  offset
	command    offset
	unicode    util.UnicodeStringLayout
}

func newDetailReader(ctx tools.Context) detailReader {
	d := detailReader{
		ctx:        ctx,
		auditInfo:  offsetOf(ctx, "_EPROCESS", "SeAuditProcessCreationInfo", "_SE_AUDIT_PROCESS_CREATION_INFO", "ImageFileName"),
		objectName: offsetOf(ctx, "_OBJECT_NAME_INFORMATION", "Name"),
		peb:        offsetOf(ctx, "_EPROCESS", "Peb"),
		parameters: offsetOf(ctx, "_PEB", "ProcessParameters"),
		imagePath:  offsetOf(ctx, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName"),
		command:    offsetOf(ctx, "_RTL_USER_PROCESS_PARAMETERS", "CommandLine"),
		unicode:    util.ResolveUnicodeStringLayout(ctx.Symbols),
	}
	if !d.auditInfo.ok || !d.objectName.ok {
		ctx.AddDiagnostic("%s: symbol table lacks SeAuditProcessCreationInfo.ImageFileName: no audit image names", Name)
	}
	if !d.peb.ok || !d.parameters.ok || !d.imagePath.ok || !d.command.ok {
		ctx.AddDiagnostic("%s: symbol table lacks _PEB.ProcessParameters or its ImagePathName and CommandLine: no command lines", Name)
	}
	return d
}

func (d detailReader) read(p processlist.Process, e *Entry) {
	e.AuditImageName, e.AuditImageNameUnreadable = d.auditName(p.EPROCESS)
	d.parametersOf(p, e)
}

func (d detailReader) auditName(eprocess uint64) (string, bool) {
	if !d.auditInfo.ok || !d.objectName.ok {
		return "", true
	}
	info, err := d.ctx.Symbols.ReadPointer(d.ctx.Memory, eprocess+d.auditInfo.at)
	if err != nil {
		return "", true
	}
	if info == 0 {
		return "", false
	}
	s, err := util.ReadUnicodeString(d.ctx.Memory, info+d.objectName.at, d.unicode, 0)
	if err != nil {
		return "", true
	}
	return s.Text(), false
}

// A process without a PEB has no parameters to read; that is not a failure.
func (d detailReader) parametersOf(p processlist.Process, e *Entry) {
	e.ParametersUnreadable, e.ImagePathNameUnreadable, e.CommandLineUnreadable = true, true, true
	if !d.peb.ok || !d.parameters.ok || !d.imagePath.ok || !d.command.ok {
		return
	}
	peb, err := d.ctx.Symbols.ReadPointer(d.ctx.Memory, p.EPROCESS+d.peb.at)
	if err != nil {
		return
	}
	if peb == 0 {
		e.ParametersUnreadable, e.ImagePathNameUnreadable, e.CommandLineUnreadable = false, false, false
		return
	}
	space, err := d.ctx.ProcessSpace(p.DirectoryTableBase)
	if err != nil {
		return
	}
	params, err := d.ctx.Symbols.ReadPointer(space, peb+d.parameters.at)
	if err != nil || params == 0 {
		return
	}
	e.ParametersUnreadable = false
	if s, err := util.ReadUnicodeString(space, params+d.imagePath.at, d.unicode, 0); err == nil {
		e.ImagePathName, e.ImagePathNameUnreadable = s.Text(), false
	}
	if s, err := util.ReadUnicodeString(space, params+d.command.at, d.unicode, 0); err == nil {
		e.CommandLine, e.CommandLineUnreadable = s.Text(), false
	}
}
