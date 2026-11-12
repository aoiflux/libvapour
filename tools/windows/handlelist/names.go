package handlelist

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/util"
)

var (
	errNameUnreadable = errors.New("handlelist: object name not readable")
	errPathTooLong    = errors.New("handlelist: name path past MaxPathSteps")
	errLevelMismatch  = errors.New("handlelist: key path length disagrees with TotalLevels")
)

// A key control block whose key roots a hive repeats the key that mounts the
// hive in its parent hive; the namespace path holds the mount point once.
const hiveRootFlag = 0x4

type nameForm int

const (
	formNamespace nameForm = iota
	formFile
	formProcess
	formThread
	formKey
	formCount
)

var formLabels = [formCount]string{"namespace", "File", "Process", "Thread", "Key"}

func formOf(typeName string) nameForm {
	switch typeName {
	case "File":
		return formFile
	case "Process":
		return formProcess
	case "Thread":
		return formThread
	case "Key":
		return formKey
	}
	return formNamespace
}

type nameReader struct {
	table    symbols.SymbolTable
	maxSteps int
	body     uint64

	namer    scan.ObjectNamer
	hasNamer bool
	dirField uint64
	hasDir   bool
	nameFld  uint64
	root     uint64
	rootRead bool

	fileDevice, fileNameOff uint64
	processID, imageName    uint64
	imageLen                uint64
	cid, cidProcess         uint64
	cidThread               uint64
	keyKCB                  uint64
	kcbParent, kcbName      uint64
	kcbFlags, kcbLevels     symbols.IntField
	hasFlags, hasLevels     bool
	ncbCompressed           symbols.IntField
	ncbLength               symbols.IntField
	ncbName                 uint64
	layoutErr               [formCount]error

	unreadable [formCount]int
	examples   [formCount]string
}

func newNameReader(table symbols.SymbolTable, maxSteps int) *nameReader {
	n := &nameReader{table: table, maxSteps: maxSteps}
	field := func(typ, member string, dst *uint64) error {
		f, err := table.Field(typ, member)
		if err != nil {
			return err
		}
		*dst = f.Offset
		return nil
	}
	intField := func(typ, member string, dst *symbols.IntField) error {
		f, err := symbols.ResolveIntField(table, typ, member)
		if err != nil {
			return err
		}
		*dst = f
		return nil
	}
	if err := field("_OBJECT_HEADER", "Body", &n.body); err != nil {
		for i := range n.layoutErr {
			n.layoutErr[i] = err
		}
		return n
	}
	n.namer, n.hasNamer = scan.NewObjectNamer(table)
	if !n.hasNamer {
		n.layoutErr[formNamespace] = errors.New("handlelist: symbol table cannot place _OBJECT_HEADER_NAME_INFO")
	}
	n.layoutErr[formNamespace] = errors.Join(n.layoutErr[formNamespace], field("_OBJECT_HEADER_NAME_INFO", "Name", &n.nameFld))
	n.hasDir = field("_OBJECT_HEADER_NAME_INFO", "Directory", &n.dirField) == nil
	n.layoutErr[formFile] = errors.Join(field("_FILE_OBJECT", "DeviceObject", &n.fileDevice),
		field("_FILE_OBJECT", "FileName", &n.fileNameOff))
	n.layoutErr[formProcess] = errors.Join(field("_EPROCESS", "UniqueProcessId", &n.processID),
		field("_EPROCESS", "ImageFileName", &n.imageName))
	if f, err := table.Field("_EPROCESS", "ImageFileName"); err == nil {
		n.imageLen = f.Type.ArrayLength
	}
	if n.imageLen == 0 {
		n.imageLen = 15
	}
	n.layoutErr[formThread] = errors.Join(field("_ETHREAD", "Cid", &n.cid),
		field("_CLIENT_ID", "UniqueProcess", &n.cidProcess), field("_CLIENT_ID", "UniqueThread", &n.cidThread))
	n.layoutErr[formKey] = errors.Join(field("_CM_KEY_BODY", "KeyControlBlock", &n.keyKCB),
		field("_CM_KEY_CONTROL_BLOCK", "ParentKcb", &n.kcbParent), field("_CM_KEY_CONTROL_BLOCK", "NameBlock", &n.kcbName),
		intField("_CM_NAME_CONTROL_BLOCK", "Compressed", &n.ncbCompressed),
		intField("_CM_NAME_CONTROL_BLOCK", "NameLength", &n.ncbLength), field("_CM_NAME_CONTROL_BLOCK", "Name", &n.ncbName))
	n.hasFlags = intField("_CM_KEY_CONTROL_BLOCK", "Flags", &n.kcbFlags) == nil
	n.hasLevels = intField("_CM_KEY_CONTROL_BLOCK", "TotalLevels", &n.kcbLevels) == nil
	return n
}

// The bool reports a name that exists but did not read.
func (n *nameReader) read(ctx tools.Context, typeName string, header uint64) (string, bool) {
	form := formOf(typeName)
	name, err := n.name(ctx, form, header)
	if err == nil {
		return name, false
	}
	n.unreadable[form]++
	if n.examples[form] == "" {
		n.examples[form] = fmt.Sprintf("object at 0x%x: %v", header, err)
	}
	return "", true
}

func (n *nameReader) name(ctx tools.Context, form nameForm, header uint64) (string, error) {
	if err := n.layoutErr[form]; err != nil {
		if form == formNamespace {
			return "", nil
		}
		return "", err
	}
	body := header + n.body
	switch form {
	case formFile:
		return n.fileObjectName(ctx, body)
	case formProcess:
		return n.processName(ctx, body)
	case formThread:
		return n.threadName(ctx, body)
	case formKey:
		return n.keyName(ctx, body)
	}
	return n.namespacePath(ctx, header)
}

func (n *nameReader) rootDirectory(ctx tools.Context) uint64 {
	if !n.rootRead {
		n.rootRead = true
		if s, err := n.table.LookupSymbol("ObpRootDirectoryObject"); err == nil {
			n.root, _ = n.table.ReadPointer(ctx.Memory, s.Address)
		}
	}
	return n.root
}

// The name info's Directory chain gives the parents. A chain that reaches
// the root directory is a full path; one that ends at a directory with no
// name, or at an object with no Directory, is given relative, with no
// leading backslash.
func (n *nameReader) namespacePath(ctx tools.Context, header uint64) (string, error) {
	if !n.hasNamer {
		return "", nil
	}
	root := n.rootDirectory(ctx)
	if root != 0 && header+n.body == root {
		return `\`, nil
	}
	var parts []string
	seen := map[uint64]bool{}
	for step := 0; ; step++ {
		if n.maxSteps > 0 && step >= n.maxSteps {
			return "", errPathTooLong
		}
		info, present, readable := n.namer.NameInfo(ctx.Memory, ctx.Memory, header)
		if !readable {
			return "", errNameUnreadable
		}
		if !present {
			if step == 0 {
				return "", nil
			}
			return joinRelative(parts), nil
		}
		part, err := readUnicodeStringAt(ctx, info+n.nameFld)
		if err != nil {
			return "", err
		}
		if step == 0 && part == "" {
			return "", nil
		}
		parts = append(parts, part)
		if !n.hasDir {
			return joinRelative(parts), nil
		}
		dir, err := n.table.ReadPointer(ctx.Memory, info+n.dirField)
		if err != nil {
			return "", err
		}
		switch {
		case dir == 0:
			return joinRelative(parts), nil
		case root != 0 && dir == root:
			slices.Reverse(parts)
			return `\` + strings.Join(parts, `\`), nil
		case seen[dir]:
			return "", errNameUnreadable
		}
		seen[dir] = true
		header = dir - n.body
	}
}

func joinRelative(parts []string) string {
	out := slices.Clone(parts)
	slices.Reverse(out)
	return strings.Join(out, `\`)
}

// FileName is the path on the device; the device's own namespace path comes
// first. A relative FileName was relative to a RelatedFileObject, which is
// valid only while the open is processed, so it stands alone.
func (n *nameReader) fileObjectName(ctx tools.Context, body uint64) (string, error) {
	file, err := readUnicodeStringAt(ctx, body+n.fileNameOff)
	if err != nil {
		return "", err
	}
	if file != "" && !strings.HasPrefix(file, `\`) {
		return file, nil
	}
	device := ""
	if dev, err := n.table.ReadPointer(ctx.Memory, body+n.fileDevice); err == nil && dev != 0 && n.layoutErr[formNamespace] == nil {
		if p, err := n.namespacePath(ctx, dev-n.body); err == nil {
			device = p
		} else if file == "" {
			return "", err
		}
	}
	return device + file, nil
}

func (n *nameReader) processName(ctx tools.Context, body uint64) (string, error) {
	pid, err := n.table.ReadPointer(ctx.Memory, body+n.processID)
	if err != nil {
		return "", err
	}
	raw, err := ctx.Memory.ReadAt(body+n.imageName, n.imageLen)
	if err != nil {
		return "", err
	}
	image := string(raw)
	if i := strings.IndexByte(image, 0); i >= 0 {
		image = image[:i]
	}
	return fmt.Sprintf("%s pid %d", util.ReplaceInvalidUTF8(image), pid), nil
}

func (n *nameReader) threadName(ctx tools.Context, body uint64) (string, error) {
	tid, err := n.table.ReadPointer(ctx.Memory, body+n.cid+n.cidThread)
	if err != nil {
		return "", err
	}
	pid, err := n.table.ReadPointer(ctx.Memory, body+n.cid+n.cidProcess)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tid %d pid %d", tid, pid), nil
}

// Each key control block names one level; the chain of parents ends at the
// root key, REGISTRY. TotalLevels, where the table has it, must equal the
// number of levels kept.
func (n *nameReader) keyName(ctx tools.Context, body uint64) (string, error) {
	kcb, err := n.table.ReadPointer(ctx.Memory, body+n.keyKCB)
	if err != nil {
		return "", err
	}
	if kcb == 0 {
		return "", nil
	}
	var levels uint64
	if n.hasLevels {
		if levels, err = n.kcbLevels.Read(ctx.Memory, kcb); err != nil {
			return "", err
		}
	}
	var parts []string
	seen := map[uint64]bool{}
	for step := 0; kcb != 0; step++ {
		if n.maxSteps > 0 && step >= n.maxSteps {
			return "", errPathTooLong
		}
		if seen[kcb] {
			return "", errNameUnreadable
		}
		seen[kcb] = true
		parent, err := n.table.ReadPointer(ctx.Memory, kcb+n.kcbParent)
		if err != nil {
			return "", err
		}
		inner := false
		if n.hasFlags && parent != 0 {
			flags, err := n.kcbFlags.Read(ctx.Memory, kcb)
			if err != nil {
				return "", err
			}
			inner = flags&hiveRootFlag != 0
		}
		if !inner {
			part, err := n.keyLevel(ctx, kcb)
			if err != nil {
				return "", err
			}
			parts = append(parts, part)
		}
		kcb = parent
	}
	if n.hasLevels && uint64(len(parts)) != levels {
		return "", fmt.Errorf("%w: %d levels, TotalLevels %d", errLevelMismatch, len(parts), levels)
	}
	slices.Reverse(parts)
	return `\` + strings.Join(parts, `\`), nil
}

// A compressed name stores one byte per character.
func (n *nameReader) keyLevel(ctx tools.Context, kcb uint64) (string, error) {
	block, err := n.table.ReadPointer(ctx.Memory, kcb+n.kcbName)
	if err != nil {
		return "", err
	}
	if block == 0 {
		return "", errNameUnreadable
	}
	compressed, err := n.ncbCompressed.Read(ctx.Memory, block)
	if err != nil {
		return "", err
	}
	length, err := n.ncbLength.Read(ctx.Memory, block)
	if err != nil {
		return "", err
	}
	raw, err := ctx.Memory.ReadAt(block+n.ncbName, length)
	if err != nil {
		return "", err
	}
	return decodeKeyLevel(raw, compressed != 0), nil
}

func decodeKeyLevel(raw []byte, compressed bool) string {
	if !compressed {
		return util.DecodeCountedUTF16LE(raw)
	}
	r := make([]rune, len(raw))
	for i, b := range raw {
		r[i] = rune(b)
	}
	return strings.ReplaceAll(string(r), "\x00", util.VisibleNUL)
}

func (n *nameReader) report(ctx tools.Context) {
	forms := make([]int, 0, formCount)
	for f := range n.unreadable {
		if n.unreadable[f] > 0 {
			forms = append(forms, f)
		}
	}
	sort.Ints(forms)
	for _, f := range forms {
		ctx.AddDiagnostic("%s: %d %s handle names did not read; first: %s", Name, n.unreadable[f], formLabels[f],
			n.examples[f])
	}
}
