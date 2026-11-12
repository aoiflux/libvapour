package executionuserassist

import "strings"

type KnownFolder struct {
	GUID string
	ID   string
	Path string
}

// The Default Path column gives the 32-bit view; the KNOWNFOLDERID Remarks
// table gives these three for a 64-bit application on a 64-bit system.
var wideSystemPaths = map[string]string{
	"FOLDERID_ProgramFilesX86":       `%SystemDrive%\Program Files (x86)`,
	"FOLDERID_ProgramFilesCommonX86": `%ProgramFiles(x86)%\Common Files`,
	"FOLDERID_SystemX86":             `%windir%\syswow64`,
}

var knownFolderIndex = func() map[string]KnownFolder {
	m := make(map[string]KnownFolder, len(knownFolderTable))
	for _, f := range knownFolderTable {
		m[f.GUID] = f
	}
	return m
}()

func LookupKnownFolder(guid string, wide bool) (KnownFolder, bool) {
	f, ok := knownFolderIndex[strings.ToUpper(guid)]
	if !ok {
		return KnownFolder{}, false
	}
	if p, override := wideSystemPaths[f.ID]; override && wide {
		f.Path = p
	}
	return f, true
}

const guidTextLen = len("{00000000-0000-0000-0000-000000000000}")

// The rest keeps its leading backslash, so prefix + rest is the name again.
func splitFolderPrefix(name string) (guid, rest string, ok bool) {
	if len(name) < guidTextLen || name[0] != '{' || name[guidTextLen-1] != '}' {
		return "", name, false
	}
	for i := 1; i < guidTextLen-1; i++ {
		c := name[i]
		switch i {
		case 9, 14, 19, 24:
			if c != '-' {
				return "", name, false
			}
		default:
			if !isHex(c) {
				return "", name, false
			}
		}
	}
	rest = name[guidTextLen:]
	if rest != "" && rest[0] != '\\' {
		return "", name, false
	}
	return name[:guidTextLen], rest, true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
