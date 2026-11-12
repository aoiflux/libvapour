package syscallstub

import "strings"

// Microsoft Defender Antivirus runs from its platform folder or, before
// platform updates, its program folder (S29 F6, M6). A process cannot choose
// the path of its own image file, so the mark rests on that path.
var defenderFolders = []string{
	`\program files\windows defender\`,
	`\programdata\microsoft\windows defender\platform\`,
}

func isDefenderPath(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	for _, folder := range defenderFolders {
		if strings.Contains(p, folder) {
			return true
		}
	}
	return false
}
