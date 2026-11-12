package executionuserassist

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestDecodeCountDataReadsTheLaunchWords(t *testing.T) {
	d, err := DecodeCountData(countData(14, 21, 420000, 0x01db0000aabbccdd))
	if err != nil || d.LaunchCount != 14 || d.LastLaunch != 0x01db0000aabbccdd {
		t.Errorf("%+v %v", d, err)
	}
	for _, n := range []int{0, 16, 71, 73, 1612} {
		if _, err := DecodeCountData(make([]byte, n)); !errors.Is(err, ErrDataLength) {
			t.Errorf("%d bytes: %v, want ErrDataLength", n, err)
		}
	}
}

func TestRot13RotatesLettersOnly(t *testing.T) {
	for in, want := range map[string]string{
		"HRZR_PGYFRFFVBA": "UEME_CTLSESSION",
		`{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\pzq.rkr`: `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe`,
		"Zvpebfbsg.Jvaqbjf.Rkcybere":                     "Microsoft.Windows.Explorer",
		"0123 !-_.\\:{}é":                                "0123 !-_.\\:{}é",
	} {
		if got := rot13(in); got != want {
			t.Errorf("rot13(%q) = %q, want %q", in, got, want)
		}
		if rot13(rot13(in)) != in {
			t.Errorf("rot13 twice changed %q", in)
		}
	}
}

func TestSplitFolderPrefix(t *testing.T) {
	for _, tc := range []struct {
		name, guid, rest string
		ok               bool
	}{
		{`{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe`, "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", `\cmd.exe`, true},
		{`{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}`, "{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}", "", true},
		{`{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}cmd.exe`, "", "", false},
		{`{1AC14E77_02E7-4E5D-B744-2EB1AE5198B7}\x`, "", "", false},
		{`{1AC14E77-02E7-4E5D-B744-2EB1AE5198BG}\x`, "", "", false},
		{`{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7\x`, "", "", false},
		{`C:\x.exe`, "", "", false},
		{"", "", "", false},
	} {
		guid, rest, ok := splitFolderPrefix(tc.name)
		if ok != tc.ok || (ok && (guid != tc.guid || rest != tc.rest)) || (!ok && rest != tc.name) {
			t.Errorf("%q: %q %q %v", tc.name, guid, rest, ok)
		}
	}
}

func TestTheKnownFolderTableIsTheLearnList(t *testing.T) {
	if len(knownFolderTable) != 124 {
		t.Errorf("%d known folders, want the 124 with a GUID", len(knownFolderTable))
	}
	braced := regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)
	guids, ids := map[string]bool{}, map[string]bool{}
	for _, f := range knownFolderTable {
		if !braced.MatchString(f.GUID) || !strings.HasPrefix(f.ID, "FOLDERID_") {
			t.Errorf("%+v", f)
		}
		if guids[f.GUID] || ids[f.ID] {
			t.Errorf("%+v listed twice", f)
		}
		guids[f.GUID], ids[f.ID] = true, true
		if f.Path != "" && !strings.HasPrefix(f.Path, "%") {
			t.Errorf("%s: path %q is not in environment-string form", f.ID, f.Path)
		}
	}
	for id := range wideSystemPaths {
		if !ids[id] {
			t.Errorf("64-bit path for %s, which the table lacks", id)
		}
	}
}

func TestLookupKnownFolder(t *testing.T) {
	for _, tc := range []struct {
		guid string
		wide bool
		id   string
		path string
	}{
		{"{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}", true, "FOLDERID_System", `%windir%\system32`},
		{"{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", false, "FOLDERID_SystemX86", `%windir%\system32`},
		{"{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", true, "FOLDERID_SystemX86", `%windir%\syswow64`},
		{"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", false, "FOLDERID_ProgramFilesX86", `%ProgramFiles%`},
		{"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", true, "FOLDERID_ProgramFilesX86", `%SystemDrive%\Program Files (x86)`},
		{"{DE974D24-D9C6-4D3E-BF91-F4455120B917}", true, "FOLDERID_ProgramFilesCommonX86", `%ProgramFiles(x86)%\Common Files`},
		{"{6D809377-6AF0-444B-8957-A3773F02200E}", true, "FOLDERID_ProgramFilesX64", `%ProgramFiles%`},
		{"{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", true, "FOLDERID_UserPinned",
			`%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned`},
		{"{F38BF404-1D43-42F2-9305-67DE0B28FC23}", true, "FOLDERID_Windows", `%windir%`},
		{"{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", true, "FOLDERID_CommonPrograms",
			`%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs`},
	} {
		f, ok := LookupKnownFolder(tc.guid, tc.wide)
		if !ok || f.ID != tc.id || f.Path != tc.path {
			t.Errorf("%s wide %v: %+v %v", tc.guid, tc.wide, f, ok)
		}
	}
	if _, ok := LookupKnownFolder("{00000000-0000-0000-0000-000000000000}", true); ok {
		t.Error("an unlisted GUID was found")
	}
}
