//go:build windows

package ownerfile_test

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/aoiflux/libvapour/internal/ownerfile"
	"github.com/aoiflux/libvapour/internal/ownerfile/ownerfiletest"
)

func currentUser(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

// FILE_ALL_ACCESS, which SDDL "FA" stands for.
const fileAllAccess = 0x1F01FF

type entry struct {
	kind  byte
	flags byte
	mask  uint32
	sid   string
}

func entries(t *testing.T, path string) (windows.SECURITY_DESCRIPTOR_CONTROL, string, []entry) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: no access list (%v)", path, err)
	}
	var out []entry
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		out = append(out, entry{ace.Header.AceType, ace.Header.AceFlags, uint32(ace.Mask),
			(*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()})
	}
	return control, owner.String(), out
}

func TestTheListIsProtectedOwnedAndForUserAndSystemOnly(t *testing.T) {
	user := currentUser(t)
	dir := ownerfiletest.LooseDir(t)
	sub := filepath.Join(dir, "sub")
	if err := ownerfile.MkdirAll(sub); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sub, "out.bin")
	write(t, ownerfile.CreateNew, file, "x")
	earlier := filepath.Join(dir, "earlier")
	if err := os.WriteFile(earlier, []byte("e"), 0o644); err != nil {
		t.Fatal(err)
	}
	write(t, ownerfile.Create, earlier, "f")

	const inherit = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	for path, wantFlags := range map[string]byte{sub: inherit, file: 0, earlier: 0} {
		control, owner, list := entries(t, path)
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Errorf("%s: list not protected", path)
		}
		if path != earlier && owner != user {
			t.Errorf("%s: owner %s, want %s", path, owner, user)
		}
		sids := map[string]bool{}
		for _, e := range list {
			if e.kind != windows.ACCESS_ALLOWED_ACE_TYPE || e.mask&fileAllAccess != fileAllAccess {
				t.Errorf("%s: entry %+v", path, e)
			}
			if e.flags&^windows.INHERITED_ACE != wantFlags {
				t.Errorf("%s: entry flags %#x, want %#x", path, e.flags, wantFlags)
			}
			sids[e.sid] = true
		}
		if len(list) != 2 || !sids[user] || !sids["S-1-5-18"] {
			t.Errorf("%s: entries %+v", path, list)
		}
	}
}

func setList(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestIsPrivateVouchesOnlyForUserAndSystemGrants(t *testing.T) {
	user := currentUser(t)
	file := filepath.Join(t.TempDir(), "f")
	write(t, ownerfile.CreateNew, file, "x")
	for _, c := range []struct {
		sddl string
		want bool
	}{
		{"D:P(A;;FA;;;" + user + ")", true},
		{"D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)", true},
		{"D:P(A;;FA;;;" + user + ")(D;;FA;;;WD)", true},
		{"D:P(A;;FA;;;" + user + ")(A;;FR;;;WD)", false},
		{"D:P(A;;FA;;;" + user + ")(A;;FR;;;BU)", false},
		{"D:P(A;;FA;;;" + user + ")(A;;FA;;;BA)", false},
	} {
		setList(t, file, c.sddl)
		if got, err := ownerfile.IsPrivate(file); err != nil || got != c.want {
			t.Errorf("%s: %v %v, want %v", c.sddl, got, err, c.want)
		}
	}
	setList(t, file, "D:P(A;;FA;;;"+user+")")
}
