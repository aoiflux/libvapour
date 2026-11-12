//go:build windows

package ownerfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const localSystem = "S-1-5-18"

// The process token's user, not CREATOR OWNER: in an elevated process the
// creator owner would be the Administrators group.
func currentUser() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("ownerfile: process token user: %w", err)
	}
	return u.User.Sid.String(), nil
}

// A protected list (P) inherits nothing from the parent. The user and the
// operating system's own account get full access; a directory passes both
// entries on to what is created inside it (OI, CI).
func privateDescriptor(container bool) (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := currentUser()
	if err != nil {
		return nil, err
	}
	flags := ""
	if container {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("O:%[1]sD:P(A;%[2]s;FA;;;%[1]s)(A;%[2]s;FA;;;SY)", user, flags)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("ownerfile: private security descriptor: %w", err)
	}
	return sd, nil
}

func securityAttributes(sd *windows.SECURITY_DESCRIPTOR) *windows.SecurityAttributes {
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa
}

func openHandle(path string, access, disposition, flags uint32, sa *windows.SecurityAttributes) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, disposition, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// FILE_FLAG_OPEN_REPARSE_POINT makes a link at path count as an existing file,
// so CREATE_NEW refuses it instead of creating the link's target.
func createNew(path string) (*os.File, error) {
	sd, err := privateDescriptor(false)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return openHandle(path, windows.GENERIC_WRITE, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, securityAttributes(sd))
}

// CreateFile ignores the descriptor when the file already exists, so an
// existing file gets the private list through its handle before it is
// truncated. A device (such as NUL) is shared by every account and is opened
// as it is.
func create(path string) (*os.File, error) {
	if info, err := os.Stat(path); err == nil && !info.Mode().IsRegular() && !info.IsDir() {
		return os.OpenFile(path, os.O_WRONLY, 0)
	}
	f, err := createNew(path)
	if !errors.Is(err, os.ErrExist) {
		return f, err
	}
	sd, err := privateDescriptor(false)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f, err = openHandle(path, windows.GENERIC_WRITE|windows.WRITE_DAC, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, nil)
	if err != nil {
		return nil, err
	}
	if err := applyPrivateList(windows.Handle(f.Fd()), sd); err != nil {
		f.Close()
		return nil, &os.PathError{Op: "restrict", Path: path, Err: err}
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func applyPrivateList(h windows.Handle, sd *windows.SECURITY_DESCRIPTOR) error {
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// Directories that already exist are left as they are; each missing one, from
// the outermost down, is created with the private list.
func mkdirAll(dir string) error {
	var missing []string
	for p := filepath.Clean(dir); ; {
		info, err := os.Stat(p)
		if err == nil {
			if !info.IsDir() {
				return &os.PathError{Op: "mkdir", Path: p, Err: syscall.ENOTDIR}
			}
			break
		}
		missing = append(missing, p)
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	if len(missing) == 0 {
		return nil
	}
	sd, err := privateDescriptor(true)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	sa := securityAttributes(sd)
	for i := len(missing) - 1; i >= 0; i-- {
		p := missing[i]
		name, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return &os.PathError{Op: "mkdir", Path: p, Err: err}
		}
		if err := windows.CreateDirectory(name, sa); err != nil {
			if info, statErr := os.Lstat(p); statErr == nil && info.IsDir() {
				continue
			}
			return &os.PathError{Op: "mkdir", Path: p, Err: err}
		}
	}
	return nil
}

// Private means no access-allowed entry for anyone but the user and the
// system account. A missing (null) list grants everyone everything. Deny
// entries take access away and are fine; any other entry kind is not vouched
// for.
func isPrivate(path string) (bool, error) {
	user, err := currentUser()
	if err != nil {
		return false, err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String(); sid != user && sid != localSystem {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	return true, nil
}
