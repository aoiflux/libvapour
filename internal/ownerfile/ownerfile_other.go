//go:build !windows

package ownerfile

import "os"

const (
	privateFile os.FileMode = 0o600
	privateDir  os.FileMode = 0o700
	othersBits  os.FileMode = 0o077
)

// O_EXCL also refuses a symbolic link at path, so a planted link cannot
// redirect the write.
func createNew(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFile)
}

// O_CREAT applies the mode only to a new file, so an existing regular file is
// narrowed afterwards. A device keeps its mode: narrowing a shared one such as
// /dev/null as root would break it for every user.
func create(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, privateFile)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && info.Mode().IsRegular() && info.Mode().Perm() != privateFile {
		err = f.Chmod(privateFile)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func mkdirAll(dir string) error { return os.MkdirAll(dir, privateDir) }

func isPrivate(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Mode().Perm()&othersBits == 0, nil
}
