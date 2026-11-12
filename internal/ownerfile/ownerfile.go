// Output files can hold credentials and memory contents, so each file and
// directory is made readable by its owner alone from the moment it exists.
// POSIX does this with the mode given to open and mkdir. On Windows a Go mode
// only sets the read-only attribute and a new file takes its parent's access
// list, so the access list is passed to the call that creates the object.
package ownerfile

import "os"

func CreateNew(path string) (*os.File, error) { return createNew(path) }

func Create(path string) (*os.File, error) { return create(path) }

func MkdirAll(dir string) error { return mkdirAll(dir) }

func IsPrivate(path string) (bool, error) { return isPrivate(path) }
