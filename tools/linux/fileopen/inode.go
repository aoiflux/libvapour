package fileopen

import "github.com/aoiflux/libvapour/tools/linuxobj"

// The stat facts are taken whole or not at all, so a row never mixes a read
// device with an inode whose other members did not read.
func (l *lister) inode(file uint64, row *File) error {
	k := l.k
	inode, held, err := k.FileInode(file)
	if err != nil {
		return l.failed(&l.lost.inodes, "file", file, "f_inode", err)
	}
	if !held {
		return nil
	}
	facts, err := l.stat(inode)
	if err != nil {
		return l.failed(&l.lost.inodes, "inode", inode, "stat facts", err)
	}
	facts.copyTo(row)
	return nil
}

type statFacts struct {
	device   string
	deviceOK bool
	number   uint64
	kind     string
	kindOK   bool
	mode     string
	times    linuxobj.InodeTimes
	size     int64
}

func (s statFacts) copyTo(row *File) {
	row.InodeOK = true
	row.Device, row.DeviceOK = s.device, s.deviceOK
	row.Inode = s.number
	row.Type, row.TypeOK = s.kind, s.kindOK
	row.Mode = s.mode
	row.Changed, row.ChangedOK = s.times.Changed, s.times.ChangedOK
	row.Modified, row.ModifiedOK = s.times.Modified, s.times.ModifiedOK
	row.Accessed, row.AccessedOK = s.times.Accessed, s.times.AccessedOK
	row.Size = s.size
}

func (l *lister) stat(inode uint64) (statFacts, error) {
	k := l.k
	var s statFacts
	sb, held, err := k.Deref(k.Memory(), inode, "inode", "i_sb")
	if err != nil {
		return s, err
	}
	if held {
		if s.device, err = k.SuperBlockDeviceString(sb); err != nil {
			return s, err
		}
		s.deviceOK = true
	}
	if s.number, err = k.Uint(k.Memory(), inode, "inode", "i_ino"); err != nil {
		return s, err
	}
	mode, err := k.InodeMode(inode)
	if err != nil {
		return s, err
	}
	s.kind, s.kindOK = linuxobj.InodeType(mode)
	s.mode = linuxobj.FileMode(mode)
	if s.times, err = k.InodeTimes(inode); err != nil {
		return s, err
	}
	s.size, err = k.InodeSize(inode)
	return s, err
}
