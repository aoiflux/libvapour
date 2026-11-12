package mountlist

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools/linuxobj"
)

var (
	ErrNoMountRoot  = errors.New("mountlist: mnt_root is null")
	ErrNoSuperBlock = errors.New("mountlist: mnt_sb is null")
)

// record gives the mountinfo line of one mount as the reader at root would
// see it; shown is false when the mount lies outside that root, where the
// kernel skips the line.
func (l *lister) record(mnt uint64, root linuxobj.PathPoint) (Mount, bool, error) {
	k := l.k
	m := Mount{MountAddress: k.Canonical(mnt)}
	dentry, err := k.MountRoot(mnt)
	if err != nil {
		return m, false, err
	}
	if dentry == 0 {
		return m, false, ErrNoMountRoot
	}
	walked, err := k.WalkPath(linuxobj.PathPoint{Mount: k.Canonical(mnt), Dentry: dentry}, root)
	if err != nil {
		return m, false, fmt.Errorf("mount point: %w", err)
	}
	if walked.End != linuxobj.EndAtRoot {
		return m, false, nil
	}
	m.MountPoint = walked.Text
	if m.Root, err = k.DentryPath(dentry); err != nil {
		return m, false, fmt.Errorf("root: %w", err)
	}
	if m.MountID, err = k.MountID(mnt); err != nil {
		return m, false, err
	}
	parent, err := k.MountParent(mnt)
	if err != nil {
		return m, false, err
	}
	if m.ParentID, err = k.MountID(parent); err != nil {
		return m, false, fmt.Errorf("parent: %w", err)
	}
	sb, err := k.MountSuperBlock(mnt)
	if err != nil {
		return m, false, err
	}
	if sb == 0 {
		return m, false, ErrNoSuperBlock
	}
	if m.MajorMinor, err = k.SuperBlockDeviceString(sb); err != nil {
		return m, false, err
	}
	flags, err := k.MountFlags(mnt)
	if err != nil {
		return m, false, err
	}
	access, mountOpts := linuxobj.MountFlagStrings(flags)
	m.MountOptions = strings.Join(append([]string{access}, mountOpts...), ",")
	if m.Fields, err = l.tags(mnt, flags, root); err != nil {
		return m, false, err
	}
	if m.FSType, m.FSTypeOK, err = k.SuperBlockType(sb); err != nil {
		return m, false, err
	}
	if m.MountSource, err = k.MountDevname(mnt); err != nil {
		return m, false, err
	}
	if m.MountSource == "" {
		m.MountSource = "none"
	}
	sbAccess, sbOpts, err := k.SuperBlockFlags(sb)
	if err != nil {
		return m, false, err
	}
	m.SBOptions = strings.Join(append([]string{sbAccess}, sbOpts...), ",")
	if l.mountsForm {
		m.MountFormat = true
		m.MntOpts = mountsOptions(access == "ro" || sbAccess == "ro", sbOpts, mountOpts)
	}
	return m, true, nil
}

// mountsOptions is the option column of /proc/<pid>/mounts: one access word
// for the mount and its superblock together, then the superblock's options,
// then the mount's.
func mountsOptions(readOnly bool, sbOpts, mountOpts []string) string {
	words := []string{"rw"}
	if readOnly {
		words[0] = "ro"
	}
	words = append(words, sbOpts...)
	return strings.Join(append(words, mountOpts...), ",")
}

func (l *lister) tags(mnt uint64, flags int64, root linuxobj.PathPoint) (string, error) {
	k := l.k
	shared, unbindable, err := k.MountPropagation(mnt, flags)
	if err != nil {
		return "", err
	}
	var tags []string
	if shared {
		group, err := k.MountGroupID(mnt)
		if err != nil {
			return "", err
		}
		tags = append(tags, fmt.Sprintf("shared:%d", group))
	}
	master, err := k.MountMaster(mnt)
	if err != nil {
		return "", err
	}
	if master != 0 {
		group, err := k.MountGroupID(master)
		if err != nil {
			return "", fmt.Errorf("master: %w", err)
		}
		tags = append(tags, fmt.Sprintf("master:%d", group))
		from, err := k.DominatingID(mnt, root)
		if err != nil {
			return "", fmt.Errorf("dominating peer group: %w", err)
		}
		if from != 0 && from != group {
			tags = append(tags, fmt.Sprintf("propagate_from:%d", from))
		}
	}
	if unbindable {
		tags = append(tags, "unbindable")
	}
	return strings.Join(tags, " "), nil
}
