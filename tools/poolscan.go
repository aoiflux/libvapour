package tools

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/scan"
)

func (c Context) HasObjectHeaderCookie() bool {
	if c.Symbols == nil {
		return false
	}
	_, err := c.Symbols.LookupSymbol("ObHeaderCookie")
	return err == nil
}

// A missing residency or identity weakens a check but does not stop the
// scan; each gap gets a diagnostic, since a silently skipped check would
// read as a clean result.
func (c Context) StructureScan(tool string, filters ...scan.PoolFilter) (scan.PoolHeaderLayout, error) {
	if err := c.RequirePoolScanBuild(tool); err != nil {
		return scan.PoolHeaderLayout{}, err
	}
	layout, err := scan.ResolvePoolHeaderLayout(c.Symbols)
	if err != nil {
		return scan.PoolHeaderLayout{}, fmt.Errorf("%s: pool header layout: %w", tool, err)
	}
	for _, f := range filters {
		if err := c.checkMinimum(tool, layout.MinimumSize, f); err != nil {
			return scan.PoolHeaderLayout{}, err
		}
	}
	if frames := c.residency(tool, "duplicate allocations are not ranked by kernel mapping"); frames != nil {
		layout = layout.WithResidency(frames)
	}
	return layout, nil
}

func (c Context) ExecutiveScan(tool string, filter scan.PoolFilter, tag scan.TypeTag) (scan.ObjectLayout, scan.ObjectIdentity, error) {
	if err := c.RequirePoolScanBuild(tool); err != nil {
		return scan.ObjectLayout{}, scan.ObjectIdentity{}, err
	}
	layout, err := scan.ResolveObjectLayout(c.Symbols)
	if err != nil {
		return scan.ObjectLayout{}, scan.ObjectIdentity{}, fmt.Errorf("%s: object layout: %w", tool, err)
	}
	if err := c.checkMinimum(tool, layout.MinimumSize, filter); err != nil {
		return scan.ObjectLayout{}, scan.ObjectIdentity{}, err
	}
	if frames := c.residency(tool, "duplicate allocations are not ranked by kernel mapping "+
		"and the TypeIndex test by address is skipped"); frames != nil {
		layout = layout.WithResidency(frames)
	}
	identity, err := scan.ResolveObjectIdentity(c.Symbols, c.Memory, filter, tag)
	if err != nil {
		c.AddDiagnostic("%s: object identity: %v; matching on the body type tag only", tool, err)
	}
	return layout, identity, nil
}

func (c Context) checkMinimum(tool string, minimum func(scan.PoolFilter) (uint64, error), f scan.PoolFilter) error {
	if _, err := minimum(f); err != nil {
		err = fmt.Errorf("%s: pool tag %q: %w", tool, f.Tag, err)
		c.AddDiagnostic("%v; pool scan not run", err)
		return err
	}
	return nil
}

// Nil when the map cannot be built, so the caller never attaches a typed nil.
func (c Context) residency(tool, without string) *layers.FrameMap {
	frames, err := c.KernelFrames()
	if err == nil && frames == nil {
		err = errors.New("tools: kernel frames: no map")
	}
	if err != nil {
		c.AddDiagnostic("%s: %v; %s", tool, err, without)
		return nil
	}
	if frames.UnreadableTables > 0 {
		c.AddDiagnostic("%s: %d kernel page tables unreadable; frames reached only through them count as "+
			"unmapped, so for those %s", tool, frames.UnreadableTables, without)
	}
	if frames.PartialLargePages > 0 {
		c.AddDiagnostic("%s: %d kernel large pages only partly in the image; their frames count as unmapped",
			tool, frames.PartialLargePages)
	}
	return frames
}
