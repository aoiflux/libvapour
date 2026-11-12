package libvapour

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
)

var (
	errOtherKernelBuild = errors.New("libvapour: the symbols are for another kernel build")
	errBaseUnconfirmed  = errors.New("libvapour: the kernel build was chosen among several and no kernel base confirms it")
)

const methodTableOwnBuild autoload.KernelMethod = "build the symbol table names"

// A PDB places a symbol at an RVA, at most 0xFFFFFFFF (S32 4.4 step 5).
func isRVA(address uint64) bool { return address <= math.MaxUint32 }

// The list-head method moves PsActiveProcessHead (S53 4.9), so a table that
// places it at an RVA needs the kernel base; one that places it in the kernel
// half was written for a known base.
func needsKernelBase(table symbols.SymbolTable) bool {
	head, err := table.LookupSymbol("PsActiveProcessHead")
	return err == nil && isRVA(head.Address)
}

func sameBuild(a, b autoload.Fingerprint) bool {
	if a.PDBName != "" && b.PDBName != "" && !strings.EqualFold(a.PDBName, b.PDBName) {
		return false
	}
	return strings.EqualFold(a.GUID, b.GUID) && a.Age == b.Age
}

func pdbBaseName(path string) string {
	return path[strings.LastIndexAny(path, `\/`)+1:]
}

// The running kernel decides (S76 4.2): a table for any other build would
// answer every name with offsets from that other build.
func explicitTableKernel(table *symbols.Table, running *autoload.KernelIdentity, runErr error) (*autoload.KernelIdentity, string, error) {
	build, named := table.WindowsPDB()
	own := autoload.Fingerprint{PDBName: build.Database, GUID: build.GUID, Age: build.Age}
	why := "the capture names no running kernel"
	if runErr != nil {
		why = runErr.Error()
	}
	switch {
	case running != nil && named:
		if !sameBuild(own, running.Fingerprint) {
			return nil, "", fmt.Errorf("%w: the table is for %s, the running kernel is %s from the %s",
				errOtherKernelBuild, build, running.Fingerprint, running.Method)
		}
		return running, "", nil
	case running != nil:
		return running, fmt.Sprintf("names no kernel build, so it was not checked against the running kernel %s", running.Fingerprint), nil
	case named:
		return &autoload.KernelIdentity{Fingerprint: own, Method: methodTableOwnBuild},
			fmt.Sprintf("names %s, which the capture could not confirm (%s); the kernel base is checked against it", build, why), nil
	default:
		return nil, fmt.Sprintf("names no kernel build and %s, so its symbols stay at their RVAs", why), nil
	}
}

type baseCandidate struct {
	from string
	find func() (uint64, error)
}

type kernelBase struct {
	address   uint64
	from      string
	confirmed bool
	unread    error
	tried     []string
}

// A candidate is confirmed when its CodeView record names the build the
// symbols are for. A record naming another kernel build refuses the session:
// the running kernel is found and the symbols are not its own. A header whose
// record does not read is kept as an unconfirmed answer, except for a build
// the scan chose among several (S75 4.4 step 3), which must be confirmed.
func findKernelBase(space memory.MemoryReader, id *autoload.KernelIdentity, candidates []baseCandidate) (kernelBase, error) {
	var tried []string
	var unconfirmed *kernelBase
	for _, c := range candidates {
		address, err := c.find()
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s: %v", c.from, err))
			continue
		}
		records, err := layers.ImageCodeViews(space, address)
		if err == nil && len(records) == 0 {
			err = errors.New("no codeview record")
		}
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s: 0x%x: %v", c.from, address, err))
			if unconfirmed == nil {
				unconfirmed = &kernelBase{address: address, from: c.from, unread: err}
			}
			continue
		}
		var other []string
		for _, r := range records {
			fp := autoload.Fingerprint{PDBName: pdbBaseName(r.PDBPath), GUID: autoload.FormatGUID(r.GUID[:]), Age: r.Age}
			if sameBuild(fp, id.Fingerprint) {
				return kernelBase{address: address, from: c.from, confirmed: true, tried: tried}, nil
			}
			if autoload.IsKernelPDB(fp.PDBName) {
				return kernelBase{}, fmt.Errorf("%w: the kernel image at 0x%x from %s is %s, the symbols are for %s from the %s",
					errOtherKernelBuild, address, c.from, fp, id.Fingerprint, id.Method)
			}
			other = append(other, fp.String())
		}
		tried = append(tried, fmt.Sprintf("%s: 0x%x is %s, not a kernel", c.from, address, strings.Join(other, ", ")))
	}
	if id.Provisional {
		return kernelBase{}, fmt.Errorf("%w: %s (tried: %s)", errBaseUnconfirmed, id.Fingerprint, strings.Join(tried, "; "))
	}
	if unconfirmed != nil {
		unconfirmed.tried = tried
		return *unconfirmed, nil
	}
	return kernelBase{tried: tried}, nil
}
