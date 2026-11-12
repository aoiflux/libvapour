package threadsuspicious

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/windows/threadaddress"
	"github.com/aoiflux/libvapour/tools/windows/threadlist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.thread.find_suspicious"

var ErrSystemFlagUnread = errors.New("threadsuspicious: system-thread flag does not read")

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "Report user threads whose start address lies in private memory, in a mapped data file, " +
				"or in no range of their process",
		},
		RunAny,
	)
}

type Finding string

const (
	FindingStartUnmapped   Finding = "start_unmapped"
	FindingStartPrivate    Finding = "start_in_private_memory"
	FindingStartMappedFile Finding = "start_in_mapped_file"
)

type AddressKind string

const (
	AddressStart      AddressKind = "start"
	AddressWin32Start AddressKind = "win32_start"
)

type Thread struct {
	PID         uint64
	Process     string
	TID         uint64
	ETHREAD     uint64
	State       string
	AddressKind AddressKind
	Address     uint64
	Finding     Finding
	RangeStart  uint64
	RangeEnd    uint64
	RangeType   string
	Protection  string
	Path        string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type sources struct {
	threads func(tools.Context) ([]threadlist.Thread, error)
	spaces  func(tools.Context) (*threadaddress.Spaces, error)
}

var defaultSources = sources{threads: threadlist.Run, spaces: threadaddress.New}

func Run(ctx tools.Context) ([]Thread, error) { return run(ctx, defaultSources) }

type tally map[string]int

func (t tally) String() string {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", t[k], k))
	}
	return strings.Join(parts, ", ")
}

func run(ctx tools.Context, src sources) ([]Thread, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	threads, err := src.threads(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: thread list: %w", Name, err)
	}
	spaces, err := src.spaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process ranges: %w", Name, err)
	}
	system := threadaddress.ResolveSystemThread(ctx.Symbols)
	failed := map[uint64]bool{}
	skipped := tally{}
	addresses := tally{}
	var rows []Thread
	for _, th := range threads {
		isSystem, err := threadaddress.IsSystemThread(system, ctx.Memory, th.ETHREAD, th.PID)
		if err != nil {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: thread %d at 0x%x: %w: %w", Name, th.TID, th.ETHREAD, ErrSystemFlagUnread, err)
			}
			skipped["system-thread flag unread"]++
			continue
		}
		if isSystem {
			skipped["system thread"]++
			continue
		}
		if th.ProcessUnreadable {
			skipped["owner unread"]++
			continue
		}
		if _, ok := spaces.Owner(th.Process); !ok {
			skipped["owner not listed"]++
			continue
		}
		ranges, err := spaces.Ranges(ctx, th.Process)
		if err != nil {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: process at 0x%x: range walk failed: %w", Name, th.Process, err)
			}
			if !failed[th.Process] {
				failed[th.Process] = true
				ctx.AddDiagnostic("%s: process at 0x%x: range walk failed: %v", Name, th.Process, err)
			}
			skipped["range walk failed"]++
			continue
		}
		if len(ranges) == 0 {
			skipped["owner has no ranges"]++
			continue
		}
		short := spaces.Short(ctx, th.Process, len(ranges))
		for _, a := range []struct {
			kind    AddressKind
			address uint64
			unread  bool
		}{
			{AddressStart, th.StartAddress, th.StartAddressUnreadable},
			{AddressWin32Start, th.Win32StartAddress, th.Win32StartAddressUnreadable},
		} {
			switch {
			case a.unread:
				addresses["unread"]++
				continue
			case a.address == 0:
				addresses["zero"]++
				continue
			case !threadaddress.UserAddress(ctx.Symbols.PointerSize(), a.address):
				addresses["not a user address"]++
				continue
			}
			finding, r, why := judge(ranges, a.address, short)
			if finding == "" {
				addresses[why]++
				continue
			}
			addresses["found"]++
			rows = append(rows, Thread{PID: th.PID, Process: util.ReplaceInvalidUTF8(th.ProcessName), TID: th.TID,
				ETHREAD: th.ETHREAD, State: th.StateName, AddressKind: a.kind, Address: a.address, Finding: finding,
				RangeStart: r.Start, RangeEnd: r.End, RangeType: r.Type, Protection: r.Protection, Path: r.Path})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		if a.TID != b.TID {
			return a.TID < b.TID
		}
		return a.AddressKind == AddressStart && b.AddressKind != AddressStart
	})
	ctx.AddDiagnostic("%s: %d threads; not examined: %s; addresses: %s", Name, len(threads), skipped, addresses)
	return rows, nil
}

// why names the outcome when there is no finding, for the run summary.
func judge(ranges []memoryranges.Mapping, address uint64, short bool) (f Finding, r threadaddress.Range, why string) {
	r, ok := threadaddress.Holding(ranges, address)
	if !ok {
		if short {
			return "", r, "in no range of a short walk"
		}
		return FindingStartUnmapped, threadaddress.Range{}, ""
	}
	switch r.Type {
	case memoryranges.KindImage:
		return "", r, "in an image"
	case memoryranges.KindPrivate:
		return FindingStartPrivate, r, ""
	case memoryranges.KindMapped:
		return FindingStartMappedFile, r, ""
	}
	return "", r, "in a range of unknown kind"
}
