package servicerecord

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

const (
	Name        = "windows.service.scan"
	ListName    = "windows.service.list"
	CompareName = "windows.service.compare"
)

var (
	ErrNoServicesProcess     = errors.New("servicerecord: no services.exe process")
	ErrPointerSize           = errors.New("servicerecord: only 64-bit services.exe is measured")
	ErrNoServiceRecords      = errors.New("servicerecord: no measured record layout fits services.exe memory")
	ErrLayoutAmbiguous       = errors.New("servicerecord: two record layouts fit equally")
	ErrUnmeasuredBuild       = errors.New("servicerecord: build not measured for this layout")
	ErrNoServiceList         = errors.New("servicerecord: no service database head in services.exe")
	ErrServiceListIncomplete = errors.New("servicerecord: service list walk stopped before its end")

	errNoPDBLoader = errors.New("servicerecord: no PDB loader")
	errNoImage     = errors.New("servicerecord: services.exe image not located")
)

type Service struct {
	RecordAddress uint64
	SCMProcessID  uint64
	Listed        bool
	Finding       Finding

	Sequence     uint32
	ServiceName  string
	DisplayName  string
	ServiceType  ServiceType
	CurrentState CurrentState
	StartType    StartType
	ErrorControl ErrorControl

	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32

	ProcessID        uint32
	ImagePath        string
	DriverObjectName string

	RegistryKeyFound   bool
	RegistryImagePath  string
	RegistryServiceDll string

	DisplayNameUnreadable      bool
	ProcessIDUnreadable        bool
	ImagePathUnreadable        bool
	DriverObjectNameUnreadable bool
	RegistryUnreadable         bool
}

func init() {
	tools.MustRegister(tools.Spec{
		Name:        Name,
		Description: "Find service records in services.exe private memory: each service's state, type, process and binary, with its registry ImagePath and ServiceDll",
	}, RunAny)
	tools.MustRegister(tools.Spec{
		Name:        ListName,
		Description: "Walk the service control manager's own list of service records in services.exe",
	}, RunListAny)
	tools.MustRegister(tools.Spec{
		Name:        CompareName,
		Description: "Compare the service records in services.exe memory with the SCM's list and the registry Services keys: unlinked records, records without a key, keys without a record",
	}, RunCompareAny)
}

func RunAny(ctx tools.Context) (any, error)        { return Run(ctx) }
func RunListAny(ctx tools.Context) (any, error)    { return List(ctx) }
func RunCompareAny(ctx tools.Context) (any, error) { return Compare(ctx) }

type analysis struct {
	target   target
	fit      fitResult
	fitErr   error
	head     head
	walk     walk
	listErr  error
	registry registryView
}

type options struct {
	scan, list bool
}

func analyse(ctx tools.Context, tool string, opt options) ([]analysis, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	targets, err := findTargets(ctx, tool)
	if err != nil {
		return nil, err
	}
	b := ctx.Bounds()
	registry := readRegistry(ctx, tool)
	if !registry.read() {
		ctx.AddDiagnostic("%s: SYSTEM hive Services key %s", tool, registry.describe())
	}
	out := make([]analysis, 0, len(targets))
	for _, t := range targets {
		a := analysis{target: t, registry: registry}
		if opt.scan {
			c := scanRegions(t.space, t.private, scanBounds{regionBytes: uint64(b.MaxRegionScanBytes), hits: b.MaxMatchesPerChunk})
			for _, cut := range c.cuts {
				ctx.AddDiagnostic("%s: %s pid %d: %s", tool, scmImage, t.pid, cut)
			}
			a.fit = fitLayouts(t.space, c, t.image)
			a.fitErr = a.fit.problem(t)
			if a.fitErr == nil {
				if err := checkBuild(ctx, tool, t, a.fit.layout); err != nil {
					return nil, err
				}
				reportRejections(ctx, tool, t, a.fit)
			}
		}
		if opt.list {
			var only *layout
			if opt.scan && a.fitErr == nil {
				only = &a.fit.layout
			}
			a.head, a.walk, a.listErr = listTarget(ctx, tool, t, only, b.MaxListEntries)
		}
		out = append(out, a)
	}
	return out, nil
}

func (f fitResult) problem(t target) error {
	if len(f.tie) > 0 {
		return fmt.Errorf("%s pid %d: layouts %s and %s: %w", scmImage, t.pid, f.layout.name, strings.Join(f.tie, ", "), ErrLayoutAmbiguous)
	}
	if !f.found() {
		return fmt.Errorf("%s pid %d: %w", scmImage, t.pid, ErrNoServiceRecords)
	}
	return nil
}

func checkBuild(ctx tools.Context, tool string, t target, l layout) error {
	b := winkernel.ReadBuild(tool, ctx.Memory, ctx.Symbols)
	var problem string
	switch {
	case b.KernelErr != nil:
		problem = fmt.Sprintf("build not read (%v)", b.KernelErr)
	default:
		build := winkernel.FileSetBuild(b.Kernel)
		measured := false
		for _, m := range layouts {
			measured = measured || m.build == build
		}
		switch {
		case !measured:
			problem = fmt.Sprintf("build %d not measured", b.Kernel)
		case build != l.build:
			problem = fmt.Sprintf("build %d was measured with another layout", b.Kernel)
		}
	}
	if problem == "" {
		return nil
	}
	err := fmt.Errorf("%s: %s pid %d: %s; layout %s fits: %w", tool, scmImage, t.pid, problem, l.name, ErrUnmeasuredBuild)
	if ctx.StrictMode() {
		return err
	}
	ctx.AddDiagnostic("%v", err)
	return nil
}

func reportRejections(ctx tools.Context, tool string, t target, f fitResult) {
	if len(f.rejected) == 0 {
		return
	}
	reasons := make([]string, 0, len(f.rejected))
	for why, n := range f.rejected {
		reasons = append(reasons, fmt.Sprintf("%s %d", why, n))
	}
	sort.Strings(reasons)
	ctx.AddDiagnostic("%s: %s pid %d: layout %s: %d records kept, tagged candidates rejected: %s",
		tool, scmImage, t.pid, f.layout.name, len(f.records), strings.Join(reasons, ", "))
}

func listTarget(ctx tools.Context, tool string, t target, only *layout, maxEntries int) (head, walk, error) {
	h, err := locateHead(ctx, tool, t)
	if err != nil {
		return head{}, walk{}, err
	}
	w := bestWalk(t.space, h, t.image, maxEntries, only)
	if w.badBackLinks > 0 {
		ctx.AddDiagnostic("%s: service record at 0x%x: previous link is not the record before; %d such records", tool, w.firstBadLink, w.badBackLinks)
	}
	for _, p := range w.headProblems(h) {
		ctx.AddDiagnostic("%s: service database at 0x%x: %s", tool, h.address, p)
	}
	if w.cut != nil {
		err := fmt.Errorf("%s: service record at 0x%x: walk stopped after %d records: %w: %w",
			tool, w.cutAt, len(w.records), ErrServiceListIncomplete, w.cut)
		if ctx.StrictMode() || len(w.records) == 0 {
			return h, w, err
		}
		ctx.AddDiagnostic("%v", err)
	}
	return h, w, nil
}

func locateHead(ctx tools.Context, tool string, t target) (head, error) {
	if t.image.end == 0 {
		return head{}, fmt.Errorf("%s: %s pid %d: %w: %w", tool, scmImage, t.pid, ErrNoServiceList, errNoImage)
	}
	table, err := t.pdb(ctx)
	if err == nil {
		h, herr := pdbHead(t.space, table, t.image)
		if herr == nil {
			return h, nil
		}
		ctx.AddDiagnostic("%s: %s pid %d: PDB head not used, searching the image: %v", tool, scmImage, t.pid, herr)
	} else if !errors.Is(err, errNoPDBLoader) {
		ctx.AddDiagnostic("%s: %s pid %d: services.pdb not loaded, searching the image: %v", tool, scmImage, t.pid, err)
	}
	heads := searchHeads(t.space, t.image)
	switch len(heads) {
	case 1:
		return heads[0], nil
	case 0:
		return head{}, fmt.Errorf("%s: %s pid %d: %w", tool, scmImage, t.pid, ErrNoServiceList)
	}
	return head{}, fmt.Errorf("%s: %s pid %d: %d places hold a head: %w", tool, scmImage, t.pid, len(heads), ErrNoServiceList)
}

func Run(ctx tools.Context) ([]Service, error) {
	all, err := analyse(ctx, Name, options{scan: true, list: true})
	if err != nil {
		return nil, err
	}
	var rows []Service
	var problems []error
	for _, a := range all {
		if a.fitErr != nil {
			problems = append(problems, a.fitErr)
			continue
		}
		listed := a.listedSet()
		if a.listErr != nil {
			ctx.AddDiagnostic("%s: Listed not set: %v", Name, a.listErr)
		}
		for _, rec := range a.fit.records {
			s := a.row(ctx, rec)
			s.Listed = listed[rec.address]
			rows = append(rows, s)
		}
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: %w", Name, errors.Join(problems...))
	}
	for _, p := range problems {
		ctx.AddDiagnostic("%s: %v", Name, p)
	}
	ctx.AddDiagnostic("%s: %d service records", Name, len(rows))
	return rows, nil
}

func List(ctx tools.Context) ([]Service, error) {
	all, err := analyse(ctx, ListName, options{list: true})
	if err != nil {
		return nil, err
	}
	var rows []Service
	var problems []error
	for _, a := range all {
		if a.listErr != nil {
			if ctx.StrictMode() {
				return nil, a.listErr
			}
			problems = append(problems, a.listErr)
		}
		for _, rec := range a.walk.records {
			s := a.rowWith(ctx, rec, a.walk.layout)
			s.Listed = true
			rows = append(rows, s)
		}
	}
	if len(rows) == 0 {
		if len(problems) == 0 {
			problems = append(problems, ErrNoServiceList)
		}
		return nil, errors.Join(problems...)
	}
	for _, p := range problems {
		ctx.AddDiagnostic("%v", p)
	}
	ctx.AddDiagnostic("%s: %d services listed", ListName, len(rows))
	return rows, nil
}

func (a analysis) listedSet() map[uint64]bool {
	out := make(map[uint64]bool, len(a.walk.records))
	if a.listErr != nil || a.walk.cut != nil {
		return out
	}
	for _, rec := range a.walk.records {
		out[rec.address] = true
	}
	return out
}

func (a analysis) row(ctx tools.Context, rec record) Service {
	return a.rowWith(ctx, rec, a.fit.layout)
}

func (a analysis) rowWith(ctx tools.Context, rec record, l layout) Service {
	s := Service{
		RecordAddress: rec.address, SCMProcessID: a.target.pid, Sequence: rec.sequence,
		ServiceName: rec.name, DisplayName: rec.display, DisplayNameUnreadable: rec.displayUnreadable,
		ServiceType: serviceTypeOf(rec.status.serviceType), CurrentState: currentStateOf(rec.status.currentState),
		StartType: startTypeOf(rec.startType), ErrorControl: errorControlOf(rec.errorControl),
		ControlsAccepted: rec.status.controlsAccepted, Win32ExitCode: rec.status.win32ExitCode,
		ServiceSpecificExitCode: rec.status.serviceSpecificExitCode,
	}
	maxUnits := int(ctx.Bounds().MaxNameBytes / 2)
	hostOrDriver(a.target.space, l, rec, maxUnits, &s)
	a.joinRegistry(&s)
	return s
}

var driverDirectories = []string{`\Driver\`, `\FileSystem\`}

// S34 4.6 steps 3 and 4.
func hostOrDriver(r memory.MemoryReader, l layout, rec record, maxUnits int, s *Service) {
	p := rec.processOrDriver
	switch t := rec.status.serviceType; {
	case t&typeWin32 != 0:
		if rec.status.currentState == stateStopped {
			return
		}
		if tag, ok := readUint32(r, p); p == 0 || !ok || tag != tagImage {
			s.ProcessIDUnreadable, s.ImagePathUnreadable = true, true
			return
		}
		pid, ok := readUint32(r, p+l.imageProcessID)
		s.ProcessID, s.ProcessIDUnreadable = pid, !ok
		line, ok := readPointer(r, p+imageCommandLine)
		if ok {
			s.ImagePath, ok = readUTF16(r, line, maxUnits)
		}
		s.ImagePathUnreadable = !ok
	case t&typeDriver != 0:
		if p == 0 {
			return
		}
		name, ok := readUTF16(r, p, maxUnits)
		if ok && hasDriverDirectory(name) {
			s.DriverObjectName = name
			return
		}
		s.DriverObjectNameUnreadable = true
	}
}

func hasDriverDirectory(name string) bool {
	for _, d := range driverDirectories {
		if len(name) > len(d) && strings.EqualFold(name[:len(d)], d) {
			return true
		}
	}
	return false
}

func (a analysis) joinRegistry(s *Service) {
	if !a.registry.read() {
		s.RegistryUnreadable = true
		return
	}
	k, ok := a.registry.lookup(s.ServiceName)
	if !ok {
		s.RegistryUnreadable = !a.registry.complete
		return
	}
	s.RegistryKeyFound, s.RegistryImagePath, s.RegistryServiceDll = true, k.imagePath, k.serviceDll
}
