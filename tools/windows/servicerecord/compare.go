package servicerecord

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

var findingOrder = map[Finding]int{FindingUnlinked: 0, FindingNoRegistryKey: 1, FindingRegistryOnly: 2}

func Compare(ctx tools.Context) ([]Service, error) {
	all, err := analyse(ctx, CompareName, options{scan: true, list: true})
	if err != nil {
		return nil, err
	}
	var rows []Service
	compared := 0
	var problems []error
	for _, a := range all {
		switch {
		case a.fitErr != nil:
			problems = append(problems, a.fitErr)
			continue
		case a.listErr != nil:
			problems = append(problems, a.listErr)
			continue
		case a.walk.cut != nil:
			problems = append(problems, fmt.Errorf("%s pid %d: list walk cut, records not compared: %w", scmImage, a.target.pid, ErrServiceListIncomplete))
			continue
		}
		compared++
		rows = append(rows, a.findings(ctx)...)
	}
	if compared == 0 {
		return nil, fmt.Errorf("%s: %w", CompareName, errors.Join(problems...))
	}
	for _, p := range problems {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: %w", CompareName, p)
		}
		ctx.AddDiagnostic("%s: %v", CompareName, p)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.SCMProcessID != b.SCMProcessID {
			return a.SCMProcessID < b.SCMProcessID
		}
		if findingOrder[a.Finding] != findingOrder[b.Finding] {
			return findingOrder[a.Finding] < findingOrder[b.Finding]
		}
		if a.RecordAddress != b.RecordAddress {
			return a.RecordAddress < b.RecordAddress
		}
		return strings.ToLower(a.ServiceName) < strings.ToLower(b.ServiceName)
	})
	ctx.AddDiagnostic("%s: %d findings", CompareName, len(rows))
	return rows, nil
}

type copyKey struct {
	sequence uint32
	name     string
}

// S34 4.5 steps 2 to 4.
func (a analysis) findings(ctx tools.Context) []Service {
	listed := make(map[uint64]bool, len(a.walk.records))
	listedCopy := make(map[copyKey]bool, len(a.walk.records))
	named := make(map[string]bool, len(a.walk.records))
	for _, rec := range a.walk.records {
		listed[rec.address] = true
		listedCopy[copyKey{rec.sequence, strings.ToLower(rec.name)}] = true
		named[strings.ToLower(rec.name)] = true
	}
	var out []Service
	copies := 0
	judged := a.registry.read() && a.registry.complete
	keyless := func(rec record, s Service) {
		if !judged {
			return
		}
		if _, ok := a.registry.lookup(rec.name); !ok {
			s.Finding = FindingNoRegistryKey
			out = append(out, s)
		}
	}
	for _, rec := range a.fit.records {
		if listed[rec.address] {
			continue
		}
		if listedCopy[copyKey{rec.sequence, strings.ToLower(rec.name)}] {
			copies++
			continue
		}
		s := a.row(ctx, rec)
		s.Finding = FindingUnlinked
		out = append(out, s)
		keyless(rec, s)
	}
	for _, rec := range a.walk.records {
		s := a.rowWith(ctx, rec, a.walk.layout)
		s.Listed = true
		keyless(rec, s)
	}
	if copies > 0 {
		ctx.AddDiagnostic("%s: %s pid %d: %d unlisted records repeat the sequence and name of a listed record and are not reported",
			CompareName, scmImage, a.target.pid, copies)
	}
	if !judged {
		ctx.AddDiagnostic("%s: %s pid %d: registry %s; registry findings not made", CompareName, scmImage, a.target.pid, a.registry.describe())
		return out
	}
	for _, k := range a.registry.sortedKeys() {
		if !k.typeKnown || k.serviceType&typeKind == 0 || named[strings.ToLower(k.name)] {
			continue
		}
		s := Service{
			SCMProcessID: a.target.pid, Finding: FindingRegistryOnly, ServiceName: k.name,
			ServiceType: serviceTypeOf(k.serviceType), RegistryKeyFound: true,
			RegistryImagePath: k.imagePath, RegistryServiceDll: k.serviceDll,
		}
		if k.startKnown {
			s.StartType = startTypeOf(k.startType)
		}
		if k.errorKnown {
			s.ErrorControl = errorControlOf(k.errorControl)
		}
		out = append(out, s)
	}
	return out
}
