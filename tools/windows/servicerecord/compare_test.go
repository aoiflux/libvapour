package servicerecord

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools"
)

func diagContext() (tools.Context, *[]string) {
	var diags []string
	return tools.Context{Options: map[string]any{"diagnostics": &diags}}, &diags
}

func registryOf(complete bool, keys ...registryKey) registryView {
	v := registryView{keys: map[string]registryKey{}, complete: complete}
	for _, k := range keys {
		v.keys[strings.ToLower(k.name)] = k
	}
	return v
}

func analysed(t *testing.T, w *world, h head, reg registryView) analysis {
	t.Helper()
	c := scanRegions(w.mem, []addressRange{fixtureHeapRange}, scanBounds{})
	f := fitLayouts(w.mem, c, fixtureImage)
	return analysis{target: target{pid: 600, space: w.mem, image: fixtureImage}, fit: f, head: h,
		walk: bestWalk(w.mem, h, fixtureImage, 0, &f.layout), registry: reg}
}

func TestTheComparisonReportsEachFinding(t *testing.T) {
	l := layoutNamed("26100")
	w := newWorld(l)
	h := w.list("Alpha", "Beta")
	w.record(running(fixtureHeap+0x2000, "Hidden", 9))
	w.record(running(fixtureHeap+0x3000, "Beta", 2))
	reg := registryOf(true,
		registryKey{name: "alpha", serviceType: 0x20, typeKnown: true},
		registryKey{name: "Beta", serviceType: 0x20, typeKnown: true},
		registryKey{name: "Loader", serviceType: 0x2, typeKnown: true, startType: 3, startKnown: true, imagePath: `\??\C:\l.sys`},
		registryKey{name: "Params"},
		registryKey{name: "Odd", serviceType: 0x100, typeKnown: true},
	)
	a := analysed(t, w, h, reg)
	ctx, diags := diagContext()
	rows := a.findings(ctx)
	got := make([]string, 0, len(rows))
	for _, r := range rows {
		got = append(got, string(r.Finding)+" "+r.ServiceName)
	}
	want := []string{"unlinked Hidden", "no registry key Hidden", "registry only Loader"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Errorf("findings %v, want %v", got, want)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "1 unlisted records repeat") {
		t.Errorf("copy not counted: %v", *diags)
	}
	for _, r := range rows {
		if r.Finding == FindingRegistryOnly && (r.RecordAddress != 0 || r.StartType != "demand" || r.ServiceType != "file system driver" ||
			r.RegistryImagePath != `\??\C:\l.sys` || r.CurrentState != "") {
			t.Errorf("registry only row %+v", r)
		}
	}
}

func TestAnIncompleteRegistryMakesNoRegistryFindings(t *testing.T) {
	w := newWorld(layoutNamed("14393"))
	h := w.list("Alpha")
	a := analysed(t, w, h, registryOf(false, registryKey{name: "Loader", serviceType: 0x1, typeKnown: true}))
	ctx, diags := diagContext()
	if rows := a.findings(ctx); len(rows) != 0 {
		t.Errorf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "registry findings not made") {
		t.Errorf("diagnostics %v", *diags)
	}
	a.registry = registryView{err: errors.New("no hive")}
	if rows := a.findings(ctx); len(rows) != 0 {
		t.Errorf("unread registry: rows %+v", rows)
	}
}

func TestARunningServiceTakesItsProcessFromItsImageRecord(t *testing.T) {
	l := layoutNamed("19041")
	w := newWorld(l)
	r := running(fixtureHeap, "Schedule", 1)
	r.processOrDriver = w.imageRecord(1234, `C:\Windows\system32\svchost.exe -k netsvcs`)
	w.record(r)
	stopped := running(fixtureHeap+0x200, "Stopped", 2)
	stopped.state = 1
	w.record(stopped)
	broken := running(fixtureHeap+0x400, "Broken", 3)
	broken.processOrDriver = fixtureHeap + 0x400
	w.record(broken)
	a := analysis{target: target{pid: 600, space: w.mem}, registry: registryOf(true,
		registryKey{name: "schedule", imagePath: "%SystemRoot%\\system32\\svchost.exe -k netsvcs", serviceDll: "schedsvc.dll"})}
	ctx, _ := diagContext()
	rows := map[string]Service{}
	for _, at := range []uint64{fixtureHeap, fixtureHeap + 0x200, fixtureHeap + 0x400} {
		rec, why := decode(w.mem, l, at, fixtureImage)
		if why != "" {
			t.Fatalf("0x%x: %s", at, why)
		}
		rows[rec.name] = a.rowWith(ctx, rec, l)
	}
	if s := rows["Schedule"]; s.ProcessID != 1234 || s.ImagePath != `C:\Windows\system32\svchost.exe -k netsvcs` ||
		s.ProcessIDUnreadable || !s.RegistryKeyFound || s.RegistryServiceDll != "schedsvc.dll" || s.CurrentState != "running" ||
		s.StartType != "auto" || s.ErrorControl != "normal" || s.ServiceType != "share process" || s.SCMProcessID != 600 {
		t.Errorf("running row %+v", s)
	}
	if s := rows["Stopped"]; s.ProcessID != 0 || s.ProcessIDUnreadable || s.RegistryKeyFound || s.RegistryUnreadable {
		t.Errorf("stopped row %+v", s)
	}
	if s := rows["Broken"]; !s.ProcessIDUnreadable || !s.ImagePathUnreadable {
		t.Errorf("untagged image record row %+v", s)
	}
}

func TestADriverTakesItsObjectNameOnlyFromADriverDirectory(t *testing.T) {
	l := layoutNamed("26100")
	w := newWorld(l)
	good := driver(fixtureHeap, "disk", 1)
	good.processOrDriver = w.str(`\Driver\disk`)
	w.record(good)
	fs := driver(fixtureHeap+0x200, "Ntfs", 2)
	fs.serviceType = 0x2
	fs.processOrDriver = w.str(`\FileSystem\Ntfs`)
	w.record(fs)
	bad := driver(fixtureHeap+0x400, "kbd", 3)
	bad.processOrDriver = w.str("ayst Root=C:")
	w.record(bad)
	none := driver(fixtureHeap+0x600, "idle", 4)
	w.record(none)
	a := analysis{target: target{space: w.mem}, registry: registryView{err: errors.New("unread")}}
	ctx, _ := diagContext()
	want := map[uint64]struct {
		name       string
		unreadable bool
	}{fixtureHeap: {`\Driver\disk`, false}, fixtureHeap + 0x200: {`\FileSystem\Ntfs`, false},
		fixtureHeap + 0x400: {"", true}, fixtureHeap + 0x600: {"", false}}
	for at, exp := range want {
		rec, why := decode(w.mem, l, at, fixtureImage)
		if why != "" {
			t.Fatalf("0x%x: %s", at, why)
		}
		s := a.rowWith(ctx, rec, l)
		if s.DriverObjectName != exp.name || s.DriverObjectNameUnreadable != exp.unreadable || !s.RegistryUnreadable || s.ProcessID != 0 {
			t.Errorf("0x%x: row %+v", at, s)
		}
	}
}
