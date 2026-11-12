package servicerecord

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

type registryKey struct {
	name                    string
	serviceType             uint32
	typeKnown               bool
	startType, errorControl uint32
	startKnown, errorKnown  bool
	imagePath, serviceDll   string
}

type registryView struct {
	keys     map[string]registryKey
	complete bool
	err      error
}

func (v registryView) read() bool { return v.err == nil }

func (v registryView) lookup(name string) (registryKey, bool) {
	k, ok := v.keys[strings.ToLower(name)]
	return k, ok
}

func readRegistry(ctx tools.Context, tool string) registryView {
	hive, err := registryhive.OpenHive(ctx, "SYSTEM", registryhive.CellReader(ctx))
	if err != nil {
		return registryView{err: err}
	}
	set, read := registryhive.CurrentControlSetChecked(hive)
	if !read {
		ctx.AddDiagnostic("%s: SYSTEM\\Select\\Current not read; %s is taken as the control set", tool, set)
	}
	services, err := hive.OpenKey(set + `\Services`)
	if err != nil {
		return registryView{err: err}
	}
	subkeys, complete := hive.SubkeysChecked(services)
	view := registryView{keys: make(map[string]registryKey, len(subkeys)), complete: complete}
	for _, sk := range subkeys {
		if sk.NameUnreadable {
			view.complete = false
			continue
		}
		k := registryKey{name: sk.Name}
		values, _ := hive.ValuesChecked(sk)
		for _, v := range values {
			if v.NameUnreadable || v.Unreadable() {
				continue
			}
			switch strings.ToLower(v.Name) {
			case "type":
				k.serviceType, k.typeKnown = dword(v.Raw)
			case "start":
				k.startType, k.startKnown = dword(v.Raw)
			case "errorcontrol":
				k.errorControl, k.errorKnown = dword(v.Raw)
			case "imagepath":
				k.imagePath = utf16z(v.Raw)
			}
		}
		if params, err := hive.Subkey(sk, "Parameters"); err == nil {
			if v, found, _ := hive.ValueByNameChecked(params, "ServiceDll"); found && !v.Unreadable() {
				k.serviceDll = utf16z(v.Raw)
			}
		}
		view.keys[strings.ToLower(sk.Name)] = k
	}
	return view
}

func (v registryView) sortedKeys() []registryKey {
	out := make([]registryKey, 0, len(v.keys))
	for _, k := range v.keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].name) < strings.ToLower(out[j].name) })
	return out
}

func dword(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

func utf16z(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

func (v registryView) describe() string {
	if v.err != nil {
		return fmt.Sprintf("not read: %v", v.err)
	}
	return "subkey list incomplete"
}
