package consolelist

import (
	"encoding/binary"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

const (
	consoleKey = "Console"
	regDWORD   = 4
	dwordBytes = 4

	valueHistoryBufferSize      = "HistoryBufferSize"
	valueNumberOfHistoryBuffers = "NumberOfHistoryBuffers"
	valueScreenBufferSize       = "ScreenBufferSize"
	valueWindowSize             = "WindowSize"
)

// Every capture's registry held these two (S33 M1); they stand in when no
// hive gives a value and no option names one.
const (
	DefaultHistoryBufferSize      = 50
	DefaultNumberOfHistoryBuffers = 4
)

type DWORDValue struct {
	Value uint32
	Set   bool
}

// The Console key of one hive, or one of its subkeys, which hold the
// settings of consoles started with that title or path.
type Setting struct {
	HivePath               string
	Key                    string
	HistoryBufferSize      DWORDValue
	NumberOfHistoryBuffers DWORDValue
	ScreenBufferSize       DWORDValue
	WindowSize             DWORDValue
}

// Hives without a Console key are not user hives and give nothing.
func ReadSettings(ctx tools.Context) []Setting {
	var out []Setting
	for _, h := range registryhive.OpenEveryHive(ctx.WithoutPIDFilter(), nil) {
		key, err := h.Layer.OpenKey(consoleKey)
		if err != nil {
			continue
		}
		path := h.Hive.FileFullPath
		if path == "" {
			path = h.Hive.Name
		}
		out = append(out, readSetting(h.Layer, key, path, consoleKey))
		subkeys, _ := h.Layer.SubkeysChecked(key)
		for _, sub := range subkeys {
			if sub.NameUnreadable {
				continue
			}
			out = append(out, readSetting(h.Layer, sub, path, consoleKey+`\`+sub.Name))
		}
	}
	return out
}

func readSetting(h *registryhive.HiveLayer, key *registryhive.KeyNode, hive, name string) Setting {
	values, _ := h.ValuesChecked(key)
	s := Setting{HivePath: hive, Key: name}
	for _, v := range values {
		if v.NameUnreadable || v.TypeUnreadable || v.Type != regDWORD || len(v.Raw) < dwordBytes {
			continue
		}
		d := DWORDValue{Value: binary.LittleEndian.Uint32(v.Raw), Set: true}
		switch {
		case strings.EqualFold(v.Name, valueHistoryBufferSize):
			s.HistoryBufferSize = d
		case strings.EqualFold(v.Name, valueNumberOfHistoryBuffers):
			s.NumberOfHistoryBuffers = d
		case strings.EqualFold(v.Name, valueScreenBufferSize):
			s.ScreenBufferSize = d
		case strings.EqualFold(v.Name, valueWindowSize):
			s.WindowSize = d
		}
	}
	return s
}

type searchSizes struct {
	historyBufferSizes     []uint64
	numberOfHistoryBuffers []uint64
}

// An option replaces the default value, the registry adds to it: a console
// keeps the size it was created with, so a value changed since still finds
// consoles made before the change.
func gatherSizes(settings []Setting, historyOption, buffersOption []uint64) searchSizes {
	z := searchSizes{
		historyBufferSizes:     slices.Clone(historyOption),
		numberOfHistoryBuffers: slices.Clone(buffersOption),
	}
	if len(z.historyBufferSizes) == 0 {
		z.historyBufferSizes = []uint64{DefaultHistoryBufferSize}
	}
	if len(z.numberOfHistoryBuffers) == 0 {
		z.numberOfHistoryBuffers = []uint64{DefaultNumberOfHistoryBuffers}
	}
	for _, s := range settings {
		if s.HistoryBufferSize.Set {
			z.historyBufferSizes = append(z.historyBufferSizes, uint64(s.HistoryBufferSize.Value))
		}
		if s.NumberOfHistoryBuffers.Set {
			z.numberOfHistoryBuffers = append(z.numberOfHistoryBuffers, uint64(s.NumberOfHistoryBuffers.Value))
		}
	}
	slices.Sort(z.historyBufferSizes)
	slices.Sort(z.numberOfHistoryBuffers)
	z.historyBufferSizes = slices.Compact(z.historyBufferSizes)
	z.numberOfHistoryBuffers = slices.Compact(z.numberOfHistoryBuffers)
	return z
}
