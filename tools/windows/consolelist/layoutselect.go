package consolelist

import (
	"errors"
	"fmt"
	"math"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

var ErrUnsupportedVersion = errors.New("consolelist: no measured conhost layout for this windows build")

// Every measured layout is of a 64-bit conhost.exe on Windows 10.0 (S33 4.1).
const (
	measuredMajor = 10
	measuredMinor = 0
)

func LayoutFor(is64 bool, major, minor, build uint64) (*Layout, error) {
	if !is64 {
		return nil, fmt.Errorf("%s: windows %d.%d build %d: 32-bit kernel: %w", Name, major, minor, build, ErrUnsupportedVersion)
	}
	l, ok := layoutForBuild[fileSet(build)]
	if !ok || major != measuredMajor || minor != measuredMinor {
		return nil, fmt.Errorf("%s: windows %d.%d build %d: %w", Name, major, minor, build, ErrUnsupportedVersion)
	}
	return l, nil
}

func LoadLayout(ctx tools.Context) (*Layout, error) {
	b := winkernel.ReadBuild(Name, ctx.Memory, ctx.Symbols)
	if err := b.Missing(); err != nil {
		return nil, err
	}
	return LayoutFor(ctx.Symbols.PointerSize() == 8, uint64(b.Major), uint64(b.Minor), uint64(b.Kernel))
}

func fileSet(build uint64) uint64 {
	if build > math.MaxUint32 {
		return build
	}
	return uint64(winkernel.FileSetBuild(uint32(build)))
}

func (l *Layout) HasConsole() bool { return l.console != nil }

// Why the console reader refuses a layout that has history members only.
func (l *Layout) ConsoleGap() string { return l.noConsole }

type LayoutMember struct {
	Name   string
	Offset int64
	Size   uint64
}

// For the measurement script: it checks each offset on the captures (S33 9).
func (l *Layout) Members() []LayoutMember {
	m := []LayoutMember{
		{"node.next", l.node.next, pointerBytes},
		{"node.prev", l.node.next + pointerBytes, pointerBytes},
		{"node.value", int64(l.node.size), 0},
		{"history.commands", l.history.commands, 3 * pointerBytes},
		{"history.capacity", l.history.capacity.off, l.history.capacity.size},
		{"history.application", l.history.application, l.text.size},
		{"history.process", l.history.process, pointerBytes},
		{"history.lastDisplayed", l.history.lastDisplayed.off, l.history.lastDisplayed.size},
		{"history.end", int64(l.history.size), 0},
		{"process.pid", l.process.pid.off, l.process.pid.size},
		{"text.chars", l.text.chars, 0},
		{"text.pointer", l.text.pointer, pointerBytes},
		{"text.length", l.text.length.off, l.text.length.size},
		{"text.capacity", l.text.capacity.off, l.text.capacity.size},
		{"text.size", int64(l.text.size), 0},
		{"vector.begin", l.vector.begin, pointerBytes},
		{"vector.end", l.vector.end, pointerBytes},
		{"vector.capacityEnd", l.vector.capacityEnd, pointerBytes},
	}
	c := l.console
	if c == nil {
		return m
	}
	return append(m,
		LayoutMember{"console.screenWidth", c.screenWidth.off, c.screenWidth.size},
		LayoutMember{"console.screenHeight", c.screenHeight.off, c.screenHeight.size},
		LayoutMember{"console.historySize", c.historySize.off, c.historySize.size},
		LayoutMember{"console.historyMax", c.historyMax.off, c.historyMax.size},
		LayoutMember{"console.historyList", c.historyList, pointerBytes},
		LayoutMember{"console.historyCount", c.historyCount.off, c.historyCount.size},
		LayoutMember{"console.processList", c.processList, pointerBytes},
		LayoutMember{"console.processCount", c.processCount.off, c.processCount.size},
		LayoutMember{"console.title", c.title, l.text.size},
		LayoutMember{"console.originalTitle", c.originalTitle, l.text.size},
		LayoutMember{"console.aliases", c.aliases, pointerBytes},
		LayoutMember{"console.activeScreen", c.activeScreen, pointerBytes},
		LayoutMember{"console.screenList", c.screenList, pointerBytes},
		LayoutMember{"processNode.process", c.processNode.process, pointerBytes},
		LayoutMember{"aliasEntry.name", c.aliasEntry.name, l.text.size},
		LayoutMember{"aliasEntry.aliases", c.aliasEntry.aliases, pointerBytes},
		LayoutMember{"alias.source", c.alias.source, l.text.size},
		LayoutMember{"alias.target", c.alias.target, l.text.size},
		LayoutMember{"screen.textBuffer", c.screen.textBuffer, pointerBytes},
		LayoutMember{"screen.next", c.screen.next, pointerBytes},
		LayoutMember{"textBuffer.rows", c.textBuffer.rows, pointerBytes},
		LayoutMember{"textBuffer.rowCount", c.textBuffer.rowCount.off, c.textBuffer.rowCount.size},
		LayoutMember{"textBuffer.firstRow", c.textBuffer.firstRow.off, c.textBuffer.firstRow.size},
		LayoutMember{"row.cells", c.row.cells, pointerBytes},
		LayoutMember{"row.width", c.row.width.off, c.row.width.size},
	)
}
