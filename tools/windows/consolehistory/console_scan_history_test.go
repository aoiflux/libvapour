package consolehistory

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/consolelist"
)

const (
	hostPID   = 700
	heapStart = uint64(0x30000000)
	heapPages = 4
)

// A heap laid out from the layout's own member list, the way a measurement
// reads it.
type heap struct {
	off  map[string]consolelist.LayoutMember
	buf  []byte
	next uint64
}

func newHeap(t *testing.T, build uint16) *heap {
	t.Helper()
	l, err := consolelist.LayoutFor(true, 10, 0, uint64(build))
	if err != nil {
		t.Fatal(err)
	}
	h := &heap{off: map[string]consolelist.LayoutMember{}, buf: make([]byte, heapPages*0x1000), next: 0x10}
	for _, m := range l.Members() {
		h.off[m.Name] = m
	}
	return h
}

func (h *heap) alloc(n uint64) uint64 {
	at := heapStart + h.next
	h.next += (n + 15) &^ 15
	return at
}

func (h *heap) put(at uint64, size uint64, v uint64) {
	b := h.buf[at-heapStart:]
	switch size {
	case 2:
		binary.LittleEndian.PutUint16(b, uint16(v))
	case 4:
		binary.LittleEndian.PutUint32(b, uint32(v))
	default:
		binary.LittleEndian.PutUint64(b, v)
	}
}

func (h *heap) member(base uint64, name string, v uint64) {
	m := h.off[name]
	h.put(uint64(int64(base)+m.Offset), max(m.Size, 1), v)
}

func (h *heap) at(base uint64, name string) uint64 { return uint64(int64(base) + h.off[name].Offset) }

func (h *heap) wide(at uint64, text string) {
	units := utf16.Encode([]rune(text))
	buf := h.alloc(uint64(2*len(units) + 2))
	for i, u := range units {
		h.put(buf+uint64(2*i), 2, uint64(u))
	}
	h.member(at, "text.pointer", buf)
	h.member(at, "text.length", uint64(len(units)))
	h.member(at, "text.capacity", uint64(max(len(units), 8)))
}

func (h *heap) history(app string, commands []string, owner uint64) uint64 {
	size := uint64(h.off["history.end"].Offset)
	head, node := h.alloc(size), h.alloc(size)
	h.member(head, "node.next", node)
	h.member(head, "node.prev", node)
	h.member(node, "node.next", head)
	h.member(node, "node.prev", head)
	h.member(node, "history.capacity", 50)
	h.wide(h.at(node, "history.application"), app)
	h.member(node, "history.process", owner)
	h.member(node, "history.lastDisplayed", uint64(len(commands)-1))
	str := uint64(h.off["text.size"].Offset)
	begin := h.alloc(uint64(len(commands)) * str)
	for i, c := range commands {
		h.wide(begin+uint64(i)*str, c)
	}
	vec := h.at(node, "history.commands")
	end := begin + uint64(len(commands))*str
	h.member(vec, "vector.begin", begin)
	h.member(vec, "vector.end", end)
	h.member(vec, "vector.capacityEnd", end)
	return node
}

func (h *heap) record(pid uint64) uint64 {
	r := h.alloc(64)
	h.member(r, "process.pid", pid)
	return r
}

func runContext(t *testing.T, h *heap, build uint16) tools.Context {
	t.Helper()
	pf := testsupport.BuildProcessFixture([]testsupport.FixtureProcess{
		{PID: 4242, Name: "cmd.exe"},
		{PID: hostPID, Name: "conhost.exe", VADs: []testsupport.FixtureVAD{{Start: heapStart, End: heapStart + uint64(len(h.buf)) - 1}}},
		{PID: 800, Name: "notconhost.exe", VADs: []testsupport.FixtureVAD{{Start: heapStart, End: heapStart + uint64(len(h.buf)) - 1}}},
	})
	for off := 0; off < len(h.buf); off += 0x1000 {
		pf.Space(hostPID).MapData(heapStart+uint64(off), h.buf[off:off+0x1000])
		pf.Space(800).MapData(heapStart+uint64(off), h.buf[off:off+0x1000])
	}
	ctx := pf.Context()
	ctx.Symbols, ctx.Memory = testsupport.WithWindowsVersion(ctx.Symbols, ctx.Memory, 10, 0, build)
	ctx.Options["diagnostics"] = &[]string{}
	return ctx
}

func TestEveryHistoryInAHostIsFoundWithItsCommands(t *testing.T) {
	for _, build := range []uint16{19045} {
		h := newHeap(t, build)
		owner := h.record(4242)
		second := h.history("powershell.exe", []string{"Get-ChildItem"}, 0)
		first := h.history("cmd.exe", []string{"whoami", "net user"}, owner)
		rows, err := Run(runContext(t, h, build))
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 || rows[0].Address != second || rows[1].Address != first {
			t.Fatalf("build %d: rows %+v", build, rows)
		}
		r := rows[1]
		if r.PID != hostPID || r.Process != "conhost.exe" || r.Application != "cmd.exe" || r.OwnerPID != 4242 || !r.OwnerPIDKnown {
			t.Errorf("build %d: row %+v", build, r)
		}
		var got []string
		for _, c := range r.Commands {
			got = append(got, c.Text)
		}
		if !reflect.DeepEqual(got, []string{"whoami", "net user"}) || r.RecallPosition != 1 {
			t.Errorf("build %d: commands %q, recall %d", build, got, r.RecallPosition)
		}
	}
}

func TestThePIDOptionKeepsOnlyTheHostsAskedFor(t *testing.T) {
	h := newHeap(t, 19045)
	h.history("cmd.exe", []string{"dir"}, 0)
	ctx := runContext(t, h, 19045)
	ctx.Options["pid"] = []uint64{4242}
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 {
		t.Errorf("rows %+v, %v", rows, err)
	}
}

func TestAnUnreadableCommandFailsStrictMode(t *testing.T) {
	h := newHeap(t, 19045)
	node := h.history("cmd.exe", []string{"dir", "cls"}, 0)
	begin := binary.LittleEndian.Uint64(h.buf[h.at(h.at(node, "history.commands"), "vector.begin")-heapStart:])
	h.member(begin, "text.pointer", 0x50)
	ctx := runContext(t, h, 19045)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || !rows[0].Commands[0].Unreadable {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	ctx = runContext(t, h, 19045)
	ctx.Options["strict"] = true
	if rows, err := Run(ctx); !errors.Is(err, consolelist.ErrIncomplete) || len(rows) != 1 {
		t.Errorf("strict: rows %d, %v", len(rows), err)
	}
}

func TestRejectedCandidatesAreCounted(t *testing.T) {
	h := newHeap(t, 19045)
	h.put(heapStart+0x2000+uint64(h.off["history.capacity"].Offset), 8, 50)
	ctx := runContext(t, h, 19045)
	if _, err := Run(ctx); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range *ctx.Options["diagnostics"].(*[]string) {
		found = found || strings.Contains(d, "1 candidates rejected: "+consolelist.RuleLinked+" 1")
	}
	if !found {
		t.Errorf("diagnostics %q", *ctx.Options["diagnostics"].(*[]string))
	}
}

func TestUnmeasuredBuildsAreRefused(t *testing.T) {
	h := newHeap(t, 19045)
	if _, err := Run(runContext(t, h, 14393)); !errors.Is(err, consolelist.ErrUnsupportedVersion) {
		t.Errorf("14393: %v", err)
	}
}

func TestOnlyWindowsIsRead(t *testing.T) {
	h := newHeap(t, 19045)
	ctx := runContext(t, h, 19045)
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Error("linux profile accepted")
	}
}

func TestAWrongOptionTypeIsAnError(t *testing.T) {
	h := newHeap(t, 19045)
	ctx := runContext(t, h, 19045)
	ctx.Options[OptionMaxHistory] = "fifty"
	if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("err %v", err)
	}
}
