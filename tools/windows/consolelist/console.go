package consolelist

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/util"
)

var (
	ErrScreenBufferSize = errors.New("consolelist: screen buffer size is not positive")
	ErrNoProcess        = errors.New("consolelist: console has no attached process")
	ErrTooManyBuffers   = errors.New("consolelist: more history buffers than NumberOfHistoryBuffers")
	ErrNoActiveScreen   = errors.New("consolelist: active screen buffer is not on the screen buffer list")
	ErrRowShape         = errors.New("consolelist: screen row count or width out of shape")
)

type AttachedProcess struct {
	Record        uint64
	PID           uint64
	InProcessList bool
}

type Alias struct {
	Address    uint64
	Executable string
	Source     string
	Target     string
}

type ScreenRow struct {
	Row  int
	Text string
}

type Screen struct {
	Address    uint64
	Active     bool
	Columns    int
	RowCount   int
	Rows       []ScreenRow
	Incomplete bool
}

type Console struct {
	PID     uint64
	Process string
	Address uint64

	Title                   string
	TitleUnreadable         bool
	OriginalTitle           string
	OriginalTitleUnreadable bool

	ScreenBufferColumns    int
	ScreenBufferRows       int
	HistoryBufferSize      uint32
	NumberOfHistoryBuffers uint32

	AttachedProcesses []AttachedProcess
	Aliases           []Alias
	Histories         []History
	Screens           []Screen

	// Each part of the console that did not read whole, with the reason.
	Incomplete []string
}

const (
	RuleScreenSize   = "C1 screen buffer size"
	RuleProcessList  = "C2 attached processes"
	RuleHistoryList  = "C3 history buffers"
	RuleTitles       = "C4 titles"
	RuleBufferNumber = "C5 history buffer count"
)

// The screen buffer size is a COORD, whose X and Y are SHORT (S33 F8).
func short(p prim) prim {
	p.signed = p.size == 2
	return p
}

// The console's two history settings are adjacent members; the pair is what
// the search looks for (S33 4.2).
func (l *Layout) SettingsPair() (prim, bool) {
	c := l.console
	if c == nil || c.historySize.size != dwordBytes || c.historyMax.size != dwordBytes ||
		c.historyMax.off != c.historySize.off+dwordBytes {
		return prim{}, false
	}
	return prim{off: c.historySize.off, size: 2 * dwordBytes}, true
}

func (l *Layout) InspectConsole(s Space, at uint64, b limits.Limits) Verdict {
	c := l.console
	fail := func(rule string, err error) Verdict { return Verdict{Address: at, Rule: rule, Err: err} }
	if c == nil {
		return fail(RuleScreenSize, fmt.Errorf("%w: %s", ErrUnsupportedVersion, l.noConsole))
	}
	cols, err := s.value(at, short(c.screenWidth))
	if err != nil {
		return fail(RuleScreenSize, err)
	}
	rows, err := s.value(at, short(c.screenHeight))
	if err != nil {
		return fail(RuleScreenSize, err)
	}
	if cols <= 0 || rows <= 0 {
		return fail(RuleScreenSize, fmt.Errorf("console 0x%x: %d x %d: %w", at, cols, rows, ErrScreenBufferSize))
	}
	procs, err := l.walkList(s, at, c.processList, c.processCount, b.MaxListEntries)
	if err != nil {
		return fail(RuleProcessList, err)
	}
	if len(procs.Nodes) == 0 {
		return fail(RuleProcessList, fmt.Errorf("console 0x%x: %w", at, ErrNoProcess))
	}
	hist, err := l.walkList(s, at, c.historyList, c.historyCount, b.MaxListEntries)
	if err != nil {
		return fail(RuleHistoryList, err)
	}
	for _, off := range []int64{c.title, c.originalTitle} {
		if _, err := l.wideShape(s, s.member(at, off)); err != nil {
			return fail(RuleTitles, err)
		}
	}
	most, err := s.value(at, c.historyMax)
	if err != nil {
		return fail(RuleBufferNumber, err)
	}
	if int64(len(hist.Nodes)) > most {
		return fail(RuleBufferNumber, fmt.Errorf("console 0x%x: %d buffers, at most %d: %w", at, len(hist.Nodes), most, ErrTooManyBuffers))
	}
	return Verdict{Address: at}
}

// Called only on a console InspectConsole accepted; listed holds the PIDs
// of the processes the kernel lists.
func (l *Layout) ReadConsole(s Space, at uint64, listed map[uint64]bool, b limits.Limits) Console {
	c := l.console
	out := Console{Address: at}
	gap := func(part string, err error) { out.Incomplete = append(out.Incomplete, part+": "+err.Error()) }

	if v, err := s.value(at, short(c.screenWidth)); err == nil {
		out.ScreenBufferColumns = int(v)
	}
	if v, err := s.value(at, short(c.screenHeight)); err == nil {
		out.ScreenBufferRows = int(v)
	}
	if v, err := s.value(at, c.historySize); err == nil {
		out.HistoryBufferSize = uint32(v)
	}
	if v, err := s.value(at, c.historyMax); err == nil {
		out.NumberOfHistoryBuffers = uint32(v)
	}
	if w, err := l.wideString(s, s.member(at, c.title), b.MaxTextBytes); err == nil {
		out.Title = w.Text
	} else {
		out.TitleUnreadable = true
		gap("title", err)
	}
	if w, err := l.wideString(s, s.member(at, c.originalTitle), b.MaxTextBytes); err == nil {
		out.OriginalTitle = w.Text
	} else {
		out.OriginalTitleUnreadable = true
		gap("original title", err)
	}

	if procs, err := l.walkList(s, at, c.processList, c.processCount, b.MaxListEntries); err == nil {
		for _, n := range procs.Nodes {
			p := AttachedProcess{}
			rec, err := s.pointer(s.member(n, c.processNode.process))
			if err == nil {
				p.Record = rec
				var pid uint64
				if pid, err = l.recordPID(s, rec); err == nil {
					p.PID, p.InProcessList = pid, listed[pid]
				}
			}
			if err != nil {
				gap(fmt.Sprintf("attached process node 0x%x", n), err)
			}
			out.AttachedProcesses = append(out.AttachedProcesses, p)
		}
	} else {
		gap("attached processes", err)
	}

	if hist, err := l.walkList(s, at, c.historyList, c.historyCount, b.MaxListEntries); err == nil {
		for _, n := range hist.Nodes {
			if v := l.InspectHistory(s, n, 0, b); !v.Accepted() {
				gap(fmt.Sprintf("history 0x%x", n), fmt.Errorf("%s: %w", v.Rule, v.Err))
				continue
			}
			out.Histories = append(out.Histories, l.ReadHistory(s, n, b))
		}
	} else {
		gap("history buffers", err)
	}

	aliases, err := l.readAliases(s, at, b)
	out.Aliases = aliases
	if err != nil {
		gap("aliases", err)
	}

	screens, err := l.readScreens(s, at, b)
	out.Screens = screens
	if err != nil {
		gap("screen buffers", err)
	}
	return out
}

// The aliases are a map from executable name to a map from source to
// target (S33 F9, M4); both maps keep their entries on a list.
func (l *Layout) readAliases(s Space, at uint64, b limits.Limits) ([]Alias, error) {
	c := l.console
	exes, err := l.walkList(s, at, c.aliases, listSize(c.aliases), b.MaxListEntries)
	if err != nil {
		return nil, err
	}
	var out []Alias
	var first error
	for _, e := range exes.Nodes {
		exe, err := l.wideString(s, s.member(e, c.aliasEntry.name), b.MaxTextBytes)
		if err != nil {
			first = cmpErr(first, err)
			continue
		}
		inner, err := l.walkList(s, e, c.aliasEntry.aliases, listSize(c.aliasEntry.aliases), b.MaxListEntries)
		if err != nil {
			first = cmpErr(first, err)
		}
		for _, n := range inner.Nodes {
			a := Alias{Address: n, Executable: exe.Text}
			src, err1 := l.wideString(s, s.member(n, c.alias.source), b.MaxTextBytes)
			dst, err2 := l.wideString(s, s.member(n, c.alias.target), b.MaxTextBytes)
			if err := errors.Join(err1, err2); err != nil {
				first = cmpErr(first, err)
				continue
			}
			a.Source, a.Target = src.Text, dst.Text
			out = append(out, a)
		}
	}
	return out, first
}

// A list's size member follows its head pointer (S33 F3, M4).
func listSize(head int64) prim { return prim{off: head + pointerBytes, size: pointerBytes} }

func cmpErr(first, err error) error {
	if first != nil {
		return first
	}
	return err
}

// Screen buffers are a chain through each buffer's next member; the active
// one is among them (S33 F2, M5).
func (l *Layout) readScreens(s Space, at uint64, b limits.Limits) ([]Screen, error) {
	c := l.console
	active, err := s.pointer(s.member(at, c.activeScreen))
	if err != nil {
		return nil, err
	}
	cur, err := s.pointer(s.member(at, c.screenList))
	if err != nil {
		return nil, err
	}
	var out []Screen
	seen := map[uint64]bool{}
	var first error
	foundActive := false
	for cur != 0 && !seen[cur] {
		if b.MaxListEntries > 0 && len(out) >= b.MaxListEntries {
			first = cmpErr(first, fmt.Errorf("screen buffers: %w (%d)", ErrListLong, b.MaxListEntries))
			break
		}
		seen[cur] = true
		sc, err := l.readScreen(s, cur, b)
		sc.Active = cur == active
		foundActive = foundActive || sc.Active
		if err != nil {
			first = cmpErr(first, fmt.Errorf("screen buffer 0x%x: %w", cur, err))
		}
		out = append(out, sc)
		if cur, err = s.pointer(s.member(cur, c.screen.next)); err != nil {
			first = cmpErr(first, err)
			break
		}
	}
	if !foundActive {
		first = cmpErr(first, fmt.Errorf("active 0x%x: %w", active, ErrNoActiveScreen))
	}
	return out, first
}

// Rows are kept as a ring whose top is the row at firstRow (S33 O3). Each
// cell is a UTF-16 unit and one more byte (S33 M6).
const cellBytes = 3

func (l *Layout) readScreen(s Space, at uint64, b limits.Limits) (Screen, error) {
	c := l.console
	sc := Screen{Address: at}
	tb, err := s.pointer(s.member(at, c.screen.textBuffer))
	if err != nil {
		return sc, err
	}
	rowMap, err := s.pointer(s.member(tb, c.textBuffer.rows))
	if err != nil {
		return sc, err
	}
	count, err := s.value(tb, c.textBuffer.rowCount)
	if err != nil {
		return sc, err
	}
	first, err := s.value(tb, c.textBuffer.firstRow)
	if err != nil {
		return sc, err
	}
	if count <= 0 || first < 0 || first >= count ||
		b.MaxRowsPerObject > 0 && count > int64(b.MaxRowsPerObject) {
		return sc, fmt.Errorf("text buffer 0x%x: %d rows, first %d: %w", tb, count, first, ErrRowShape)
	}
	sc.RowCount = int(count)
	var gapErr error
	for j := range count {
		stored := uint64((first + j) % count)
		row, err := s.pointer(rowMap + stored*pointerBytes)
		if err != nil {
			gapErr = cmpErr(gapErr, err)
			sc.Incomplete = true
			continue
		}
		text, width, err := l.rowText(s, row, b)
		if err != nil {
			gapErr = cmpErr(gapErr, fmt.Errorf("row %d: %w", j, err))
			sc.Incomplete = true
			continue
		}
		sc.Columns = max(sc.Columns, width)
		if text != "" {
			sc.Rows = append(sc.Rows, ScreenRow{Row: int(j), Text: text})
		}
	}
	return sc, gapErr
}

func (l *Layout) rowText(s Space, row uint64, b limits.Limits) (string, int, error) {
	c := l.console
	width, err := s.value(row, c.row.width)
	if err != nil {
		return "", 0, err
	}
	if width <= 0 || b.MaxTextBytes > 0 && width*wideBytes > b.MaxTextBytes {
		return "", 0, fmt.Errorf("row 0x%x: width %d: %w", row, width, ErrRowShape)
	}
	cells, err := s.pointer(s.member(row, c.row.cells))
	if err != nil {
		return "", 0, err
	}
	raw, err := s.read(cells, uint64(width)*cellBytes)
	if err != nil {
		return "", 0, err
	}
	units := make([]byte, 0, width*wideBytes)
	for i := int64(0); i < width; i++ {
		units = append(units, raw[i*cellBytes], raw[i*cellBytes+1])
	}
	return strings.TrimRight(util.DecodeUTF16LE(units), " \x00"), int(width), nil
}
