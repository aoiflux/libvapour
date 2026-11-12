package processlist

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var ErrSnapshotNoPID = errors.New("processlist: snapshot csv has no pid column")

type CrossChecker interface {
	Confirm(Process) (bool, error)
}

type SnapshotProcess struct {
	PID      uint64
	Name     string
	EPROCESS uint64
}

type SnapshotCrossChecker struct {
	byPID map[uint64][]SnapshotProcess
}

func NewSnapshotCrossChecker(rows []SnapshotProcess) SnapshotCrossChecker {
	byPID := make(map[uint64][]SnapshotProcess, len(rows))
	for _, row := range rows {
		byPID[row.PID] = append(byPID[row.PID], row)
	}
	return SnapshotCrossChecker{byPID: byPID}
}

func (c SnapshotCrossChecker) Confirm(p Process) (bool, error) {
	for _, row := range c.byPID[p.PID] {
		if row.Name != "" && !snapshotNameMatches(p.Name, row.Name) {
			continue
		}
		if row.EPROCESS != 0 && p.EPROCESS != 0 && row.EPROCESS != p.EPROCESS {
			continue
		}
		return true, nil
	}
	return false, nil
}

// ImageFileName keeps 14 characters and a NUL of a longer name (S65 M8).
const keptNameLength = WindowsImageNameLength - 1

func snapshotNameMatches(listed, snapshot string) bool {
	if strings.EqualFold(listed, snapshot) {
		return true
	}
	return len(listed) == keptNameLength && len(snapshot) > keptNameLength &&
		strings.EqualFold(listed, snapshot[:keptNameLength])
}

func LoadSnapshotCSV(path string) ([]SnapshotProcess, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("processlist: open snapshot csv: %w", err)
	}
	defer f.Close()
	rows, err := ParseSnapshotCSV(f)
	if err != nil {
		return nil, fmt.Errorf("processlist: read snapshot csv %s: %w", path, err)
	}
	return rows, nil
}

var (
	pidHeaders     = []string{"ProcessId", "PID", "Id"}
	nameHeaders    = []string{"Name", "Image Name", "ProcessName"}
	addressHeaders = []string{"EPROCESS"}
)

func ParseSnapshotCSV(r io.Reader) ([]SnapshotProcess, error) {
	in := bufio.NewReader(r)
	if lead, err := in.Peek(3); err == nil && bytes.Equal(lead, []byte("\xef\xbb\xbf")) {
		_, _ = in.Discard(3)
	}
	skipped := 0
	if lead, err := in.Peek(5); err == nil && string(lead) == "#TYPE" {
		if _, err := in.ReadString('\n'); err != nil {
			return nil, nil
		}
		skipped = 1
	}
	reader := csv.NewReader(in)
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	header, err := reader.Read()
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pidAt := headerIndex(header, pidHeaders)
	if pidAt < 0 {
		return nil, ErrSnapshotNoPID
	}
	nameAt, addressAt := headerIndex(header, nameHeaders), headerIndex(header, addressHeaders)
	var rows []SnapshotProcess
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return rows, nil
		}
		if err != nil {
			return nil, err
		}
		if blankRecord(record) {
			continue
		}
		line, _ := reader.FieldPos(0)
		line += skipped
		text := strings.TrimSpace(field(record, pidAt))
		pid, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("processlist: snapshot csv line %d: pid %q is not a decimal number", line, text)
		}
		row := SnapshotProcess{PID: pid, Name: strings.TrimSpace(field(record, nameAt))}
		row.EPROCESS, _ = parseAddress(field(record, addressAt))
		rows = append(rows, row)
	}
}

func headerIndex(header, names []string) int {
	for i, h := range header {
		for _, n := range names {
			if strings.EqualFold(strings.TrimSpace(h), n) {
				return i
			}
		}
	}
	return -1
}

func field(record []string, i int) string {
	if i < 0 || i >= len(record) {
		return ""
	}
	return record[i]
}

func blankRecord(record []string) bool {
	for _, f := range record {
		if strings.TrimSpace(f) != "" {
			return false
		}
	}
	return true
}

func parseAddress(text string) (uint64, bool) {
	text = strings.TrimSpace(text)
	if hex, ok := strings.CutPrefix(strings.ToLower(text), "0x"); ok {
		v, err := strconv.ParseUint(hex, 16, 64)
		return v, err == nil
	}
	v, err := strconv.ParseUint(text, 10, 64)
	return v, err == nil
}
